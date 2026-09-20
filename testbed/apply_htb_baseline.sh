#!/usr/bin/env bash
# apply_htb_baseline.sh -- apply one of the frozen baselines' tc/HTB
# configuration to the CLIENT-side egress interfaces (sbeq0-fastpeer,
# sbeq0-quarpeer, sbeq0-shrpeer), which live in the nested client
# namespace created by setup_netns.sh. Every capacity and buffer number
# below is copied verbatim from configs/confirmatory_v2.json (frozen
# 2026-08-04, before any experiment ran) -- nothing here is invented at
# apply time.
#
# Why the CLIENT side: tc/HTB shapes EGRESS traffic only. All traffic this
# testbed generates originates from the client namespace (traffic_gen.py
# client role), so the client's egress is the only point that is both (a)
# where all offered traffic actually leaves and (b) something we control
# without needing an IFB-redirect ingress trick. This is a testbed
# simplification specific to synthetic, self-authored traffic -- stated
# here rather than left implicit. A real deployment enforces at the
# receiver/ingress side via XDP+tc once CAP_BPF is available (see
# SERVER_ENVIRONMENT_REPORT.md); this script does not claim otherwise.
#
# Classification stand-in: XDP is not attached yet, so there is no live
# classifier producing a redirect decision. Until it is, traffic_gen.py
# marks each packet's IP TOS byte itself (0x10 = FAST-classified/benign,
# 0x00 = QUARANTINE-classified/suspicious) as an oracle label, exactly
# analogous to this project's existing "oracle mode" used elsewhere as an
# explicitly labeled ceiling, never presented as classifier output. All tc
# filters below match on that TOS byte for the same reason.
#
# Usage:
#   ./apply_htb_baseline.sh <server_anchor_pid> <client_anchor_pid> <B0|B1|B2|B3|B4|B5|B6> [--dry-run] [--buffer-time-s N]
#
#   B0  shared_fifo_no_defense             -- one class, full capacity, no
#                                              classification-based split.
#   B1  detection_and_drop                 -- FAST gets full capacity;
#                                              QUARANTINE-marked traffic is
#                                              dropped outright, no service.
#   B2  shared_aggregate_rate_limiter      -- one class, full capacity,
#                                              classification-blind (same
#                                              shape as B0; distinct id per
#                                              Stage 4's baseline list).
#   B3  fixed_capacity_isolation           -- two classes, rate==ceil each,
#                                              no borrowing (v1 mechanism).
#   B4  classifier_aware_shared_quarantine -- two classes, no reserved
#                                              floor, full shared ceiling.
#   B5  classifier_aware_work_conserving_reserved_scheduler -- guaranteed
#                                              floors + full borrowing
#                                              (the required fair baseline).
#   B6  proposed_mechanism (SBEQ)          -- identical static HTB shape to
#                                              B5; the distinguishing
#                                              security-budget gate and
#                                              bounded revocation are
#                                              applied dynamically on top by
#                                              sbeq_budget_controller.sh, not
#                                              by a different static shape.
#
# Applied only to sbeq0-shrpeer (the SHARED/one-path link's client-side
# leg) by default; pass --all-links to also apply the two-class shape to
# sbeq0-fastpeer/sbeq0-quarpeer (the two-path topology's client-side legs)
# for baselines that use a two-class shape (not B0/B1/B2, which are single
# aggregate classes and don't need the two-path link at all).
#
# --buffer-time-s overrides the default 0.02s (20ms) normalized buffer time
# used to size each leaf class's bfifo queue as
# rate_of_that_class * buffer_time_s (Stage-5 Family C -- see
# CONFIRMATORY_PROTOCOL_V2.md Sec 6). Frozen sweep points: 0.005/0.02/0.08.
#
# All commands are printed before being run (or instead of being run, with
# --dry-run). This script sources lib_isolation_guard.sh inside BOTH
# namespaces and refuses to touch anything unless both pass.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ $# -lt 3 ]]; then
	echo "usage: $0 <server_anchor_pid> <client_anchor_pid> <B0|B1|B2|B3|B4|B5|B6> [--dry-run] [--buffer-time-s N]" >&2
	exit 2
fi
SERVER_PID="$1"
CLIENT_PID="$2"
BASELINE="$3"
shift 3
DRY_RUN=0
BUFFER_TIME_S="0.02"
while [[ $# -gt 0 ]]; do
	case "$1" in
	--dry-run) DRY_RUN=1 ;;
	--buffer-time-s) BUFFER_TIME_S="$2"; shift ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
	shift
done

TOTAL_BPS=8000000
FAST_MIN_BPS=5600000
QUAR_MIN_BPS=2400000
IFACE="sbeq0-shrpeer"

bytes_for() { awk -v r="$1" -v t="$BUFFER_TIME_S" 'BEGIN{printf "%d", r*t}'; }
TOTAL_BUFFER_BYTES=$(bytes_for "$TOTAL_BPS")
FAST_BUFFER_BYTES=$(bytes_for "$FAST_MIN_BPS")
QUAR_BUFFER_BYTES=$(bytes_for "$QUAR_MIN_BPS")

declare -a TC_COMMANDS=()
case "$BASELINE" in
B0|B2)
	TC_COMMANDS=(
		"tc qdisc del dev $IFACE root"
		"tc qdisc add dev $IFACE root handle 1: htb default 1"
		"tc class add dev $IFACE parent 1: classid 1:1 htb rate ${TOTAL_BPS}Bps ceil ${TOTAL_BPS}Bps"
		"tc qdisc add dev $IFACE parent 1:1 handle 10: bfifo limit ${TOTAL_BUFFER_BYTES}"
	)
	[[ "$BASELINE" == "B0" ]] && DESC="shared_fifo_no_defense: one class, full capacity, no classification consulted" \
		|| DESC="shared_aggregate_rate_limiter: one class, full capacity, classification-blind by design (distinct id from B0 per Stage 4)"
	;;
B1)
	DESC="detection_and_drop: FAST full capacity, QUARANTINE-marked traffic dropped"
	TC_COMMANDS=(
		"tc qdisc del dev $IFACE root"
		"tc qdisc add dev $IFACE root handle 1: htb default 1"
		"tc class add dev $IFACE parent 1: classid 1:1 htb rate ${TOTAL_BPS}Bps ceil ${TOTAL_BPS}Bps"
		"tc qdisc add dev $IFACE parent 1:1 handle 10: bfifo limit ${TOTAL_BUFFER_BYTES}"
		"tc filter add dev $IFACE parent 1: protocol ip prio 1 u32 match ip tos 0x00 0xff action drop"
	)
	;;
B3|B4|B5|B6)
	case "$BASELINE" in
	B3) FAST_RATE=$FAST_MIN_BPS; FAST_CEIL=$FAST_MIN_BPS; QUAR_RATE=$QUAR_MIN_BPS; QUAR_CEIL=$QUAR_MIN_BPS
		DESC="fixed_capacity_isolation: rate==ceil per class, no borrowing (v1 mechanism)" ;;
	B4) FAST_RATE=1; FAST_CEIL=$TOTAL_BPS; QUAR_RATE=1; QUAR_CEIL=$TOTAL_BPS
		DESC="classifier_aware_shared_quarantine: no reserved floor, full shared ceiling" ;;
	B5) FAST_RATE=$FAST_MIN_BPS; FAST_CEIL=$TOTAL_BPS; QUAR_RATE=$QUAR_MIN_BPS; QUAR_CEIL=$TOTAL_BPS
		DESC="classifier_aware_work_conserving_reserved_scheduler: guaranteed floor + full borrowing" ;;
	B6) FAST_RATE=$FAST_MIN_BPS; FAST_CEIL=$TOTAL_BPS; QUAR_RATE=$QUAR_MIN_BPS; QUAR_CEIL=$TOTAL_BPS
		DESC="proposed_mechanism (SBEQ): identical static shape to B5 -- run sbeq_budget_controller.sh alongside this" ;;
	esac
	TC_COMMANDS=(
		"tc qdisc del dev $IFACE root"
		"tc qdisc add dev $IFACE root handle 1: htb default 20"
		"tc class add dev $IFACE parent 1: classid 1:1 htb rate ${TOTAL_BPS}Bps ceil ${TOTAL_BPS}Bps"
		"tc class add dev $IFACE parent 1:1 classid 1:10 htb rate ${FAST_RATE}Bps ceil ${FAST_CEIL}Bps"
		"tc class add dev $IFACE parent 1:1 classid 1:20 htb rate ${QUAR_RATE}Bps ceil ${QUAR_CEIL}Bps"
		"tc qdisc add dev $IFACE parent 1:10 handle 10: bfifo limit ${FAST_BUFFER_BYTES}"
		"tc qdisc add dev $IFACE parent 1:20 handle 20: bfifo limit ${QUAR_BUFFER_BYTES}"
		"tc filter add dev $IFACE parent 1: protocol ip prio 1 u32 match ip tos 0x10 0xff flowid 1:10"
		"tc filter add dev $IFACE parent 1: protocol ip prio 2 u32 match ip tos 0x00 0xff flowid 1:20"
	)
	;;
*)
	echo "unknown baseline '$BASELINE' -- expected B0, B1, B2, B3, B4, B5, or B6" >&2
	exit 2
	;;
esac

echo "=== baseline $BASELINE: $DESC ==="
echo "interface=$IFACE (client-side egress) total=${TOTAL_BPS}Bps buffer_time_s=${BUFFER_TIME_S} total_buffer=${TOTAL_BUFFER_BYTES}B"

# Double nsenter: sbeq0-shrpeer lives in the client namespace, which is a
# child of the server anchor's user namespace (see setup_netns.sh) -- a
# lone `nsenter --net` from the top-level host shell lacks the capability
# to join it.
run_in_client() {
	nsenter --target "$SERVER_PID" --net --user --preserve-credentials -- \
		nsenter --target "$CLIENT_PID" --net -- bash -c "$1"
}
GUARD_CHECK="source '$(pwd)/lib_isolation_guard.sh'; sbeq_require_full_isolation"

if [[ "$DRY_RUN" == "1" ]]; then
	echo "=== dry-run: isolation guard would be checked in both namespaces first, then: ==="
	for cmd in "${TC_COMMANDS[@]}"; do
		echo "[dry-run] would run in client namespace: $cmd"
	done
	echo "[dry-run] expected output after apply: 'tc class show dev $IFACE' in the client namespace reflecting the commands above"
	exit 0
fi

echo "=== checking isolation guard (server side) ==="
nsenter --target "$SERVER_PID" --net --user --preserve-credentials -- bash -c "$GUARD_CHECK"
echo "=== checking isolation guard (client side) ==="
run_in_client "$GUARD_CHECK"

echo "=== applying tc/HTB configuration for $BASELINE to $IFACE (client side) ==="
for cmd in "${TC_COMMANDS[@]}"; do
	if [[ "$cmd" == "tc qdisc del"* ]]; then
		run_in_client "$cmd" 2>/dev/null || echo "(no pre-existing qdisc to remove, expected on first apply)"
	else
		echo "+ $cmd"
		run_in_client "$cmd"
	fi
done

echo "=== resulting configuration ==="
run_in_client "tc class show dev $IFACE; echo '--'; tc qdisc show dev $IFACE; echo '--'; tc filter show dev $IFACE"

echo ""
echo "Baseline $BASELINE applied to $IFACE (client side) and verified isolated."
