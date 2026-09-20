#!/usr/bin/env bash
# sbeq_budget_controller.sh -- the actual SBEQ mechanism (Stage 2's
# security-budgeted, bounded-revocation gate) applied on top of B6's static
# HTB shape on the client-side egress interface (sbeq0-shrpeer), which
# apply_htb_baseline.sh B6 leaves identical to B5's shape.
#
# CORRECTED 2026-08-05 after an external audit (see AUDIT_RESPONSE.md and
# external_audit_2026-08-05/) found the original version polled TOTAL class
# bytes -- including bytes the class was already entitled to under its
# guaranteed floor -- and reset on a fixed 1-second tumbling window. That is
# not a borrowed-capacity budget: a source using only its guaranteed 2.4MB/s
# floor, never borrowing anything, would still exhaust the "budget" and
# trigger revocation, and a burst straddling a tumbling-window boundary
# could double-spend. The corrected version:
#   1. debits only BORROWED bytes: each poll, computes
#      max(0, bytes_sent_since_last_poll - floor_entitled_bytes_over_that_
#      interval), where floor_entitled_bytes = quarantine_reserved_Bps *
#      elapsed_time. Bytes served within the guaranteed floor are never
#      debited, matching the mechanism's stated intent (budget borrowed
#      service, not total service).
#   2. uses a genuine SLIDING window (a ring buffer of per-poll borrowed
#      increments, summed over the trailing window_ms), not a tumbling
#      window that resets to zero at fixed boundaries -- this removes the
#      window-boundary double-spend the audit flagged, and lets revocation
#      lift naturally as old borrowing ages out rather than only at a fixed
#      reset instant.
#   3. uses a monotonic clock (/proc/uptime, seconds since boot) instead of
#      wall-clock `date +%s%3N`, so an NTP step cannot corrupt window math.
#
# What it does: polls the QUARANTINE class's byte counter on sbeq0-shrpeer
# every poll_interval_ms (default = revocation_bound_ms = 50ms, the frozen
# CONFIRMATORY_PROTOCOL_V2.md Sec 9 value), converts each interval's byte
# delta into a borrowed-byte increment, and sums borrowed increments over
# the trailing window_ms. While that sum stays under
# budget_bytes_per_window, quarantine traffic can still borrow up to the
# full shared ceiling (identical to B5's behavior). The moment the sliding
# sum exceeds budget, the controller revokes borrowing by clamping ceil
# down to the class's own reserved rate -- within one poll interval of the
# exhaustion event. As old borrowing ages out of the sliding window, the
# sum drops back under budget and ceil is restored automatically, with no
# separate "window rollover" event.
#
# Known scope limitation, stated plainly rather than hidden: this enforces
# the budget at the AGGREGATE quarantine-class level, not per source IP.
# True per-source granularity needs the XDP program's source_budget_map
# (xdp/xdp_shared.h), which requires CAP_BPF -- not available yet (see
# SERVER_ENVIRONMENT_REPORT.md). The control primitive this script
# implements (poll a counter, compute borrowed bytes, clamp/restore ceil
# within a bounded time) is the same primitive that will later be driven by
# per-source XDP map reads instead of the aggregate class counter; only the
# input signal changes, not the mechanism. The revocation *decision* latency
# is still only bounded by the poll interval, not independently measured
# end-to-end (trigger-to-kernel-effective) -- see AUDIT_RESPONSE.md P1-5.
#
# Usage:
#   ./sbeq_budget_controller.sh <server_anchor_pid> <client_anchor_pid> [--dry-run] [--iterations N]
#       [--poll-interval-ms MS] [--budget-bytes-per-window N] [--window-ms MS]
#
# Runs bounded (--iterations, default 20, ~1s at the default 50ms poll
# interval) unless --iterations 0 (run until SIGINT/SIGTERM). Always
# attempts to restore ceil on exit, even on error or signal.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ $# -lt 2 ]]; then
	echo "usage: $0 <server_anchor_pid> <client_anchor_pid> [--dry-run] [--iterations N] [--poll-interval-ms MS] [--budget-bytes-per-window N] [--window-ms MS]" >&2
	exit 2
fi
SERVER_PID="$1"; CLIENT_PID="$2"; shift 2

DRY_RUN=0
ITERATIONS=20
POLL_INTERVAL_MS=50              # == capacity.revocation_bound_ms, configs/confirmatory_v2.json
BUDGET_BYTES_PER_WINDOW=2400000  # borrowed-byte budget per sliding window; == quarantine_reserved_Bps * 1 window-second
WINDOW_MS=1000

while [[ $# -gt 0 ]]; do
	case "$1" in
	--dry-run) DRY_RUN=1 ;;
	--iterations) ITERATIONS="$2"; shift ;;
	--poll-interval-ms) POLL_INTERVAL_MS="$2"; shift ;;
	--budget-bytes-per-window) BUDGET_BYTES_PER_WINDOW="$2"; shift ;;
	--window-ms) WINDOW_MS="$2"; shift ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
	shift
done

IFACE="sbeq0-shrpeer"
TOTAL_BPS=8000000
QUAR_MIN_BPS=2400000

run_in_client() {
	nsenter --target "$SERVER_PID" --net --user --preserve-credentials -- \
		nsenter --target "$CLIENT_PID" --net -- bash -c "$1"
}

echo "=== checking isolation guard before starting ==="
run_in_client "source '$(pwd)/lib_isolation_guard.sh'; sbeq_require_full_isolation"

echo "=== checking that class 1:20 exists on $IFACE (B6 must already be applied) ==="
if ! run_in_client "tc class show dev $IFACE" | grep -q "1:20"; then
	echo "ERROR: class 1:20 not found on $IFACE -- run apply_htb_baseline.sh <server_pid> <client_pid> B6 first" >&2
	exit 1
fi

if [[ "$DRY_RUN" == "1" ]]; then
	echo "[dry-run] would poll: tc -s class show dev $IFACE classid 1:20 (every ${POLL_INTERVAL_MS}ms, ${ITERATIONS} iterations)"
	echo "[dry-run] each poll: borrowed_bytes_this_interval = max(0, byte_delta - ${QUAR_MIN_BPS}Bps * elapsed_s)"
	echo "[dry-run] sliding sum over trailing ${WINDOW_MS}ms; if > ${BUDGET_BYTES_PER_WINDOW} bytes and not revoked: would run"
	echo "[dry-run]   tc class change dev $IFACE parent 1:1 classid 1:20 htb rate ${QUAR_MIN_BPS}Bps ceil ${QUAR_MIN_BPS}Bps"
	echo "[dry-run] once the sliding sum drops back <= budget and revoked: would run"
	echo "[dry-run]   tc class change dev $IFACE parent 1:1 classid 1:20 htb rate ${QUAR_MIN_BPS}Bps ceil ${TOTAL_BPS}Bps"
	echo "[dry-run] expected output: a JSON line per poll with borrowed-byte accounting, sliding-window sum, and any revoke/restore event"
	exit 0
fi

get_bytes() {
	run_in_client "tc -s class show dev $IFACE classid 1:20" \
		| grep -oE 'Sent [0-9]+ bytes' | grep -oE '[0-9]+' | head -1
}
restore_ceil() {
	run_in_client "tc class change dev $IFACE parent 1:1 classid 1:20 htb rate ${QUAR_MIN_BPS}Bps ceil ${TOTAL_BPS}Bps" 2>/dev/null || true
}
trap restore_ceil EXIT

# Monotonic milliseconds since boot -- /proc/uptime's first field is
# seconds since boot with centisecond resolution, immune to wall-clock
# (NTP) steps, unlike `date +%s%3N`.
now_ms() { awk '{printf "%d", $1*1000}' /proc/uptime; }

PREV_MS=$(now_ms)
PREV_BYTES=$(get_bytes)
REVOKED=0
ITER=0

# Sliding-window ring buffer: parallel arrays of (timestamp_ms,
# borrowed_bytes_this_interval) for every poll still within window_ms of
# now. Bash arrays are adequate at this poll rate (~20 entries for the
# default 1000ms window / 50ms interval).
declare -a RING_TS=()
declare -a RING_BORROWED=()

echo "controller started: poll_interval_ms=$POLL_INTERVAL_MS budget_bytes_per_window(borrowed)=$BUDGET_BYTES_PER_WINDOW window_ms=$WINDOW_MS floor_Bps=$QUAR_MIN_BPS baseline_bytes=$PREV_BYTES"

while [[ "$ITERATIONS" -eq 0 || "$ITER" -lt "$ITERATIONS" ]]; do
	CUR_MS=$(now_ms)
	CUR_BYTES=$(get_bytes)

	ELAPSED_MS=$((CUR_MS - PREV_MS))
	[[ "$ELAPSED_MS" -lt 1 ]] && ELAPSED_MS=1
	DELTA_BYTES=$((CUR_BYTES - PREV_BYTES))
	[[ "$DELTA_BYTES" -lt 0 ]] && DELTA_BYTES=0  # counter reset (e.g. re-applied baseline) -- treat as no borrowing this interval

	# Floor-entitled bytes over this interval, at the guaranteed rate.
	FLOOR_BYTES=$(( QUAR_MIN_BPS * ELAPSED_MS / 1000 ))
	BORROWED_THIS_INTERVAL=$((DELTA_BYTES - FLOOR_BYTES))
	[[ "$BORROWED_THIS_INTERVAL" -lt 0 ]] && BORROWED_THIS_INTERVAL=0

	RING_TS+=("$CUR_MS")
	RING_BORROWED+=("$BORROWED_THIS_INTERVAL")

	# Drop ring entries older than window_ms and sum the rest in one pass.
	WINDOW_START_MS=$((CUR_MS - WINDOW_MS))
	NEW_TS=()
	NEW_BORROWED=()
	WINDOW_SUM=0
	for i in "${!RING_TS[@]}"; do
		if [[ "${RING_TS[$i]}" -ge "$WINDOW_START_MS" ]]; then
			NEW_TS+=("${RING_TS[$i]}")
			NEW_BORROWED+=("${RING_BORROWED[$i]}")
			WINDOW_SUM=$((WINDOW_SUM + RING_BORROWED[$i]))
		fi
	done
	RING_TS=("${NEW_TS[@]}")
	RING_BORROWED=("${NEW_BORROWED[@]}")

	EVENT="none"
	if [[ "$WINDOW_SUM" -gt "$BUDGET_BYTES_PER_WINDOW" && "$REVOKED" -eq 0 ]]; then
		run_in_client "tc class change dev $IFACE parent 1:1 classid 1:20 htb rate ${QUAR_MIN_BPS}Bps ceil ${QUAR_MIN_BPS}Bps"
		REVOKED=1
		EVENT="budget_exceeded_revoke"
	elif [[ "$WINDOW_SUM" -le "$BUDGET_BYTES_PER_WINDOW" && "$REVOKED" -eq 1 ]]; then
		restore_ceil
		REVOKED=0
		EVENT="borrowed_aged_out_restore"
	fi

	printf '{"ts_ms": %d, "class_bytes_total": %d, "delta_bytes": %d, "floor_entitled_bytes": %d, "borrowed_this_interval": %d, "borrowed_sliding_window_sum": %d, "budget_bytes_per_window": %d, "revoked": %s, "event": "%s"}\n' \
		"$CUR_MS" "$CUR_BYTES" "$DELTA_BYTES" "$FLOOR_BYTES" "$BORROWED_THIS_INTERVAL" "$WINDOW_SUM" "$BUDGET_BYTES_PER_WINDOW" \
		"$([[ $REVOKED -eq 1 ]] && echo true || echo false)" "$EVENT"

	PREV_MS=$CUR_MS
	PREV_BYTES=$CUR_BYTES
	ITER=$((ITER + 1))
	sleep "$(awk -v ms="$POLL_INTERVAL_MS" 'BEGIN{printf "%.3f", ms/1000}')"
done

echo "controller stopped after $ITER iterations (ceil restored on exit via trap)"
