#!/usr/bin/env bash
# setup_netns.sh -- create TWO isolated, unprivileged network namespaces
# (a "server" side and a "client" side) connected by veth pairs, and the
# FAST/QUARANTINE/SHARED links between them.
#
# Why two namespaces, not one (this replaces an earlier one-namespace
# design): a smoke test with both veth ends configured in the SAME
# namespace failed ARP resolution (`ip neigh show` stuck at INCOMPLETE) --
# `ip route get <peer-address>` showed the kernel treating the peer's
# address as "local" (routed via `lo`) rather than real peer traffic
# requiring the wire, because both addresses genuinely were local to that
# one namespace. Two separate namespaces make the two sides genuinely
# distinct from the kernel's point of view, exactly like two real hosts,
# which is what actually exercises ARP/routing/tc egress shaping
# correctly. The client namespace is a NESTED namespace under the same
# user namespace as the server anchor (unshare --net, no second --user),
# not a second independent unshare --user -- an independent user
# namespace cannot receive an interface moved from a different one
# without extra privilege; nesting under the same user namespace avoids
# that entirely and was verified working directly on the selected execution host.
#
# Usage:
#   ./setup_netns.sh [--dry-run]
#
# What it does, in order:
#   1. Refuses to run if a server anchor is already active.
#   2. Snapshots the host's interfaces and network-namespace id (for
#      teardown verification and the isolation guard's self-read compare).
#   3. Starts the server anchor (unshare --user --net --map-root-user
#      --fork + sleep infinity), PID saved to run/anchor.pid.
#   4. Inside the server anchor, starts a nested client anchor (unshare
#      --net --fork, same user namespace) + sleep infinity, PID saved to
#      run/client_anchor.pid.
#   5. Creates three veth pairs in the server anchor: sbeq0-fast/-quar
#      (two-path, no-borrow topology) and sbeq0-shared (one-path,
#      HTB-borrowing topology). Moves the *peer* leg of each
#      (sbeq0-fastpeer/-quarpeer/-shrpeer) into the client anchor, then
#      addresses and brings up both legs from their respective sides.
#      All addresses from 198.51.100.0/24 (RFC 5737 TEST-NET-2, never
#      validly routable).
#   6. Runs the full isolation guard against BOTH namespaces.
#
# apply_htb_baseline.sh and sbeq_budget_controller.sh apply shaping on the
# CLIENT side's egress (sbeq0-shrpeer) -- tc shapes egress only, and the
# client is the sender for all traffic this testbed generates, so shaping
# its egress is the enforcement point. This is a testbed simplification
# (we author both ends; a real deployment enforces at the receiver/ingress
# via XDP+tc once CAP_BPF is available), stated here rather than left
# implicit.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib_isolation_guard.sh

DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
	DRY_RUN=1
	export SBEQ_DRY_RUN=1
fi

RUNDIR="$(pwd)/run"
PIDFILE="$RUNDIR/anchor.pid"
CLIENT_PIDFILE="$RUNDIR/client_anchor.pid"
BASELINE_FILE="$RUNDIR/host_baseline.txt"
NETNS_ID_FILE="$RUNDIR/host_netns_id.txt"

mkdir -p "$RUNDIR"

if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
	echo "A server anchor is already running (pid $(cat "$PIDFILE"))." >&2
	echo "Run teardown_netns.sh first if you want to recreate it." >&2
	exit 1
fi
rm -f "$PIDFILE" "$CLIENT_PIDFILE"

if [[ "$DRY_RUN" == "1" ]]; then
	echo "[dry-run] would snapshot host interfaces to $BASELINE_FILE and namespace id to $NETNS_ID_FILE"
	echo "[dry-run] would start server anchor: unshare --user --net --map-root-user --fork sleep infinity -> $PIDFILE"
	echo "[dry-run] would start nested client anchor from inside it: unshare --net --fork sleep infinity -> $CLIENT_PIDFILE"
	echo "[dry-run] would create veth pairs sbeq0-fast/-quar/-shared in the server anchor"
	echo "[dry-run] would move sbeq0-fastpeer/-quarpeer/-shrpeer into the client anchor via 'ip link set <if> netns <client_pid>'"
	echo "[dry-run] would address both legs from 198.51.100.0/24 and bring all up"
	echo "[dry-run] would run the isolation guard against both namespaces"
	echo "[dry-run] expected output: interface lists split across the two namespaces as described above; isolation guard ALL CHECKS PASSED for both"
	exit 0
fi

echo "=== step 1/6: snapshot host interfaces and namespace id ==="
ip -brief link show > "$BASELINE_FILE"
echo "saved to $BASELINE_FILE:"; cat "$BASELINE_FILE"
readlink /proc/self/ns/net > "$NETNS_ID_FILE"
echo "saved host network namespace id to $NETNS_ID_FILE: $(cat "$NETNS_ID_FILE")"

echo "=== step 2/6: start server anchor (unshare --user --net) ==="
unshare --user --net --map-root-user --fork bash -c "echo \$\$ > '$PIDFILE'; exec sleep infinity" \
	</dev/null >"$RUNDIR/anchor.log" 2>&1 &
disown
for _ in 1 2 3 4 5 6 7 8 9 10; do
	[[ -s "$PIDFILE" ]] && break
	sleep 0.3
done
[[ -s "$PIDFILE" ]] || { echo "server anchor failed to start" >&2; exit 1; }
ANCHOR_PID=$(cat "$PIDFILE")
echo "server anchor pid: $ANCHOR_PID"

run_in_server() { nsenter --target "$ANCHOR_PID" --net --user --preserve-credentials -- bash -c "$1"; }

echo "=== step 3/6: start nested client anchor (unshare --net only, same user namespace) ==="
nsenter --target "$ANCHOR_PID" --net --user --preserve-credentials -- bash -c "
	unshare --net --fork bash -c 'echo \$\$ > \"$CLIENT_PIDFILE\"; exec sleep infinity' \
		</dev/null >'$RUNDIR/client_anchor.log' 2>&1 &
	disown
"
for _ in 1 2 3 4 5 6 7 8 9 10; do
	[[ -s "$CLIENT_PIDFILE" ]] && break
	sleep 0.3
done
[[ -s "$CLIENT_PIDFILE" ]] || { echo "client anchor failed to start" >&2; exit 1; }
CLIENT_PID=$(cat "$CLIENT_PIDFILE")
echo "client anchor pid (nested, same userns): $CLIENT_PID"

# Double nsenter: the client netns is a child of the server anchor's user
# namespace (nested unshare --net, no second --user), so reaching it from
# the top-level host shell requires joining the server's user+net
# namespace first, then the client's net namespace from within that
# context -- a lone `nsenter --net` here would lack the needed capability.
run_in_client() {
	nsenter --target "$ANCHOR_PID" --net --user --preserve-credentials -- \
		nsenter --target "$CLIENT_PID" --net -- bash -c "$1"
}

echo "=== step 4/6: create veth pairs in the server anchor ==="
run_in_server '
	set -euo pipefail
	ip link add sbeq0-fast type veth peer name sbeq0-fastpeer
	ip link add sbeq0-quar type veth peer name sbeq0-quarpeer
	ip link add sbeq0-shared type veth peer name sbeq0-shrpeer
'

echo "=== step 5/6: move peer legs into the client anchor, address both sides, bring up ==="
run_in_server "
	set -euo pipefail
	ip link set sbeq0-fastpeer netns $CLIENT_PID
	ip link set sbeq0-quarpeer netns $CLIENT_PID
	ip link set sbeq0-shrpeer netns $CLIENT_PID
	ip addr add 198.51.100.1/30 dev sbeq0-fast
	ip addr add 198.51.100.5/30 dev sbeq0-quar
	ip addr add 198.51.100.9/30 dev sbeq0-shared
	ip link set sbeq0-fast up
	ip link set sbeq0-quar up
	ip link set sbeq0-shared up
"
run_in_client '
	set -euo pipefail
	ip addr add 198.51.100.2/30 dev sbeq0-fastpeer
	ip addr add 198.51.100.6/30 dev sbeq0-quarpeer
	ip addr add 198.51.100.10/30 dev sbeq0-shrpeer
	ip link set lo up
	ip link set sbeq0-fastpeer up
	ip link set sbeq0-quarpeer up
	ip link set sbeq0-shrpeer up
'

echo "=== step 6/6: run full isolation guard against both namespaces ==="
echo "-- server side --"
run_in_server "
	source '$(pwd)/lib_isolation_guard.sh'
	sbeq_require_full_isolation
	echo '-- server interfaces --'; ip -brief link show
	echo '-- server addresses --'; ip -brief addr show
"
echo "-- client side --"
run_in_client "
	source '$(pwd)/lib_isolation_guard.sh'
	sbeq_require_full_isolation
	echo '-- client interfaces --'; ip -brief link show
	echo '-- client addresses --'; ip -brief addr show
"

echo ""
echo "Setup complete."
echo "Server anchor pid: $ANCHOR_PID (saved at $PIDFILE)"
echo "Client anchor pid: $CLIENT_PID (saved at $CLIENT_PIDFILE)"
echo "Use validate_isolation.sh $ANCHOR_PID [$CLIENT_PID] to re-check at any time."
echo "Use teardown_netns.sh $ANCHOR_PID when done (tears down the client anchor too)."
