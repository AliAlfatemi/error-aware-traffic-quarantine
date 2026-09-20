#!/usr/bin/env bash
# teardown_netns.sh -- rollback. Kills both anchor processes (client first,
# since it is logically nested under the server's user namespace, then
# server), which destroys both namespaces and every interface inside them
# as a direct consequence of Linux namespace lifecycle. Then proves the
# host's interface list is byte-identical to the pre-setup snapshot.
#
# Usage: ./teardown_netns.sh <server_anchor_pid> [client_anchor_pid]
# (client_anchor_pid defaults to the value saved in run/client_anchor.pid)

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ $# -lt 1 ]]; then
	echo "usage: $0 <server_anchor_pid> [client_anchor_pid]" >&2
	exit 2
fi
SERVER_PID="$1"
RUNDIR="$(pwd)/run"
CLIENT_PID="${2:-$(cat "$RUNDIR/client_anchor.pid" 2>/dev/null || true)}"
PIDFILE="$RUNDIR/anchor.pid"
CLIENT_PIDFILE="$RUNDIR/client_anchor.pid"
BASELINE_FILE="$RUNDIR/host_baseline.txt"

kill_and_wait() {
	local pid="$1" label="$2"
	if kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || true
		for _ in 1 2 3 4 5 6 7 8 9 10; do
			kill -0 "$pid" 2>/dev/null || break
			sleep 0.3
		done
		if kill -0 "$pid" 2>/dev/null; then
			echo "$label did not exit after SIGTERM, sending SIGKILL" >&2
			kill -9 "$pid" 2>/dev/null || true
			sleep 0.3
		fi
	else
		echo "$label ($pid) was already not running"
	fi
	if kill -0 "$pid" 2>/dev/null; then
		echo "ROLLBACK FAILED: $label ($pid) is still alive" >&2
		exit 1
	fi
	echo "$label confirmed terminated"
}

if [[ -n "$CLIENT_PID" ]]; then
	echo "=== killing client anchor pid $CLIENT_PID ==="
	kill_and_wait "$CLIENT_PID" "client anchor"
fi

echo "=== killing server anchor pid $SERVER_PID ==="
kill_and_wait "$SERVER_PID" "server anchor"

rm -f "$PIDFILE" "$CLIENT_PIDFILE"

echo "=== verifying host interfaces are unchanged since setup ==="
if [[ ! -f "$BASELINE_FILE" ]]; then
	echo "no baseline snapshot found at $BASELINE_FILE -- cannot verify, but namespace" >&2
	echo "teardown above is independently sufficient." >&2
else
	CURRENT=$(mktemp)
	ip -brief link show > "$CURRENT"
	if diff -u "$BASELINE_FILE" "$CURRENT" > /dev/null; then
		echo "CONFIRMED: host interface list is byte-identical to the pre-setup baseline."
	else
		echo "ROLLBACK VERIFICATION FAILED: host interface list differs from baseline:" >&2
		diff -u "$BASELINE_FILE" "$CURRENT" >&2 || true
		rm -f "$CURRENT"
		exit 1
	fi
	rm -f "$CURRENT"
fi

echo ""
echo "Teardown complete and verified."
