#!/usr/bin/env bash
# Tear down only anchors created by setup_matched_scheduler_netns.sh and
# prove that the host interface list and host network namespace are unchanged.

set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RUNDIR="$SCRIPT_DIR/run_matched_scheduler"
SERVER_PIDFILE="$RUNDIR/server_anchor.pid"
CLIENT_PIDFILE="$RUNDIR/client_anchor.pid"

if [[ $# -ne 0 ]]; then
	echo "usage: $0" >&2
	exit 2
fi
for required in "$SERVER_PIDFILE" "$CLIENT_PIDFILE" \
	"$RUNDIR/server_start_ticks.txt" "$RUNDIR/client_start_ticks.txt" \
	"$RUNDIR/owner_uid.txt" "$RUNDIR/host_interfaces.before" "$RUNDIR/host_netns_id.txt"; do
	[[ -s "$required" ]] || { echo "REFUSING: missing teardown identity file $required" >&2; exit 1; }
done

SERVER_PID=$(cat "$SERVER_PIDFILE")
CLIENT_PID=$(cat "$CLIENT_PIDFILE")
EXPECTED_UID=$(cat "$RUNDIR/owner_uid.txt")

verify_identity() {
	local pid=$1 expected_ticks_file=$2 label=$3
	[[ "$pid" =~ ^[0-9]+$ ]] || { echo "REFUSING invalid $label pid: $pid" >&2; exit 1; }
	[[ -r "/proc/$pid/stat" ]] || { echo "REFUSING: $label process $pid is absent" >&2; exit 1; }
	local actual_ticks actual_uid
	actual_ticks=$(awk '{print $22}' "/proc/$pid/stat")
	actual_uid=$(stat -c '%u' "/proc/$pid")
	[[ "$actual_ticks" == "$(cat "$expected_ticks_file")" ]] || {
		echo "REFUSING: $label pid $pid was recycled" >&2; exit 1;
	}
	[[ "$actual_uid" == "$EXPECTED_UID" ]] || {
		echo "REFUSING: $label pid $pid is not owned by expected uid $EXPECTED_UID" >&2; exit 1;
	}
}

verify_identity "$SERVER_PID" "$RUNDIR/server_start_ticks.txt" server
verify_identity "$CLIENT_PID" "$RUNDIR/client_start_ticks.txt" client

kill "$CLIENT_PID"
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
	kill -0 "$CLIENT_PID" 2>/dev/null || break
	sleep 0.2
done
if kill -0 "$CLIENT_PID" 2>/dev/null; then kill -9 "$CLIENT_PID"; fi
kill -0 "$CLIENT_PID" 2>/dev/null && { echo "client anchor survived teardown" >&2; exit 1; }

kill "$SERVER_PID"
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
	kill -0 "$SERVER_PID" 2>/dev/null || break
	sleep 0.2
done
if kill -0 "$SERVER_PID" 2>/dev/null; then kill -9 "$SERVER_PID"; fi
kill -0 "$SERVER_PID" 2>/dev/null && { echo "server anchor survived teardown" >&2; exit 1; }

[[ "$(readlink /proc/self/ns/net)" == "$(cat "$RUNDIR/host_netns_id.txt")" ]] || {
	echo "host network namespace changed during campaign" >&2; exit 1;
}
CURRENT=$(mktemp)
trap 'rm -f "$CURRENT"' EXIT
ip -brief link show > "$CURRENT"
diff -u "$RUNDIR/host_interfaces.before" "$CURRENT"
rm -f "$CURRENT"
trap - EXIT
rm -f "$SERVER_PIDFILE" "$CLIENT_PIDFILE"
echo "MATCHED_SCHEDULER_TEARDOWN_OK"
echo "host interface list is byte-identical to the pre-setup snapshot"

