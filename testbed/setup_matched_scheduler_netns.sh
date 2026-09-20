#!/usr/bin/env bash
# Create the one-veth, rootless namespace topology frozen for Study B.

set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RUNDIR="$SCRIPT_DIR/run_matched_scheduler"
SERVER_PIDFILE="$RUNDIR/server_anchor.pid"
CLIENT_PIDFILE="$RUNDIR/client_anchor.pid"
BASELINE_FILE="$RUNDIR/host_interfaces.before"
HOST_NS_FILE="$RUNDIR/host_netns_id.txt"

if [[ "${1:-}" == "--dry-run" ]]; then
	echo "[dry-run] would create rootless server/client network namespaces"
	echo "[dry-run] would create only sbeq0-shared <-> sbeq0-shrpeer"
	echo "[dry-run] would assign only 198.51.100.9/30 and 198.51.100.10/30"
	echo "[dry-run] would reject every default route and non-sbeq0 interface"
	echo "[dry-run] state directory: $RUNDIR"
	exit 0
elif [[ $# -ne 0 ]]; then
	echo "usage: $0 [--dry-run]" >&2
	exit 2
fi

mkdir -p "$RUNDIR"
for pidfile in "$SERVER_PIDFILE" "$CLIENT_PIDFILE"; do
	if [[ -s "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
		echo "REFUSING: live matched-scheduler anchor in $pidfile" >&2
		exit 1
	fi
done
rm -f "$SERVER_PIDFILE" "$CLIENT_PIDFILE"

ip -brief link show > "$BASELINE_FILE"
readlink /proc/self/ns/net > "$HOST_NS_FILE"
printf '%s\n' "$(id -u)" > "$RUNDIR/owner_uid.txt"

SERVER_PID=""
CLIENT_PID=""
SERVER_START_TICKS=""
CLIENT_START_TICKS=""
SERVER_OWNER_UID=""
CLIENT_OWNER_UID=""
SERVER_WRAPPER_PID=""
CLIENT_WRAPPER_PID=""
SERVER_WRAPPER_START_TICKS=""
CLIENT_WRAPPER_START_TICKS=""
SERVER_WRAPPER_OWNER_UID=""
CLIENT_WRAPPER_OWNER_UID=""
cleanup_partial() {
	status=$?
	trap - EXIT INT TERM
	partial_identity_matches() {
		local pid=$1 expected_ticks=$2 expected_uid=$3 label=$4
		if [[ ! -r "/proc/$pid/stat" ]] \
			|| [[ -z "$expected_ticks" || -z "$expected_uid" ]] \
			|| [[ "$(awk '{print $22}' "/proc/$pid/stat")" != "$expected_ticks" ]] \
			|| [[ "$(stat -c '%u' "/proc/$pid")" != "$expected_uid" ]]; then
			echo "REFUSING: partial-cleanup identity mismatch for $label pid $pid" >&2
			return 1
		fi
	}
	stop_partial_anchor() {
		local pid=$1 expected_ticks=$2 expected_uid=$3 label=$4
		[[ "$pid" =~ ^[0-9]+$ ]] || return 0
		if kill -0 "$pid" 2>/dev/null; then
			partial_identity_matches "$pid" "$expected_ticks" "$expected_uid" "$label" || return 1
			kill "$pid" 2>/dev/null || true
			for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
				kill -0 "$pid" 2>/dev/null || break
				sleep 0.2
			done
			if kill -0 "$pid" 2>/dev/null; then
				partial_identity_matches "$pid" "$expected_ticks" "$expected_uid" "$label" || return 1
				kill -9 "$pid" 2>/dev/null || true
			fi
		fi
		return 0
	}
	reap_partial_wrapper() {
		local pid=$1 expected_ticks=$2 expected_uid=$3 label=$4
		[[ "$pid" =~ ^[0-9]+$ ]] || return 0
		if kill -0 "$pid" 2>/dev/null; then
			partial_identity_matches "$pid" "$expected_ticks" "$expected_uid" "$label" || return 1
			kill "$pid" 2>/dev/null || true
		fi
		wait "$pid" 2>/dev/null || true
		! kill -0 "$pid" 2>/dev/null
	}
	partial_process_absent() {
		local pid=$1 label=$2
		[[ "$pid" =~ ^[0-9]+$ ]] || return 0
		if kill -0 "$pid" 2>/dev/null; then
			echo "partial-cleanup process survived: $label pid $pid" >&2
			return 1
		fi
	}
	cleanup_ok=1
	stop_partial_anchor "$CLIENT_PID" "$CLIENT_START_TICKS" "$CLIENT_OWNER_UID" client_anchor || cleanup_ok=0
	reap_partial_wrapper "$CLIENT_WRAPPER_PID" "$CLIENT_WRAPPER_START_TICKS" "$CLIENT_WRAPPER_OWNER_UID" client_wrapper || cleanup_ok=0
	partial_process_absent "$CLIENT_PID" client_anchor || cleanup_ok=0
	stop_partial_anchor "$SERVER_PID" "$SERVER_START_TICKS" "$SERVER_OWNER_UID" server_anchor || cleanup_ok=0
	reap_partial_wrapper "$SERVER_WRAPPER_PID" "$SERVER_WRAPPER_START_TICKS" "$SERVER_WRAPPER_OWNER_UID" server_wrapper || cleanup_ok=0
	partial_process_absent "$SERVER_PID" server_anchor || cleanup_ok=0
	if [[ -s "$HOST_NS_FILE" ]] && [[ "$(readlink /proc/self/ns/net)" != "$(cat "$HOST_NS_FILE")" ]]; then
		cleanup_ok=0
	fi
	if [[ -s "$BASELINE_FILE" ]]; then
		CURRENT=$(mktemp)
		ip -brief link show > "$CURRENT"
		diff -u "$BASELINE_FILE" "$CURRENT" >/dev/null || cleanup_ok=0
		rm -f "$CURRENT"
	fi
	if [[ "$cleanup_ok" -eq 1 ]]; then
		rm -f "$SERVER_PIDFILE" "$CLIENT_PIDFILE"
		echo "MATCHED_SCHEDULER_PARTIAL_CLEANUP_OK" >&2
	else
		echo "MATCHED_SCHEDULER_PARTIAL_CLEANUP_FAILED" >&2
		status=1
	fi
	exit "$status"
}
trap cleanup_partial EXIT INT TERM

unshare --user --net --map-root-user --fork bash -c \
	"echo \$\$ > '$SERVER_PIDFILE'; exec sleep infinity" \
	</dev/null >"$RUNDIR/server_anchor.log" 2>&1 &
SERVER_WRAPPER_PID=$!
if [[ -r "/proc/$SERVER_WRAPPER_PID/stat" ]]; then
	SERVER_WRAPPER_START_TICKS=$(awk '{print $22}' "/proc/$SERVER_WRAPPER_PID/stat")
	SERVER_WRAPPER_OWNER_UID=$(stat -c '%u' "/proc/$SERVER_WRAPPER_PID")
fi
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
	[[ -s "$SERVER_PIDFILE" ]] && break
	sleep 0.2
done
[[ -s "$SERVER_PIDFILE" ]] || { echo "server anchor failed to start" >&2; exit 1; }
SERVER_PID=$(cat "$SERVER_PIDFILE")
kill -0 "$SERVER_PID"
SERVER_START_TICKS=$(awk '{print $22}' "/proc/$SERVER_PID/stat")
SERVER_OWNER_UID=$(stat -c '%u' "/proc/$SERVER_PID")
[[ "$SERVER_OWNER_UID" == "$(cat "$RUNDIR/owner_uid.txt")" ]] || {
	echo "server anchor owner mismatch" >&2; exit 1;
}

run_server() {
	nsenter --target "$SERVER_PID" --net --user --preserve-credentials -- \
		env SBEQ_RUN_DIR="$RUNDIR" "$@"
}

run_server unshare --net --fork bash -c \
	"echo \$\$ > '$CLIENT_PIDFILE'; exec sleep infinity" \
	</dev/null >"$RUNDIR/client_anchor.log" 2>&1 &
CLIENT_WRAPPER_PID=$!
if [[ -r "/proc/$CLIENT_WRAPPER_PID/stat" ]]; then
	CLIENT_WRAPPER_START_TICKS=$(awk '{print $22}' "/proc/$CLIENT_WRAPPER_PID/stat")
	CLIENT_WRAPPER_OWNER_UID=$(stat -c '%u' "/proc/$CLIENT_WRAPPER_PID")
fi
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
	[[ -s "$CLIENT_PIDFILE" ]] && break
	sleep 0.2
done
[[ -s "$CLIENT_PIDFILE" ]] || { echo "client anchor failed to start" >&2; exit 1; }
CLIENT_PID=$(cat "$CLIENT_PIDFILE")
kill -0 "$CLIENT_PID"
CLIENT_START_TICKS=$(awk '{print $22}' "/proc/$CLIENT_PID/stat")
CLIENT_OWNER_UID=$(stat -c '%u' "/proc/$CLIENT_PID")
[[ "$CLIENT_OWNER_UID" == "$(cat "$RUNDIR/owner_uid.txt")" ]] || {
	echo "client anchor owner mismatch" >&2; exit 1;
}

run_client() {
	nsenter --target "$SERVER_PID" --net --user --preserve-credentials -- \
		nsenter --target "$CLIENT_PID" --net -- env SBEQ_RUN_DIR="$RUNDIR" "$@"
}

# Freeze the address family surface before any interface is brought up.
# These are namespace-local sysctls inside the unprivileged user namespace;
# they cannot alter the host namespace.
run_server sysctl -qw net.ipv6.conf.all.disable_ipv6=1
run_server sysctl -qw net.ipv6.conf.default.disable_ipv6=1
run_client sysctl -qw net.ipv6.conf.all.disable_ipv6=1
run_client sysctl -qw net.ipv6.conf.default.disable_ipv6=1
run_server ip link add sbeq0-shared type veth peer name sbeq0-shrpeer
run_server ip link set sbeq0-shrpeer netns "$CLIENT_PID"
run_server ip addr add 198.51.100.9/30 dev sbeq0-shared
run_server ip addr replace 127.0.0.1/8 dev lo
run_server ip link set lo up
run_server ip link set sbeq0-shared up
run_client ip addr add 198.51.100.10/30 dev sbeq0-shrpeer
run_client ip addr replace 127.0.0.1/8 dev lo
run_client ip link set lo up
run_client ip link set sbeq0-shrpeer up

# Eliminate ARP packets from the measured qdisc accounting.  The veth MACs
# are read only after both endpoints exist and the resulting peer entries
# are permanent inside these two disposable namespaces.
# Query link-layer identity over namespace-local rtnetlink.  Reading the host's
# existing sysfs mount after only a user+network nsenter can expose the host
# network view on some distributions even though rtnetlink is correctly scoped.
read_link_mac() {
	python3 -c 'import json,sys; rows=json.load(sys.stdin); assert len(rows)==1; value=rows[0].get("address", ""); assert value; print(value.lower())'
}
SERVER_MAC=$(run_server ip -j link show dev sbeq0-shared | read_link_mac)
CLIENT_MAC=$(run_client ip -j link show dev sbeq0-shrpeer | read_link_mac)
run_server ip neigh replace 198.51.100.10 lladdr "$CLIENT_MAC" nud permanent dev sbeq0-shared
run_client ip neigh replace 198.51.100.9 lladdr "$SERVER_MAC" nud permanent dev sbeq0-shrpeer

run_server bash -c 'source "$1"; sbeq_require_full_isolation' bash "$SCRIPT_DIR/lib_isolation_guard.sh"
run_client bash -c 'source "$1"; sbeq_require_full_isolation' bash "$SCRIPT_DIR/lib_isolation_guard.sh"

printf '%s\n' "$SERVER_START_TICKS" > "$RUNDIR/server_start_ticks.txt"
printf '%s\n' "$CLIENT_START_TICKS" > "$RUNDIR/client_start_ticks.txt"
readlink "/proc/$SERVER_PID/ns/net" > "$RUNDIR/server_netns_id.txt"
readlink "/proc/$CLIENT_PID/ns/net" > "$RUNDIR/client_netns_id.txt"

trap - EXIT INT TERM
echo "MATCHED_SCHEDULER_SETUP_OK"
echo "server_pid=$SERVER_PID"
echo "client_pid=$CLIENT_PID"
echo "run_dir=testbed/run_matched_scheduler"
