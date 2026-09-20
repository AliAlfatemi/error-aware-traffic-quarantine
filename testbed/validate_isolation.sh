#!/usr/bin/env bash
# validate_isolation.sh -- pure read-only check of both namespaces. Mutates
# nothing. Safe to run at any time, including repeatedly.
#
# Usage: ./validate_isolation.sh <server_anchor_pid> [client_anchor_pid]
# (client_anchor_pid defaults to the matched setup state directory selected by
# SBEQ_RUN_DIR, or ./run_matched_scheduler when that variable is absent.)

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ $# -lt 1 ]]; then
	echo "usage: $0 <server_anchor_pid> [client_anchor_pid]" >&2
	exit 2
fi
SERVER_PID="$1"
CLIENT_PID="${2:-$(cat "${SBEQ_RUN_DIR:-run_matched_scheduler}/client_anchor.pid" 2>/dev/null || true)}"

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
	echo "VALIDATION FAILED: server anchor pid $SERVER_PID is not running" >&2
	exit 1
fi

echo "=== server side (pid $SERVER_PID) ==="
nsenter --target "$SERVER_PID" --net --user --preserve-credentials -- bash -c "
	source '$(pwd)/lib_isolation_guard.sh'
	sbeq_require_full_isolation
	echo '-- interfaces --'; ip -brief link show
	echo '-- addresses --'; ip -brief addr show
	echo '-- qdiscs --'; tc qdisc show
"

if [[ -n "$CLIENT_PID" ]] && kill -0 "$CLIENT_PID" 2>/dev/null; then
	echo "=== client side (pid $CLIENT_PID) ==="
	# Reached via a double nsenter: the client netns is a child of the
		# SERVER anchor's user namespace (nested unshare --net, no second
		# --user -- see setup_matched_scheduler_netns.sh), so a lone
		# `nsenter --net` from the
	# top-level host shell lacks the capability to join it. Joining the
	# server's user+net namespace first, then the client's net namespace
	# from within that context, matches exactly what was verified working
	# by hand before this script was written.
	nsenter --target "$SERVER_PID" --net --user --preserve-credentials -- \
		nsenter --target "$CLIENT_PID" --net -- bash -c "
		source '$(pwd)/lib_isolation_guard.sh'
		sbeq_require_full_isolation
		echo '-- interfaces --'; ip -brief link show
		echo '-- addresses --'; ip -brief addr show
		echo '-- qdiscs --'; tc qdisc show
	"
else
	echo "(no client anchor pid given/running -- server-side check only)"
fi

echo ""
echo "VALIDATION PASSED"
