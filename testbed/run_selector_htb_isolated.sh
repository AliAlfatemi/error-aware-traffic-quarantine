#!/usr/bin/env bash
# Enter a disposable user+network namespace before the Python runner mutates
# any link, address, neighbor, or qdisc state.

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <run_selector_htb arguments...>" >&2
    exit 2
fi

HOST_NETNS_ID=$(readlink /proc/self/ns/net)
PYTHON_EXECUTABLE=${CIQ_PYTHON:-python3}

exec unshare --user --map-root-user --net --fork \
    env CIQ_HOST_NETNS_ID="$HOST_NETNS_ID" \
    "$PYTHON_EXECUTABLE" -m testbed.run_selector_htb "$@"
