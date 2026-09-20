#!/usr/bin/env bash
# lib_isolation_guard.sh -- sourced by every other testbed/ script before it
# runs a single mutating command. Fail-closed by construction: every
# function here exits the calling script non-zero on anything unexpected,
# rather than warning and continuing.
#
# Safety model: all testbed interfaces live inside an unprivileged
# user+net namespace created by the applicable setup helper. This
# namespace starts with only a loopback interface and no route table, so a
# script running inside it structurally cannot reach the host's production
# non-allowlisted host interfaces or any production network --
# there is no path out. These checks exist to catch the one way that
# invariant could be violated: a script accidentally running in the HOST
# namespace instead of the isolated one (e.g., a missing nsenter, a copy-
# paste into the wrong shell). They are not what makes isolation true; the
# namespace boundary itself is. They are what makes a violation LOUD instead
# of silent.

set -euo pipefail

SBEQ_ALLOWED_IFACE_PREFIX="sbeq0-"

sbeq_fail() {
	echo "ISOLATION GUARD FAILED: $*" >&2
	echo "Refusing to proceed. No mutating command was run." >&2
	exit 1
}

# Fails unless the current process's network namespace differs from the
# host's. This is the single most important check: every other check in
# this file is meaningless if this one is wrong.
#
# Implementation note: this deliberately does NOT read /proc/1/ns/net to
# find "the host namespace" -- from inside a nested user namespace, reading
# another real process's /proc/<pid>/ns/net is permission-denied (the
# kernel's ptrace_may_access check does not treat a mapped-root uid inside
# a user namespace as equivalent to the real uid outside it, so PID 1's
# namespace file is unreadable even though our uid reads as 0 in here).
# Instead, setup_netns.sh captures the host's own namespace id via a
# SELF-read (`readlink /proc/self/ns/net`, run on the host, before
# unsharing anything) into run/host_netns_id.txt. This function only ever
# does self-reads (host writes its own id; the namespace later reads its
# own id and compares) -- no cross-process /proc read is ever needed.
sbeq_require_isolated_netns() {
	local self_ns host_ns_file host_ns
	self_ns=$(readlink /proc/self/ns/net 2>/dev/null) || sbeq_fail "cannot read /proc/self/ns/net"
	# The historical pilot uses ./run.  The matched scheduler diagnostic uses
	# a separate run directory so its namespace anchors cannot be confused
	# with pilot state.  Callers may select that exact directory explicitly.
	host_ns_file="${SBEQ_RUN_DIR:-./run}/host_netns_id.txt"
	[[ -f "$host_ns_file" ]] || sbeq_fail "$host_ns_file not found -- run the namespace setup helper first (it captures the host namespace id before creating the anchor)"
	host_ns=$(cat "$host_ns_file")
	if [[ "$self_ns" == "$host_ns" ]]; then
		sbeq_fail "current process is in the HOST network namespace (matches the id captured in $host_ns_file). This script must be run via nsenter into the anchor namespace created by setup_netns.sh, never directly."
	fi
	echo "isolation guard: confirmed running in an isolated network namespace ($self_ns != host $host_ns)"
}

# Fails unless every interface visible right now is either loopback or
# named with the sbeq0- prefix this project reserves for testbed veth
# endpoints. Any non-allowlisted interface visible here would mean the
# namespace is not what the setup helper created.
sbeq_require_only_allowed_interfaces() {
	local bad=0
	while read -r name; do
		name="${name%@*}" # strip @peer suffix ip -brief prints for veth
		if [[ "$name" != "lo" && "$name" != ${SBEQ_ALLOWED_IFACE_PREFIX}* ]]; then
			echo "unexpected interface present: $name" >&2
			bad=1
		fi
	done < <(ip -brief link show | awk '{print $1}')
	if [[ "$bad" -ne 0 ]]; then
		sbeq_fail "found interface(s) outside the {lo, ${SBEQ_ALLOWED_IFACE_PREFIX}*} allowlist -- this is not the expected isolated testbed namespace"
	fi
	echo "isolation guard: confirmed only allowlisted interfaces present (lo, ${SBEQ_ALLOWED_IFACE_PREFIX}*)"
}

# Fails if any default route exists. The isolated namespace should have no
# route out at all; a default route appearing would be the concrete
# mechanism by which test traffic could otherwise reach a real network.
sbeq_require_no_default_route() {
	local route_out
	route_out=$(ip route show default 2>/dev/null || true)
	if [[ -n "$route_out" ]]; then
		sbeq_fail "a default route exists in this namespace ($route_out) -- the testbed must have no route out"
	fi
	echo "isolation guard: confirmed no default route exists"
}

# Runs all three checks. Call this once at the top of every script that
# will run a mutating tc/ip command inside the namespace.
sbeq_require_full_isolation() {
	sbeq_require_isolated_netns
	sbeq_require_only_allowed_interfaces
	sbeq_require_no_default_route
	echo "isolation guard: ALL CHECKS PASSED"
}

# Dry-run helper: prints the command instead of running it when SBEQ_DRY_RUN=1.
sbeq_run() {
	if [[ "${SBEQ_DRY_RUN:-0}" == "1" ]]; then
		echo "[dry-run] would run: $*"
	else
		echo "+ $*"
		"$@"
	fi
}
