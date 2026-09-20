#!/usr/bin/env python3
"""Execute the frozen Study-B matched rootless HTB campaign.

Authoritative execution requires --profile authoritative and
--manage-namespaces. The latter creates exactly one isolated veth pair and
performs identity-checked teardown in a finally block. Existing result
directories are never resumed, replaced, or cleaned.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import math
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
import zlib
from array import array
from pathlib import Path
from typing import Any

try:
    from testbed.matched_scheduler_lib import (
        ARM_SCHEMA_VERSION,
        CAMPAIGN_SCHEMA_VERSION,
        FROZEN_SOURCE_RELATIVE_PATHS,
        PROJECT_ROOT,
        assert_only_frozen_tc_difference,
        available_cpu_assignment,
        build_execution_plan,
        file_sha256,
        load_config,
        make_tree_manifest,
        object_sha256,
        requested_tc_spec,
        require_finite_tree,
        tc_command_vectors,
        write_new_json,
    )
except ModuleNotFoundError:  # direct execution: script directory is sys.path[0]
    from matched_scheduler_lib import (
        ARM_SCHEMA_VERSION,
        CAMPAIGN_SCHEMA_VERSION,
        FROZEN_SOURCE_RELATIVE_PATHS,
        PROJECT_ROOT,
        assert_only_frozen_tc_difference,
        available_cpu_assignment,
        build_execution_plan,
        file_sha256,
        load_config,
        make_tree_manifest,
        object_sha256,
        requested_tc_spec,
        require_finite_tree,
        tc_command_vectors,
        write_new_json,
    )


TESTBED_DIR = Path(__file__).resolve().parent
TRAFFIC_PROGRAM = TESTBED_DIR / "matched_scheduler_traffic.py"
SETUP_SCRIPT = TESTBED_DIR / "setup_matched_scheduler_netns.sh"
TEARDOWN_SCRIPT = TESTBED_DIR / "teardown_matched_scheduler_netns.sh"
GUARD_SCRIPT = TESTBED_DIR / "lib_isolation_guard.sh"
RUN_DIR = TESTBED_DIR / "run_matched_scheduler"
LATENESS_SAMPLE_ENCODING = "zlib_base64_uint64_le_v1"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _private_string_replacements() -> tuple[tuple[str, str], ...]:
    candidates = (
        (str(PROJECT_ROOT.resolve()), "<PROJECT_ROOT>"),
        (str(Path.home().resolve()), "<HOME>"),
        (platform.node().strip(), "<HOSTNAME>"),
    )
    # Replacing a root slash or an empty/one-character hostname would destroy
    # evidence rather than redact an identifier.  Longest first ensures a
    # project path nested below HOME receives the more specific token.
    return tuple(
        sorted(
            (
                (needle, replacement)
                for needle, replacement in candidates
                if len(needle) > 1 and needle != os.sep
            ),
            key=lambda item: len(item[0]),
            reverse=True,
        )
    )


def redact_private_strings(value: Any) -> Any:
    """Redact host/account-specific identifiers from persisted diagnostics."""

    if isinstance(value, str):
        for needle, replacement in _private_string_replacements():
            value = value.replace(needle, replacement)
        return value
    if isinstance(value, list):
        return [redact_private_strings(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_private_strings(item) for item in value)
    if isinstance(value, dict):
        return {key: redact_private_strings(item) for key, item in value.items()}
    return value


def persisted_privacy_violations(root: Path) -> list[str]:
    """Return only relative file/token labels, never the private text itself."""

    violations: list[str] = []
    labels = {
        "<PROJECT_ROOT>": str(PROJECT_ROOT.resolve()),
        "<HOME>": str(Path.home().resolve()),
        "<HOSTNAME>": platform.node().strip(),
    }
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        payload = path.read_bytes()
        for label, needle in labels.items():
            if len(needle) > 1 and needle != os.sep and needle.encode() in payload:
                violations.append(f"{path.relative_to(root).as_posix()}:{label}")
    return violations


def run_command(
    command: list[str],
    *,
    timeout: float = 30.0,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=TESTBED_DIR,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {command!r}\n"
            f"stdout={completed.stdout[-4000:]}\nstderr={completed.stderr[-4000:]}"
        )
    return completed


def nsenter_server(server_pid: int, inner: list[str]) -> list[str]:
    return [
        "nsenter", "--target", str(server_pid), "--net", "--user",
        "--preserve-credentials", "--", *inner,
    ]


def nsenter_client(server_pid: int, client_pid: int, inner: list[str]) -> list[str]:
    return [
        "nsenter", "--target", str(server_pid), "--net", "--user",
        "--preserve-credentials", "--",
        "nsenter", "--target", str(client_pid), "--net", "--", *inner,
    ]


def guarded_client_command(server_pid: int, client_pid: int, inner: list[str]) -> list[str]:
    shell = 'source "$1"; sbeq_require_full_isolation; shift; exec "$@"'
    return nsenter_client(
        server_pid,
        client_pid,
        [
            "env", f"SBEQ_RUN_DIR={RUN_DIR}", "bash", "-c", shell, "bash",
            str(GUARD_SCRIPT), *inner,
        ],
    )


def validate_namespaces(server_pid: int, client_pid: int) -> dict[str, Any]:
    env = dict(os.environ)
    env["SBEQ_RUN_DIR"] = str(RUN_DIR)
    completed = run_command(
        ["bash", str(TESTBED_DIR / "validate_isolation.sh"), str(server_pid), str(client_pid)],
        timeout=20,
        env=env,
    )
    return {
        "validated_utc": utc_now(),
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "returncode": completed.returncode,
    }


def _process_identity(pid: int) -> dict[str, Any]:
    stat_path = Path(f"/proc/{pid}/stat")
    if not stat_path.is_file():
        raise RuntimeError(f"anchor process is absent: {pid}")
    suffix = stat_path.read_text(encoding="utf-8").rsplit(")", 1)[1].split()
    # Field 22 (starttime) is index 19 after fields 1/2 (pid/comm).
    return {
        "pid": pid,
        "start_ticks": int(suffix[19]),
        "owner_uid": stat_path.stat().st_uid,
        "netns_id": os.readlink(f"/proc/{pid}/ns/net"),
        "userns_id": os.readlink(f"/proc/{pid}/ns/user"),
    }


def capture_anchor_identity(server_pid: int, client_pid: int) -> dict[str, Any]:
    identity = {
        "server": _process_identity(server_pid),
        "client": _process_identity(client_pid),
    }
    if identity["server"]["netns_id"] == identity["client"]["netns_id"]:
        raise RuntimeError("server and client anchors share a network namespace")
    if identity["server"]["userns_id"] != identity["client"]["userns_id"]:
        raise RuntimeError("server and client anchors do not share the isolated user namespace")
    return identity


def require_managed_identity_files(identity: dict[str, Any]) -> None:
    expected_files = {
        ("server", "pid"): RUN_DIR / "server_anchor.pid",
        ("client", "pid"): RUN_DIR / "client_anchor.pid",
        ("server", "start_ticks"): RUN_DIR / "server_start_ticks.txt",
        ("client", "start_ticks"): RUN_DIR / "client_start_ticks.txt",
        ("server", "netns_id"): RUN_DIR / "server_netns_id.txt",
        ("client", "netns_id"): RUN_DIR / "client_netns_id.txt",
    }
    for (role, field), path in expected_files.items():
        if not path.is_file():
            raise RuntimeError(f"managed namespace identity file is missing: {path}")
        raw = path.read_text(encoding="utf-8").strip()
        expected = str(identity[role][field])
        if raw != expected:
            raise RuntimeError(
                f"managed namespace identity mismatch for {role}.{field}: "
                f"{raw!r} != {expected!r}"
            )


def _namespace_json(command: list[str]) -> list[dict[str, Any]]:
    completed = run_command(command, timeout=20)
    value = json.loads(completed.stdout)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise RuntimeError(f"namespace command did not return a JSON record list: {command}")
    return value


def validate_matched_namespace_state(
    config: dict[str, Any],
    server_pid: int,
    client_pid: int,
    expected_identity: dict[str, Any],
) -> dict[str, Any]:
    """Fail closed on the exact two-interface, TEST-NET-only topology."""

    actual_identity = capture_anchor_identity(server_pid, client_pid)
    if actual_identity != expected_identity:
        raise RuntimeError("namespace anchor PID/start-time/namespace identity changed")
    guard = validate_namespaces(server_pid, client_pid)
    network = config["network"]
    roles = {
        "server": {
            "command": lambda inner: nsenter_server(server_pid, inner),
            "interface": network["server_interface"],
            "address": f"{network['server_ip']}/{network['prefix_length']}",
        },
        "client": {
            "command": lambda inner: nsenter_client(server_pid, client_pid, inner),
            "interface": network["client_interface"],
            "address": f"{network['client_ip']}/{network['prefix_length']}",
        },
    }
    snapshots: dict[str, Any] = {}
    errors: list[str] = []
    for role, expected in roles.items():
        wrap = expected["command"]
        links = _namespace_json(wrap(["ip", "-j", "link", "show"]))
        ipv4 = _namespace_json(wrap(["ip", "-j", "-4", "addr", "show"]))
        ipv6 = _namespace_json(wrap(["ip", "-j", "-6", "addr", "show"]))
        routes4 = _namespace_json(
            wrap(["ip", "-j", "-4", "route", "show", "table", "main"])
        )
        routes6 = _namespace_json(
            wrap(["ip", "-j", "-6", "route", "show", "table", "main"])
        )
        neighbors = _namespace_json(wrap(["ip", "-j", "neigh", "show"]))
        ipv6_disabled = run_command(
            wrap(["cat", "/proc/sys/net/ipv6/conf/all/disable_ipv6"]), timeout=10
        ).stdout.strip()
        link_names = sorted(str(item.get("ifname")) for item in links)
        expected_links = sorted(["lo", expected["interface"]])
        if link_names != expected_links:
            errors.append(f"{role}:interfaces:{link_names!r}!={expected_links!r}")

        addresses4 = sorted(
            f"{address.get('local')}/{address.get('prefixlen')}"
            for item in ipv4
            for address in item.get("addr_info", [])
            if address.get("family") == "inet"
        )
        expected_addresses4 = sorted([network["loopback_ipv4"], expected["address"]])
        if addresses4 != expected_addresses4:
            errors.append(
                f"{role}:ipv4_addresses:{addresses4!r}!={expected_addresses4!r}"
            )
        addresses6 = [
            address
            for item in ipv6
            for address in item.get("addr_info", [])
            if address.get("family") == "inet6"
        ]
        if addresses6 or routes6 or ipv6_disabled != "1":
            errors.append(
                f"{role}:ipv6_not_exactly_disabled:addresses={addresses6!r}:"
                f"routes={routes6!r}:sysctl={ipv6_disabled!r}"
            )
        normalized_routes4 = sorted(
            (str(route.get("dst")), str(route.get("dev"))) for route in routes4
        )
        expected_routes4 = [(network["main_route"], expected["interface"])]
        if normalized_routes4 != expected_routes4:
            errors.append(
                f"{role}:main_routes:{normalized_routes4!r}!={expected_routes4!r}"
            )
        snapshots[role] = {
            "links": links,
            "ipv4_addresses": ipv4,
            "ipv6_addresses": ipv6,
            "ipv4_main_routes": routes4,
            "ipv6_main_routes": routes6,
            "neighbors": neighbors,
            "ipv6_disabled": ipv6_disabled,
        }
    peer_expectations = {
        "server": ("client", network["client_ip"]),
        "client": ("server", network["server_ip"]),
    }
    for role, (peer_role, peer_ip) in peer_expectations.items():
        peer_interface = roles[peer_role]["interface"]
        peer_link = next(
            item
            for item in snapshots[peer_role]["links"]
            if item.get("ifname") == peer_interface
        )
        expected_neighbor = {
            "dst": peer_ip,
            "dev": roles[role]["interface"],
            "lladdr": str(peer_link.get("address", "")).lower(),
            "state": ["PERMANENT"],
        }
        normalized_neighbors = [
            {
                "dst": item.get("dst"),
                "dev": item.get("dev"),
                "lladdr": str(item.get("lladdr", "")).lower(),
                "state": item.get("state"),
            }
            for item in snapshots[role]["neighbors"]
        ]
        if normalized_neighbors != [expected_neighbor]:
            errors.append(
                f"{role}:permanent_neighbor:{normalized_neighbors!r}!="
                f"{[expected_neighbor]!r}"
            )
    if errors:
        raise RuntimeError("exact namespace validation failed: " + ";".join(errors))
    return {
        "validated_utc": utc_now(),
        "anchor_identity": actual_identity,
        "generic_isolation_guard": guard,
        "exact_state": snapshots,
        "errors": [],
    }


def apply_tc(server_pid: int, client_pid: int, spec: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    for index, vector in enumerate(tc_command_vectors(spec)):
        completed = run_command(
            guarded_client_command(server_pid, client_pid, vector),
            timeout=20,
            check=False,
        )
        allowed_missing_root = (
            index == 0
            and completed.returncode != 0
            and any(
                fragment in (completed.stdout + completed.stderr).lower()
                for fragment in (
                    "no such file",
                    "cannot delete qdisc with handle of zero",
                    "invalid argument",
                )
            )
        )
        record = {
            "index": index,
            "argv": vector,
            "returncode": completed.returncode,
            "allowed_initial_root_absence": allowed_missing_root,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
        records.append(record)
        if completed.returncode != 0 and not allowed_missing_root:
            raise RuntimeError(f"tc apply command {index} failed: {record}")
    return records


def tc_snapshot(server_pid: int, client_pid: int, interface: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "capture_started_monotonic_ns": time.monotonic_ns(),
        "commands": {},
    }
    for category in ("qdisc", "class", "filter"):
        vector = ["tc", "-s", "-d", "-j", category, "show", "dev", interface]
        completed = run_command(nsenter_client(server_pid, client_pid, vector), timeout=20)
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError(f"tc {category} did not emit JSON: {error}") from error
        if not isinstance(payload, list):
            raise RuntimeError(f"tc {category} JSON is not a list")
        result["commands"][category] = {"argv": vector, "records": payload}
    result["capture_finished_monotonic_ns"] = time.monotonic_ns()
    return result


def _rate_Bps(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return float(value)
    if not isinstance(value, str):
        return None
    cleaned = value.strip().replace(" ", "")
    units = {
        "Bps": 1.0,
        "Kbit": 1000.0 / 8.0,
        "Mbit": 1_000_000.0 / 8.0,
        "Gbit": 1_000_000_000.0 / 8.0,
        "bit": 1.0 / 8.0,
    }
    for suffix, multiplier in units.items():
        if cleaned.endswith(suffix):
            try:
                return float(cleaned[: -len(suffix)]) * multiplier
            except ValueError:
                return None
    return None


def _by_identity(records: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    return {str(record.get(key)): record for record in records if record.get(key) is not None}


def validate_live_tc(snapshot: dict[str, Any], spec: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    qdiscs = snapshot["commands"]["qdisc"]["records"]
    classes = snapshot["commands"]["class"]["records"]
    filters = snapshot["commands"]["filter"]["records"]
    qdisc_by_handle = _by_identity(qdiscs, "handle")
    # iproute2 6.4 identifies classes with "handle" and calls the class
    # implementation "class"; earlier JSON variants used classid/kind.
    class_by_id = {
        str(record.get("classid", record.get("handle"))): record
        for record in classes
        if record.get("classid", record.get("handle")) is not None
    }
    expected_qdisc_handles = {
        spec["root"]["handle"],
        spec["classes"]["fast"]["bfifo_handle"],
        spec["classes"]["suspicious"]["bfifo_handle"],
    }
    if set(qdisc_by_handle) != expected_qdisc_handles:
        errors.append(
            "qdisc handle set mismatch: "
            f"{sorted(qdisc_by_handle)} vs {sorted(expected_qdisc_handles)}"
        )
    expected_classids = {
        spec["root"]["classid"],
        spec["classes"]["fast"]["classid"],
        spec["classes"]["suspicious"]["classid"],
    }
    if set(class_by_id) != expected_classids:
        errors.append(
            "class id set mismatch: "
            f"{sorted(class_by_id)} vs {sorted(expected_classids)}"
        )
    root_qdisc = qdisc_by_handle.get("1:")
    if not root_qdisc or root_qdisc.get("kind") != "htb" or root_qdisc.get("root") is not True:
        errors.append("missing root htb qdisc handle 1:")
    elif (
        root_qdisc.get("options", {}).get("r2q") != spec["root"]["r2q"]
        or root_qdisc.get("options", {}).get("direct_qlen")
        != spec["root"]["direct_qlen_packets"]
        or root_qdisc.get("options", {}).get("default")
        not in {
            spec["root"]["default_class_minor"],
            f"0x{spec['root']['default_class_minor']}",
            str(spec["root"]["default_class_minor"]),
        }
    ):
        errors.append("root htb r2q/default mismatch")
    for label in ("fast", "suspicious"):
        expected = spec["classes"][label]
        qdisc = qdisc_by_handle.get(expected["bfifo_handle"])
        if not qdisc or qdisc.get("kind") != "bfifo" or qdisc.get("parent") != expected["classid"]:
            errors.append(f"missing {label} bfifo on {expected['classid']}")
        else:
            actual_limit = qdisc.get("options", {}).get("limit")
            if actual_limit is not None and int(actual_limit) != expected["bfifo_limit_bytes"]:
                errors.append(f"{label} bfifo limit mismatch: {actual_limit}")
    expected_classes = {
        "1:1": spec["root"],
        spec["classes"]["fast"]["classid"]: spec["classes"]["fast"],
        spec["classes"]["suspicious"]["classid"]: spec["classes"]["suspicious"],
    }
    for classid, expected in expected_classes.items():
        observed = class_by_id.get(classid)
        if not observed or observed.get("kind", observed.get("class")) != "htb":
            errors.append(f"missing htb class {classid}")
            continue
        if classid == spec["root"]["classid"]:
            if observed.get("root") is not True:
                errors.append(f"root class {classid} is not marked root")
        elif observed.get("parent") != expected["parent"]:
            errors.append(
                f"class {classid} parent mismatch: "
                f"{observed.get('parent')} vs {expected['parent']}"
            )
        options = {**observed, **observed.get("options", {})}
        for key, expected_value in (
            ("rate", expected["rate_Bps"]),
            ("ceil", expected["ceil_Bps"]),
        ):
            actual = _rate_Bps(options.get(key))
            if actual is None:
                errors.append(f"class {classid} lacks machine-readable {key}")
            elif abs(actual - expected_value) > max(1.0, expected_value * 0.001):
                errors.append(f"class {classid} {key} mismatch: {actual} vs {expected_value}")
        for key, expected_key in (
            ("burst", "burst_bytes"),
            ("cburst", "cburst_bytes"),
            ("quantum", "quantum_bytes"),
        ):
            # The root class has no siblings, so Linux omits its inoperative
            # quantum from tc JSON even when the explicit command supplied it.
            if classid == "1:1" and key == "quantum" and options.get(key) is None:
                continue
            if options.get(key) != expected[expected_key]:
                errors.append(
                    f"class {classid} {key} mismatch: "
                    f"{options.get(key)} vs {expected[expected_key]}"
                )
        if not (
            classid == "1:1" and options.get("prio") is None
        ) and options.get("prio") != expected["priority"]:
            errors.append(
                f"class {classid} prio mismatch: "
                f"{options.get('prio')} vs {expected['priority']}"
            )
        if options.get("linklayer") != expected["linklayer"]:
            errors.append(
                f"class {classid} linklayer mismatch: "
                f"{options.get('linklayer')} vs {expected['linklayer']}"
            )
    filter_items = [
        item
        for item in filters
        if item.get("kind") == "u32" and item.get("options", {}).get("flowid")
    ]
    if len(filters) != 6 or len(filter_items) != 2:
        errors.append(f"filter record count/type mismatch: {len(filters)} total")
    filter_rules = {
        item.get("options", {}).get("flowid"): item for item in filter_items
    }
    expected_filter_matches = {
        "1:10": {"value": "100000", "mask": "ff0000"},
        "1:20": {"value": "0", "mask": "ff0000"},
    }
    for flowid, expected_match in expected_filter_matches.items():
        item = filter_rules.get(flowid, {})
        actual_match = item.get("options", {}).get("match", {})
        if any(actual_match.get(key) != value for key, value in expected_match.items()):
            errors.append(f"missing or mismatched TOS filter for {flowid}")
            continue
        expected_pref = 1 if flowid == "1:10" else 2
        if (
            item.get("protocol") != "ip"
            or item.get("pref") != expected_pref
            or item.get("parent") != "1:"
            or item.get("chain") != 0
            or actual_match.get("off") != 0
        ):
            errors.append(f"filter metadata mismatch for {flowid}")
        expected_table = "800" if expected_pref == 1 else "801"
        expected_rule_options = {
            "fh": f"{expected_table}::800",
            "bkt": "0",
            "key_ht": expected_table,
            "order": 2048,
        }
        if any(
            item.get("options", {}).get(key, item.get(key)) != value
            for key, value in expected_rule_options.items()
        ):
            errors.append(f"filter u32 handle/order mismatch for {flowid}")
        same_pref = [candidate for candidate in filters if candidate.get("pref") == expected_pref]
        headers = [candidate for candidate in same_pref if not candidate.get("options")]
        tables = [
            candidate
            for candidate in same_pref
            if candidate.get("options", {}).get("ht_divisor") == 1
        ]
        if (
            len(same_pref) != 3
            or len(headers) != 1
            or len(tables) != 1
            or tables[0].get("options", {}).get("fh") != f"{expected_table}:"
            or any(
                candidate.get("kind") != "u32"
                or candidate.get("protocol") != "ip"
                or candidate.get("parent") != "1:"
                or candidate.get("chain") != 0
                for candidate in same_pref
            )
        ):
            errors.append(f"filter header/table topology mismatch for preference {expected_pref}")
    return errors


def _tc_counter(
    snapshot: dict[str, Any], category: str, identity: str, name: str
) -> int | None:
    identity_key = "handle"
    records = snapshot["commands"][category]["records"]
    record = next(
        (
            item
            for item in records
            if str(item.get("classid", item.get(identity_key))) == identity
        ),
        None,
    )
    if record is None:
        return None
    if isinstance(record.get(name), (int, float)):
        return int(record[name])
    stats = record.get("stats", {})
    if isinstance(stats.get(name), (int, float)):
        return int(stats[name])
    stats2 = record.get("stats2", {})
    if name in {"packets", "bytes"}:
        value = stats2.get("basic", {}).get(name)
    else:
        value = stats2.get("queue", {}).get(name)
    return int(value) if isinstance(value, (int, float)) else None


def _counter_delta(
    before: dict[str, Any],
    after: dict[str, Any],
    category: str,
    identity: str,
    name: str,
) -> int | None:
    first = _tc_counter(before, category, identity, name)
    last = _tc_counter(after, category, identity, name)
    if first is None or last is None or last < first:
        return None
    return last - first


def _read_proc_stat() -> dict[str, tuple[int, int]]:
    result: dict[str, tuple[int, int]] = {}
    for line in Path("/proc/stat").read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if not fields or (fields[0] != "cpu" and not fields[0].startswith("cpu")):
            continue
        if fields[0] != "cpu" and not fields[0][3:].isdigit():
            continue
        ticks = [int(field) for field in fields[1:]]
        if len(ticks) < 4:
            raise RuntimeError(f"short /proc/stat CPU record: {line}")
        idle = ticks[3] + (ticks[4] if len(ticks) > 4 else 0)
        total = sum(ticks[:8])
        result[fields[0]] = (total - idle, total)
    if "cpu" not in result:
        raise RuntimeError("/proc/stat has no aggregate CPU record")
    return result


def summarize_background_cpu(
    before: dict[str, tuple[int, int]],
    after: dict[str, tuple[int, int]],
    cpu_assignment: dict[str, int],
) -> dict[str, Any]:
    def delta(label: str) -> tuple[int, int, float]:
        if label not in before or label not in after:
            raise RuntimeError(f"/proc/stat is missing {label}")
        busy_delta = after[label][0] - before[label][0]
        total_delta = after[label][1] - before[label][1]
        if busy_delta < 0 or total_delta <= 0 or busy_delta > total_delta:
            raise RuntimeError(f"invalid /proc/stat delta for {label}")
        return busy_delta, total_delta, busy_delta / total_delta * 100.0

    assigned = {}
    for role, cpu_id in cpu_assignment.items():
        busy_delta, total_delta, busy_percent = delta(f"cpu{cpu_id}")
        assigned[role] = {
            "cpu_id": cpu_id,
            "busy_ticks_delta": busy_delta,
            "total_ticks_delta": total_delta,
            "busy_percent": busy_percent,
        }
    aggregate_busy, aggregate_total, aggregate_percent = delta("cpu")
    logical_cpu_count = sum(label != "cpu" for label in before)
    return {
        "assigned_cpus": assigned,
        "maximum_assigned_cpu_busy_percent": max(
            sample["busy_percent"] for sample in assigned.values()
        ),
        "whole_host_aggregate_descriptive_only": {
            "busy_ticks_delta": aggregate_busy,
            "total_ticks_delta": aggregate_total,
            "busy_percent_total_capacity": aggregate_percent,
            "busy_percent_one_core_equivalent": aggregate_percent
            * logical_cpu_count,
            "logical_cpu_count": logical_cpu_count,
            "used_as_invalidation_trigger": False,
        },
    }


def background_cpu_sample(
    duration_s: float, cpu_assignment: dict[str, int]
) -> dict[str, Any]:
    before = _read_proc_stat()
    start_ns = time.monotonic_ns()
    time.sleep(duration_s)
    end_ns = time.monotonic_ns()
    after = _read_proc_stat()
    result = {
        "sample_start_monotonic_ns": start_ns,
        "sample_end_monotonic_ns": end_ns,
        "requested_duration_s": duration_s,
        "actual_duration_s": (end_ns - start_ns) / 1e9,
        "loadavg": list(os.getloadavg()),
    }
    result.update(summarize_background_cpu(before, after, cpu_assignment))
    return result


def live_cpu_topology(
    assignment: dict[str, int], expected: dict[str, dict[str, int]]
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for role, cpu_id in assignment.items():
        base = Path(f"/sys/devices/system/cpu/cpu{cpu_id}")
        topology = base / "topology"
        node_ids = sorted(
            int(path.name[4:])
            for path in base.glob("node[0-9]*")
            if path.name[4:].isdigit()
        )
        observed = {
            "cpu_id": cpu_id,
            "physical_package_id": int(
                (topology / "physical_package_id").read_text().strip()
            ),
            "core_id": int((topology / "core_id").read_text().strip()),
            "numa_node": node_ids[0] if len(node_ids) == 1 else None,
            "thread_siblings_list": (
                topology / "thread_siblings_list"
            ).read_text().strip(),
        }
        expected_record = expected[role]
        for key in ("cpu_id", "physical_package_id", "core_id", "numa_node"):
            if observed[key] != expected_record[key]:
                raise RuntimeError(
                    f"live CPU topology mismatch for {role}.{key}: "
                    f"{observed[key]} != {expected_record[key]}"
                )
        result[role] = observed
    physical_cores = {
        (record["physical_package_id"], record["core_id"])
        for record in result.values()
    }
    if len(physical_cores) != len(result):
        raise RuntimeError("assigned processes are not on distinct physical cores")
    return result


def system_metadata(config: dict[str, Any]) -> dict[str, Any]:
    os_release = {}
    path = Path("/etc/os-release")
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                if key in {"ID", "VERSION_ID", "PRETTY_NAME"}:
                    os_release[key] = value.strip().strip('"')
    cpu_model = "unknown"
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        for line in cpuinfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.lower().startswith("model name") and ":" in line:
                cpu_model = line.split(":", 1)[1].strip()
                break
    assignment = available_cpu_assignment(config)
    topology = live_cpu_topology(
        assignment,
        config["execution"]["cpu_affinity_selection"]["expected_linux_topology"],
    )
    governors = {}
    for role, cpu_id in assignment.items():
        governor = Path(f"/sys/devices/system/cpu/cpu{cpu_id}/cpufreq/scaling_governor")
        governors[role] = governor.read_text().strip() if governor.is_file() else "unavailable"

    def version(command: list[str]) -> str:
        completed = run_command(command, timeout=10, check=False)
        output = (completed.stdout or completed.stderr).strip()
        return output.splitlines()[0] if output else "unavailable"

    return {
        "captured_utc": utc_now(),
        "kernel_release": platform.release(),
        "kernel_machine": platform.machine(),
        "python_version": platform.python_version(),
        "os_release": os_release,
        "cpu_model": cpu_model,
        "logical_cpu_count": os.cpu_count(),
        "available_cpu_ids": sorted(os.sched_getaffinity(0)),
        "resolved_process_cpu_affinity": assignment,
        "verified_cpu_topology": topology,
        "cpufreq_governors": governors,
        "tc_version": version(["tc", "-V"]),
        "ip_version": version(["ip", "-V"]),
        "unshare_version": version(["unshare", "--version"]),
        "socket_buffer_sysctls": {
            name: Path(f"/proc/sys/net/core/{name}").read_text().strip()
            for name in ("rmem_default", "rmem_max", "wmem_default", "wmem_max")
            if Path(f"/proc/sys/net/core/{name}").is_file()
        },
    }


def _last_json_line(output: str) -> dict[str, Any]:
    for line in reversed(output.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return {}


def decode_lateness_samples(
    block: dict[str, Any], *, expected_count: int
) -> list[int]:
    """Decode and authenticate one lossless traffic-process sample vector."""

    expected_keys = {
        "encoding", "sample_count", "uncompressed_sha256", "data_base64"
    }
    if not isinstance(block, dict) or set(block) != expected_keys:
        raise ValueError("lateness sample block has an unexpected shape")
    if block["encoding"] != LATENESS_SAMPLE_ENCODING:
        raise ValueError("lateness sample encoding differs from the frozen encoding")
    count = block["sample_count"]
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ValueError("lateness sample count is not a nonnegative integer")
    if (
        isinstance(expected_count, bool)
        or not isinstance(expected_count, int)
        or expected_count < 0
    ):
        raise ValueError("expected lateness sample count is invalid")
    if count != expected_count:
        raise ValueError(
            f"lateness sample count mismatch: {count} != {expected_count}"
        )
    digest = block["uncompressed_sha256"]
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ValueError("lateness sample SHA-256 is malformed")
    encoded = block["data_base64"]
    if not isinstance(encoded, str) or not encoded.isascii():
        raise ValueError("lateness sample data is not ASCII base64")
    try:
        compressed = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("lateness sample data is not canonical base64") from error
    if base64.b64encode(compressed).decode("ascii") != encoded:
        raise ValueError("lateness sample base64 representation is not canonical")
    expected_bytes = count * 8
    # A valid zlib stream is never usefully larger than this conservative
    # bound for an exact fixed-width vector.  Bound the compressed input and
    # decompressed output before allocating attacker-controlled evidence.
    if len(compressed) > max(128, expected_bytes * 2 + 1024):
        raise ValueError("lateness sample compressed payload is implausibly large")
    decompressor = zlib.decompressobj()
    try:
        raw = decompressor.decompress(compressed, expected_bytes + 1)
    except zlib.error as error:
        raise ValueError("lateness sample zlib stream is invalid") from error
    if (
        len(raw) != expected_bytes
        or not decompressor.eof
        or decompressor.unconsumed_tail
        or decompressor.unused_data
    ):
        raise ValueError("lateness sample zlib stream length/framing is invalid")
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("lateness sample uncompressed SHA-256 mismatch")
    words = array("Q")
    words.frombytes(raw)
    if sys.byteorder != "little":
        words.byteswap()
    return [int(value) for value in words]


def _lateness_summary(values: list[int]) -> dict[str, Any]:
    return {
        "sample_count": len(values),
        "mean_ns": sum(values) / len(values) if values else None,
        "max_ns": max(values) if values else None,
        "p99_ns": (
            sorted(values)[max(0, math.ceil(0.99 * len(values)) - 1)]
            if values
            else None
        ),
    }


def _wait_for_ready(
    process: subprocess.Popen[str],
    timeout_s: float,
    *,
    role: str,
    traffic_class: str | None = None,
) -> dict[str, Any]:
    if process.stdout is None:
        raise RuntimeError("receiver stdout pipe is absent")
    import select

    readable, _, _ = select.select([process.stdout], [], [], timeout_s)
    if not readable:
        raise TimeoutError(f"{role} did not emit its ready record")
    line = process.stdout.readline()
    ready = json.loads(line)
    if ready.get("event") != "ready" or ready.get("role") != role:
        raise RuntimeError(f"unexpected {role} first record: {ready}")
    if traffic_class is not None and ready.get("traffic_class") != traffic_class:
        raise RuntimeError(f"unexpected sender class in ready record: {ready}")
    return ready


def _terminate(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=2)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=2)


def _sleep_until(deadline_ns: int) -> None:
    while True:
        remaining = deadline_ns - time.monotonic_ns()
        if remaining <= 0:
            return
        time.sleep(min(0.1, remaining / 1e9))


def _traffic_common(config: dict[str, Any], trial: dict[str, Any]) -> list[str]:
    return [
        "--warmup-s", str(trial["warmup_s"]),
        "--measurement-s", str(trial["measurement_s"]),
        "--drain-s", str(trial["drain_s"]),
        "--packet-size", str(config["traffic"]["packet_payload_bytes"]),
        "--socket-buffer-bytes", str(config["traffic"]["socket_buffer_request_bytes"]),
    ]


def _process_record(process: subprocess.Popen[str], timeout_s: float) -> dict[str, Any]:
    stdout, stderr = process.communicate(timeout=timeout_s)
    return {
        "returncode": process.returncode,
        "final_record": _last_json_line(stdout),
        "stderr": stderr,
        "stdout_non_json_line_count": sum(
            1
            for line in stdout.splitlines()
            if line.strip() and not line.lstrip().startswith("{")
        ),
    }


def build_counter_reconciliation(
    config: dict[str, Any],
    receiver: dict[str, Any],
    benign: dict[str, Any],
    suspicious: dict[str, Any],
    tc_arm_start: dict[str, Any],
    tc_measurement_start: dict[str, Any],
    tc_measurement_end: dict[str, Any],
    tc_arm_end: dict[str, Any],
) -> dict[str, Any]:
    errors: list[str] = []
    packet_size = config["traffic"]["packet_payload_bytes"]
    qdisc_packet_bytes = config["traffic"]["accounting"][
        "configured_qdisc_accounted_bytes_per_packet"
    ]
    received = receiver.get("counts_by_arrival_window", {}).get("measurement", {})
    cohort_matrix = receiver.get("sender_phase_by_arrival_window", {})
    sender_by_class = {"benign": benign, "suspicious": suspicious}
    for label, sender in sender_by_class.items():
        received_packets = received.get(f"{label}_packets")
        received_bytes = received.get(f"{label}_bytes")
        if not all(
            isinstance(value, int)
            for value in (received_packets, received_bytes)
        ):
            errors.append(f"missing {label} application counters")
            continue
        if received_bytes != received_packets * packet_size:
            errors.append(f"{label} received byte/packet counters disagree")
        for phase in ("warmup", "measurement"):
            sent_packets = sender.get("sent", {}).get(phase, {}).get("packets")
            cohort_received = sum(
                window.get(f"{label}_packets", 0)
                for window in cohort_matrix.get(phase, {}).values()
            )
            if not isinstance(sent_packets, int):
                errors.append(f"missing {label} {phase} sender counter")
            elif cohort_received > sent_packets:
                errors.append(
                    f"{label} {phase}-origin receiver cohort exceeds successful sends"
                )
    root_measurement_packets = _counter_delta(
        tc_measurement_start, tc_measurement_end, "qdisc", "1:", "packets"
    )
    root_measurement_bytes = _counter_delta(
        tc_measurement_start, tc_measurement_end, "qdisc", "1:", "bytes"
    )
    if root_measurement_packets is None or root_measurement_bytes is None:
        errors.append("root qdisc packet counters are missing or nonmonotonic")
    else:
        sent_total = sum(
            sender.get("sent", {}).get("measurement", {}).get("packets", 0)
            for sender in (benign, suspicious)
        )
        received_total = sum(
            received.get(f"{label}_packets", 0)
            for label in ("benign", "suspicious")
        )
        tolerance = max(
            config["validity"]["qdisc_packet_conservation_absolute_tolerance"],
            math.ceil(
                sent_total
                * config["validity"]["counter_reconciliation_relative_tolerance"]
            ),
        )
        if abs(root_measurement_packets - received_total) > tolerance:
            errors.append(
                "root qdisc measurement departures do not match receiver arrival-window packets"
            )
        if root_measurement_packets > sent_total + tolerance:
            errors.append("qdisc measurement delta exceeds sender success beyond tolerance")
        if root_measurement_bytes != root_measurement_packets * qdisc_packet_bytes:
            errors.append("root qdisc measurement bytes do not use frozen 1242-byte SKB unit")

    root_arm = {
        name: _counter_delta(tc_arm_start, tc_arm_end, "qdisc", "1:", name)
        for name in ("packets", "bytes", "drops")
    }
    sent_arm_packets = sum(
        sender.get("sent", {}).get(phase, {}).get("packets", 0)
        for sender in (benign, suspicious)
        for phase in ("warmup", "measurement")
    )
    received_arm_packets = sum(
        window.get(f"{label}_packets", 0)
        for window in receiver.get("counts_by_arrival_window", {}).values()
        for label in ("benign", "suspicious")
    )
    absolute_tolerance = config["validity"][
        "qdisc_packet_conservation_absolute_tolerance"
    ]
    if any(value is None for value in root_arm.values()):
        errors.append("root qdisc arm counters are missing or nonmonotonic")
    else:
        assert all(isinstance(value, int) for value in root_arm.values())
        if abs(root_arm["packets"] + root_arm["drops"] - sent_arm_packets) > absolute_tolerance:
            errors.append("root qdisc departures+drops do not conserve successful sends")
        if abs(root_arm["packets"] - received_arm_packets) > absolute_tolerance:
            errors.append("root qdisc arm departures do not reconcile receiver arrivals")
        if root_arm["bytes"] != root_arm["packets"] * qdisc_packet_bytes:
            errors.append("root qdisc arm bytes do not use frozen 1242-byte SKB unit")

    leaf_arm: dict[str, dict[str, int | None]] = {}
    class_arm: dict[str, dict[str, int | None]] = {}
    for label, qdisc_handle, classid in (
        ("fast", "10:", "1:10"),
        ("suspicious", "20:", "1:20"),
    ):
        leaf_arm[label] = {
            name: _counter_delta(
                tc_arm_start, tc_arm_end, "qdisc", qdisc_handle, name
            )
            for name in ("packets", "bytes", "drops")
        }
        class_arm[label] = {
            name: _counter_delta(
                tc_arm_start, tc_arm_end, "class", classid, name
            )
            for name in ("packets", "bytes", "drops")
        }
    for name in ("packets", "bytes", "drops"):
        leaf_values = [leaf_arm[label][name] for label in ("fast", "suspicious")]
        if root_arm[name] is None or any(value is None for value in leaf_values):
            errors.append(f"leaf/root {name} counters are unavailable")
        elif sum(int(value) for value in leaf_values) != root_arm[name]:
            errors.append(f"leaf qdisc {name} counters do not sum exactly to root")
        class_values = [class_arm[label][name] for label in ("fast", "suspicious")]
        if root_arm[name] is None or any(value is None for value in class_values):
            errors.append(f"child/root class {name} counters are unavailable")
        elif sum(int(value) for value in class_values) != root_arm[name]:
            errors.append(f"child class {name} counters do not sum exactly to root")

    backlogs: dict[str, Any] = {}
    for snapshot_name, snapshot in (
        ("arm_start", tc_arm_start),
        ("measurement_start", tc_measurement_start),
        ("measurement_end", tc_measurement_end),
        ("arm_end", tc_arm_end),
    ):
        root_backlog = _tc_counter(snapshot, "qdisc", "1:", "backlog")
        leaf_backlogs = {
            "fast": _tc_counter(snapshot, "qdisc", "10:", "backlog"),
            "suspicious": _tc_counter(snapshot, "qdisc", "20:", "backlog"),
        }
        backlogs[snapshot_name] = {
            "root_bytes": root_backlog,
            "leaf_bytes": leaf_backlogs,
        }
        if root_backlog is None or any(value is None for value in leaf_backlogs.values()):
            errors.append(f"qdisc backlog counters unavailable at {snapshot_name}")
        elif root_backlog != sum(int(value) for value in leaf_backlogs.values()):
            errors.append(f"leaf qdisc backlog does not sum exactly at {snapshot_name}")
    if backlogs.get("arm_start", {}).get("root_bytes") not in (0, None):
        errors.append("root qdisc backlog is nonzero at arm start")
    if backlogs.get("arm_end", {}).get("root_bytes") not in (0, None):
        errors.append("root qdisc backlog is nonzero after drain")

    evidence = {
        "primary_receiver_window": "arrival_measurement",
        "qdisc_byte_unit_bytes_per_departure": qdisc_packet_bytes,
        "measurement": {
            "root_departure_packets": root_measurement_packets,
            "root_departure_bytes": root_measurement_bytes,
            "receiver_arrival_packets": sum(
                received.get(f"{label}_packets", 0)
                for label in ("benign", "suspicious")
            ),
            "sender_success_packets": sum(
                sender.get("sent", {}).get("measurement", {}).get("packets", 0)
                for sender in (benign, suspicious)
            ),
        },
        "arm": {
            "root": root_arm,
            "leaf_qdiscs": leaf_arm,
            "child_classes": class_arm,
            "sender_success_packets": sent_arm_packets,
            "receiver_arrival_packets": received_arm_packets,
        },
        "backlogs": backlogs,
        "errors": sorted(set(errors)),
    }
    require_finite_tree(evidence)
    return evidence


def determine_validity(
    config: dict[str, Any],
    profile: dict[str, Any],
    trial: dict[str, Any],
    record: dict[str, Any],
) -> tuple[bool, list[str], dict[str, Any]]:
    reasons: list[str] = []
    checks: dict[str, dict[str, Any]] = {}

    def check(
        name: str,
        passed: bool,
        reason: str,
        *,
        observed: Any = None,
        expected: Any = None,
    ) -> None:
        checks[name] = {
            "passed": bool(passed),
            "observed": observed,
            "expected": expected,
        }
        if not passed:
            reasons.append(reason)

    background = record["background_cpu"]
    background_threshold = config["validity"][
        "maximum_background_busy_pct_each_assigned_cpu"
    ]
    for role, sample in background["assigned_cpus"].items():
        check(
            f"background_cpu.{role}",
            sample["busy_percent"] <= background_threshold,
            "background_cpu_over_20pct_assigned_core:"
            f"{role}:cpu{sample['cpu_id']}",
            observed=sample["busy_percent"],
            expected={"maximum_percent": background_threshold},
        )
    check(
        "cpu_assignment",
        record.get("cpu_assignment") == config["execution"]["cpu_affinity_ids"],
        "cpu_assignment_not_frozen",
        observed=record.get("cpu_assignment"),
        expected=config["execution"]["cpu_affinity_ids"],
    )
    for boundary in ("before", "after"):
        isolation = record.get(f"isolation_{boundary}", {})
        check(
            f"namespace_{boundary}",
            isolation.get("errors") == [],
            f"namespace_exact_state_failed_{boundary}",
            observed=isolation.get("errors"),
            expected=[],
        )
    check(
        "tc_live_all_snapshots",
        not record["tc_live_validation_errors"],
        "tc_configuration_not_exact_at_all_snapshots",
        observed=record["tc_live_validation_errors"],
        expected=[],
    )
    reasons.extend(
        f"tc_configuration:{item}" for item in record["tc_live_validation_errors"]
    )

    ready = record.get("process_ready", {})
    start_ns = record["traffic_start_monotonic_ns"]
    minimum_ready_lead_ns = int(
        round(profile["timing"]["minimum_all_process_ready_lead_s"] * 1e9)
    )
    ready_leads: dict[str, int | None] = {}
    for role in ("receiver", "benign_sender", "suspicious_sender"):
        ready_ns = ready.get(role, {}).get("monotonic_ns")
        ready_leads[role] = start_ns - ready_ns if isinstance(ready_ns, int) else None
    expected_ready = {
        "receiver": {
            "role": "receiver",
            "bind_ip": config["network"]["server_ip"],
            "port": config["network"]["receiver_port"],
            "cpu_affinity": [config["execution"]["cpu_affinity_ids"]["receiver"]],
        },
        "benign_sender": {
            "role": "sender",
            "traffic_class": "benign",
            "bind_ip": config["network"]["client_ip"],
            "source_port": config["network"]["benign_source_port"],
            "cpu_affinity": [config["execution"]["cpu_affinity_ids"]["benign_sender"]],
            "rtt_probe_rate_pps": trial["benign_rtt_probe_rate_pps"],
        },
        "suspicious_sender": {
            "role": "sender",
            "traffic_class": "suspicious",
            "bind_ip": config["network"]["client_ip"],
            "source_port": config["network"]["suspicious_source_port"],
            "cpu_affinity": [config["execution"]["cpu_affinity_ids"]["suspicious_sender"]],
            "rtt_probe_rate_pps": 0.0,
        },
    }
    ready_shape_ok = set(ready) == set(expected_ready)
    if ready_shape_ok:
        for role, expected_fields in expected_ready.items():
            ready_shape_ok = ready_shape_ok and ready[role].get("event") == "ready"
            ready_shape_ok = ready_shape_ok and all(
                ready[role].get(key) == value for key, value in expected_fields.items()
            )
    check(
        "ready_record_identity",
        ready_shape_ok,
        "process_ready_record_identity_mismatch",
        observed=ready,
        expected=expected_ready,
    )
    check(
        "all_processes_ready",
        all(
            isinstance(lead, int) and lead >= minimum_ready_lead_ns
            for lead in ready_leads.values()
        ),
        "all_process_ready_barrier_or_lead_failed",
        observed=ready_leads,
        expected={"minimum_each_ns": minimum_ready_lead_ns},
    )
    barrier = record.get("start_barrier", {})
    ready_times = [
        ready.get(role, {}).get("monotonic_ns")
        for role in ("receiver", "benign_sender", "suspicious_sender")
    ]
    selected_ns = barrier.get("start_selected_monotonic_ns")
    write_times = barrier.get("per_process_write_monotonic_ns", {})
    barrier_ok = (
        all(isinstance(value, int) for value in ready_times)
        and isinstance(selected_ns, int)
        and selected_ns >= max(ready_times)
        and barrier.get("selected_only_after_all_ready") is True
        and barrier.get("start_record")
        == {"event": "start", "start_monotonic_ns": start_ns}
        and set(write_times) == {"receiver", "benign_sender", "suspicious_sender"}
        and all(
            isinstance(value, int) and selected_ns <= value < start_ns
            for value in write_times.values()
        )
    )
    check(
        "post_readiness_start_selection",
        bool(barrier_ok),
        "shared_start_was_not_selected_and_broadcast_after_all_ready",
        observed=barrier,
        expected="select after all readiness records; broadcast before future start",
    )

    warmup_end_ns = start_ns + int(round(trial["warmup_s"] * 1e9))
    measurement_end_ns = warmup_end_ns + int(round(trial["measurement_s"] * 1e9))
    snapshot_lateness = {
        "measurement_start_ns": record["tc_snapshots"]["measurement_start"][
            "capture_started_monotonic_ns"
        ]
        - warmup_end_ns,
        "measurement_end_ns": record["tc_snapshots"]["measurement_end"][
            "capture_started_monotonic_ns"
        ]
        - measurement_end_ns,
    }
    maximum_snapshot_lateness = profile["validity"][
        "maximum_phase_snapshot_start_lateness_ns"
    ]
    check(
        "phase_snapshot_lateness",
        all(
            0 <= value <= maximum_snapshot_lateness
            for value in snapshot_lateness.values()
        ),
        "phase_snapshot_lateness_exceeds_frozen_gate",
        observed=snapshot_lateness,
        expected={"range_ns": [0, maximum_snapshot_lateness]},
    )

    for role in ("receiver", "benign_sender", "suspicious_sender"):
        process = record["processes"][role]
        check(
            f"process.{role}",
            process["returncode"] == 0
            and not process["final_record"].get("error")
            and process.get("stdout_non_json_line_count") == 0,
            f"{role}_process_failed",
            observed={
                "returncode": process["returncode"],
                "error": process["final_record"].get("error"),
                "stdout_non_json_line_count": process.get("stdout_non_json_line_count"),
            },
            expected={"returncode": 0, "error": None, "stdout_non_json_line_count": 0},
        )
    receiver = record["processes"]["receiver"]["final_record"]
    benign = record["processes"]["benign_sender"]["final_record"]
    suspicious = record["processes"]["suspicious_sender"]["final_record"]
    start_signal_receipts = {
        role: process_record.get("start_signal_received_monotonic_ns")
        for role, process_record in (
            ("receiver", receiver),
            ("benign_sender", benign),
            ("suspicious_sender", suspicious),
        )
    }
    check(
        "start_signal_receipts",
        all(
            isinstance(value, int)
            and ready[role]["monotonic_ns"] <= value < start_ns
            for role, value in start_signal_receipts.items()
        ),
        "process_start_signal_receipt_invalid",
        observed=start_signal_receipts,
        expected={"after_each_ready_and_before_start": True},
    )
    expected_boundaries = {
        "start_monotonic_ns": start_ns,
        "warmup_end_monotonic_ns": warmup_end_ns,
        "measurement_end_monotonic_ns": measurement_end_ns,
    }
    process_identity_errors: list[str] = []
    for role, final in (
        ("receiver", receiver),
        ("benign_sender", benign),
        ("suspicious_sender", suspicious),
    ):
        expected_role = "receiver" if role == "receiver" else "sender"
        if final.get("role") != expected_role or final.get("final") is not True:
            process_identity_errors.append(f"{role}:role_or_final")
        if any(final.get(key) != value for key, value in expected_boundaries.items()):
            process_identity_errors.append(f"{role}:phase_boundaries")
        if final.get("packet_size_bytes") != config["traffic"]["packet_payload_bytes"]:
            process_identity_errors.append(f"{role}:packet_size")
        if final.get("cpu_affinity") != [record["cpu_assignment"][role]]:
            process_identity_errors.append(f"{role}:cpu_affinity")
        if final.get("requested_socket_buffer_bytes") != config["traffic"][
            "socket_buffer_request_bytes"
        ]:
            process_identity_errors.append(f"{role}:socket_buffer_request")
        buffers = final.get("actual_socket_buffers", {})
        if not all(
            isinstance(buffers.get(key), int) and buffers[key] > 0
            for key in ("receive_bytes", "send_bytes")
        ):
            process_identity_errors.append(f"{role}:actual_socket_buffers")
    for label, final in (("benign", benign), ("suspicious", suspicious)):
        if (
            final.get("traffic_class") != label
            or final.get("seed") != trial["traffic_seed"]
            or final.get("target_rate_pps") != trial[f"{label}_target_pps"]
            or final.get("source_port")
            != config["network"][f"{label}_source_port"]
            or final.get("target_port") != config["network"]["receiver_port"]
            or final.get("tos")
            != config["service"][
                "fast_tos" if label == "benign" else "suspicious_tos"
            ]
        ):
            process_identity_errors.append(f"{label}_sender:frozen_schedule_identity")
    check(
        "process_final_identity",
        not process_identity_errors,
        "process_final_identity_or_boundary_mismatch",
        observed=sorted(process_identity_errors),
        expected=[],
    )
    check(
        "receiver_packet_format",
        receiver.get("malformed_packets") == 0
        and receiver.get("wrong_size_packets") == 0,
        "receiver_malformed_or_wrong_size_packets",
        observed={
            "malformed": receiver.get("malformed_packets"),
            "wrong_size": receiver.get("wrong_size_packets"),
        },
        expected={"malformed": 0, "wrong_size": 0},
    )
    arrival_counts = receiver.get("counts_by_arrival_window", {})
    arrival_counter_exact = set(arrival_counts) == {
        "before_start", "warmup", "measurement", "drain"
    }
    if arrival_counter_exact:
        for window in arrival_counts.values():
            for label in ("benign", "suspicious"):
                arrival_counter_exact = arrival_counter_exact and (
                    window.get(f"{label}_bytes")
                    == window.get(f"{label}_packets", -1)
                    * config["traffic"]["packet_payload_bytes"]
                )
    sender_phase_counts = receiver.get("counts_by_sender_phase", {})
    cohort_matrix = receiver.get("sender_phase_by_arrival_window", {})
    counter_keys = {
        "benign_packets", "benign_bytes", "suspicious_packets",
        "suspicious_bytes", "benign_rtt_probe_packets",
    }
    arrival_counter_exact = arrival_counter_exact and set(sender_phase_counts) == {
        "warmup", "measurement"
    } and set(cohort_matrix) == {"warmup", "measurement"}
    if arrival_counter_exact:
        for phase in ("warmup", "measurement"):
            arrival_counter_exact = arrival_counter_exact and (
                set(cohort_matrix[phase]) == set(arrival_counts)
                and set(sender_phase_counts[phase]) == counter_keys
            )
            if not arrival_counter_exact:
                break
            records_to_validate = [sender_phase_counts[phase], *cohort_matrix[phase].values()]
            for counter in records_to_validate:
                arrival_counter_exact = arrival_counter_exact and (
                    set(counter) == counter_keys
                    and all(isinstance(value, int) and value >= 0 for value in counter.values())
                    and counter["benign_bytes"]
                    == counter["benign_packets"]
                    * config["traffic"]["packet_payload_bytes"]
                    and counter["suspicious_bytes"]
                    == counter["suspicious_packets"]
                    * config["traffic"]["packet_payload_bytes"]
                    and counter["benign_rtt_probe_packets"] <= counter["benign_packets"]
                )
            phase_sum = {
                key: sum(cohort_matrix[phase][window].get(key, -1) for window in arrival_counts)
                for key in counter_keys
            }
            arrival_counter_exact = phase_sum == sender_phase_counts[phase]
        for window in arrival_counts:
            if not arrival_counter_exact:
                break
            window_sum = {
                key: sum(cohort_matrix[phase][window].get(key, -1) for phase in cohort_matrix)
                for key in counter_keys
            }
            arrival_counter_exact = window_sum == arrival_counts[window]
    check(
        "receiver_arrival_window_counters",
        arrival_counter_exact,
        "receiver_arrival_window_counters_invalid",
        observed=arrival_counts,
        expected="four exact windows with payload byte/packet identity",
    )

    maximum_missed_fraction = profile["validity"]["maximum_missed_schedule_fraction"]
    maximum_lateness = profile["validity"]["maximum_send_lateness_p99_ns"]
    sender_fidelity: dict[str, Any] = {}
    sender_lateness_samples: dict[str, dict[str, list[int]]] = {}
    for label, sender in (("benign", benign), ("suspicious", suspicious)):
        sender_fidelity[label] = {}
        sender_lateness_samples[label] = {}
        for phase in ("warmup", "measurement"):
            planned = sender.get("planned_packets", {}).get(phase)
            sent = sender.get("sent", {}).get(phase, {}).get("packets")
            missed = sender.get("missed_deadlines", {}).get(phase)
            send_errors = sender.get("send_errors_by_phase", {}).get(phase)
            lateness_p99 = sender.get("send_lateness_by_phase", {}).get(phase, {}).get("p99_ns")
            counters_are_ints = all(
                isinstance(value, int) and not isinstance(value, bool) and value >= 0
                for value in (planned, sent, missed, send_errors)
            )
            conserved = counters_are_ints and planned == sent + missed + send_errors
            missed_fraction = missed / planned if counters_are_ints and planned else 0.0
            lateness_ok = (sent == 0 and lateness_p99 is None) or (
                isinstance(lateness_p99, int)
                and not isinstance(lateness_p99, bool)
                and 0 <= lateness_p99 <= maximum_lateness
            )
            sample_error: str | None = None
            decoded_samples: list[int] | None = None
            try:
                decoded_samples = decode_lateness_samples(
                    sender.get("send_lateness_samples_by_phase", {}).get(phase),
                    expected_count=(
                        sent
                        if counters_are_ints and sent <= planned
                        else -1
                    ),
                )
            except (TypeError, ValueError, zlib.error) as error:
                sample_error = f"{type(error).__name__}: {error}"
            recomputed_phase_summary = (
                _lateness_summary(decoded_samples)
                if decoded_samples is not None
                else None
            )
            reported_phase_summary = sender.get("send_lateness_by_phase", {}).get(
                phase
            )
            sample_summary_ok = (
                sample_error is None
                and recomputed_phase_summary == reported_phase_summary
                and all(
                    isinstance(value, int) and not isinstance(value, bool) and value >= 0
                    for value in (decoded_samples or [])
                )
            )
            if decoded_samples is not None:
                sender_lateness_samples[label][phase] = decoded_samples
            sender_fidelity[label][phase] = {
                "planned": planned,
                "sent": sent,
                "missed": missed,
                "send_errors": send_errors,
                "missed_fraction": missed_fraction,
                "lateness_p99_ns": lateness_p99,
            }
            check(
                f"schedule_conservation.{label}.{phase}",
                bool(conserved),
                f"{label}_{phase}_schedule_counters_not_conserved",
                observed=sender_fidelity[label][phase],
                expected="planned=sent+missed+send_errors",
            )
            check(
                f"send_errors.{label}.{phase}",
                counters_are_ints and send_errors == 0,
                f"{label}_{phase}_send_errors_nonzero",
                observed=send_errors,
                expected=0,
            )
            check(
                f"missed_fraction.{label}.{phase}",
                counters_are_ints and missed_fraction <= maximum_missed_fraction,
                f"{label}_{phase}_missed_schedule_fraction_exceeded",
                observed=missed_fraction,
                expected={"maximum": maximum_missed_fraction},
            )
            check(
                f"lateness.{label}.{phase}",
                bool(lateness_ok),
                f"{label}_{phase}_send_lateness_p99_exceeded",
                observed=lateness_p99,
                expected={"maximum_ns": maximum_lateness},
            )
            check(
                f"lateness_samples.{label}.{phase}",
                bool(sample_summary_ok),
                f"{label}_{phase}_lateness_samples_or_summary_invalid",
                observed={
                    "decode_error": sample_error,
                    "recomputed": recomputed_phase_summary,
                    "reported": reported_phase_summary,
                },
                expected="lossless samples decode and exactly reproduce phase summary",
            )

        decoded_by_phase = sender_lateness_samples[label]
        complete_samples = set(decoded_by_phase) == {"warmup", "measurement"}
        all_samples = (
            decoded_by_phase.get("warmup", [])
            + decoded_by_phase.get("measurement", [])
        )
        recomputed_overall = _lateness_summary(all_samples) if complete_samples else None
        reported_overall = {
            "sample_count": sender.get("send_lateness_sample_count"),
            "mean_ns": sender.get("send_lateness_mean_ns"),
            "max_ns": sender.get("send_lateness_max_ns"),
            "p99_ns": sender.get("send_lateness_p99_ns"),
        }
        check(
            f"lateness_samples_overall.{label}",
            complete_samples and recomputed_overall == reported_overall,
            f"{label}_overall_lateness_samples_or_summary_invalid",
            observed={
                "recomputed": recomputed_overall,
                "reported": reported_overall,
            },
            expected="concatenated phase samples exactly reproduce overall summary",
        )

    probes = benign.get("rtt_probes", {})
    probe_received = probes.get("measurement_received")
    minimum_probes = profile["validity"]["minimum_measurement_rtt_probes_received"]
    probe_sent = probes.get("sent", {}).get("measurement")
    probe_unacked = probes.get("measurement_unacknowledged")
    probe_loss = probes.get("measurement_loss_packets")
    probe_metadata_ok = (
        benign.get("rtt_probe_policy") == "fixed_rate_flagged_subset_echo_only"
        and probes.get("target_rate_pps") == trial["benign_rtt_probe_rate_pps"]
        and isinstance(probes.get("selection_every_n_benign_packets"), int)
        and probes.get("selection_every_n_benign_packets") > 0
        and probes.get("sent", {}).get("warmup")
        == benign.get("sent", {}).get("warmup", {}).get("rtt_probe_packets")
        and probe_sent
        == benign.get("sent", {}).get("measurement", {}).get("rtt_probe_packets")
    )
    check(
        "rtt_probe_metadata",
        probe_metadata_ok,
        "rtt_probe_rate_selection_or_sent_metadata_invalid",
        observed=probes,
        expected={"target_rate_pps": trial["benign_rtt_probe_rate_pps"]},
    )
    probe_arithmetic_ok = all(
        isinstance(value, int)
        for value in (probe_received, probe_sent, probe_unacked, probe_loss)
    ) and probe_received + probe_unacked == probe_sent and probe_loss == probe_unacked
    check(
        "rtt_probe_minimum",
        isinstance(probe_received, int) and probe_received >= minimum_probes,
        "insufficient_delivered_measurement_rtt_probes",
        observed=probe_received,
        expected={"minimum": minimum_probes},
    )
    check(
        "rtt_probe_arithmetic",
        bool(probe_arithmetic_ok),
        "rtt_probe_sent_received_unacked_arithmetic_failed",
        observed={
            "sent": probe_sent,
            "received": probe_received,
            "unacked": probe_unacked,
            "loss": probe_loss,
        },
        expected="sent=received+unacked and loss=unacked",
    )
    rtt_samples = benign.get("measurement_rtt_ns", [])
    conditional_p99 = benign.get("measurement_rtt_p99_ns")
    expected_p99 = (
        sorted(rtt_samples)[max(0, math.ceil(0.99 * len(rtt_samples)) - 1)]
        if rtt_samples
        else None
    )
    check(
        "conditional_rtt_p99",
        conditional_p99 == expected_p99
        and probes.get("measurement_conditional_rtt_p99_ns") == expected_p99,
        "conditional_rtt_p99_not_exact",
        observed={
            "sender": conditional_p99,
            "probe_record": probes.get("measurement_conditional_rtt_p99_ns"),
        },
        expected=expected_p99,
    )
    suspicious_probe_evidence = suspicious.get("rtt_probes", {})
    check(
        "suspicious_has_no_rtt_probes",
        suspicious_probe_evidence
        == {
            "target_rate_pps": 0.0,
            "selection_every_n_benign_packets": None,
            "planned": {"warmup": 0, "measurement": 0},
            "sent": {"warmup": 0, "measurement": 0},
            "measurement_received": 0,
            "measurement_unacknowledged": 0,
            "measurement_loss_packets": 0,
            "measurement_loss_fraction": None,
            "measurement_conditional_rtt_p99_ns": None,
        },
        "suspicious_sender_emitted_or_reported_rtt_probes",
        observed=suspicious_probe_evidence,
        expected="all-zero/no-probe record",
    )

    total_receiver_probes = sum(
        window.get("benign_rtt_probe_packets", 0)
        for window in arrival_counts.values()
    )
    echo_errors = {
        "receiver_echo_failures": receiver.get("benign_echo_failures"),
        "receiver_attempts_minus_received_probes": receiver.get("benign_echo_attempts", -1)
        - total_receiver_probes,
        "sender_malformed": benign.get("echo_malformed"),
        "sender_wrong_class": benign.get("echo_wrong_class"),
        "sender_duplicates": benign.get("echo_duplicates"),
        "sender_nonprobe": benign.get("echo_nonprobe"),
    }
    check(
        "echo_instrumentation",
        all(value == 0 for value in echo_errors.values()),
        "echo_instrumentation_error",
        observed=echo_errors,
        expected="all zero",
    )

    socket_evidence: dict[str, Any] = {}
    for role, process_record in (
        ("receiver", receiver),
        ("benign_sender", benign),
        ("suspicious_sender", suspicious),
    ):
        snmp = process_record.get("udp_snmp_delta", {})
        observed = {
            "SO_RXQ_OVFL": process_record.get("socket_rxq_overflow_drops"),
            "InErrors": snmp.get("InErrors"),
            "RcvbufErrors": snmp.get("RcvbufErrors"),
        }
        socket_evidence[role] = observed
        check(
            f"socket_overflow.{role}",
            all(value == 0 for value in observed.values()),
            f"{role}_udp_socket_or_snmp_overflow",
            observed=observed,
            expected="all zero",
        )

    if trial["regime"] in {"borrowable_overload", "both_saturated"}:
        for label, sender in (("benign", benign), ("suspicious", suspicious)):
            planned = sender.get("planned_packets", {}).get("measurement", 0)
            sent = sender.get("sent", {}).get("measurement", {}).get("packets", 0)
            fraction = sent / planned if planned else 0.0
            check(
                f"overload_offered_fraction.{label}",
                fraction >= config["validity"]["minimum_overload_offered_fraction"],
                f"{label}_overload_offered_fraction_below_0.90",
                observed=fraction,
                expected={
                    "minimum": config["validity"]["minimum_overload_offered_fraction"]
                },
            )
    check(
        "counter_reconciliation",
        not record["counter_reconciliation_errors"],
        "counter_reconciliation_failed",
        observed=record["counter_reconciliation_errors"],
        expected=[],
    )
    reasons.extend(
        f"counter_reconciliation:{reason}"
        for reason in record["counter_reconciliation_errors"]
    )
    try:
        require_finite_tree(record)
    except (ValueError, TypeError) as error:
        reasons.append(f"nonfinite_or_unsupported_output:{error}")
    evidence = {
        "schema_version": "matched-scheduler-validity-evidence-1.0",
        "primary_service_window": "receiver_arrival_measurement",
        "checks": checks,
        "sender_fidelity": sender_fidelity,
        "probe_delivery": {
            "planned": probes.get("planned", {}).get("measurement"),
            "sent": probe_sent,
            "received": probe_received,
            "unacked": probe_unacked,
            "loss_packets": probe_loss,
            "loss_fraction": probes.get("measurement_loss_fraction"),
            "conditional_p99_ns": conditional_p99,
        },
        "socket_overflow": socket_evidence,
        "invalid_reasons": sorted(set(reasons)),
    }
    require_finite_tree(evidence)
    return not reasons, sorted(set(reasons)), evidence


def run_arm(
    config: dict[str, Any],
    profile: dict[str, Any],
    trial: dict[str, Any],
    server_pid: int,
    client_pid: int,
    cpu_assignment: dict[str, int],
    expected_anchor_identity: dict[str, Any],
) -> dict[str, Any]:
    started_utc = utc_now()
    started_ns = time.monotonic_ns()
    background = background_cpu_sample(
        profile["validity"]["background_sample_s"], cpu_assignment
    )
    isolation_before = validate_matched_namespace_state(
        config, server_pid, client_pid, expected_anchor_identity
    )
    spec = requested_tc_spec(
        config, trial["arm_id"], trial["reservation_id"]
    )
    apply_records = apply_tc(server_pid, client_pid, spec)
    tc_arm_start = tc_snapshot(server_pid, client_pid, spec["interface"])

    timing = profile["timing"]
    common = _traffic_common(config, trial)
    python = sys.executable
    receiver_inner = [
        python, str(TRAFFIC_PROGRAM), "receiver", *common,
        "--bind-ip", config["network"]["server_ip"],
        "--port", str(config["network"]["receiver_port"]),
        "--cpu-id", str(cpu_assignment["receiver"]),
    ]
    sender_common = [
        python, str(TRAFFIC_PROGRAM), "sender", *common,
        "--bind-ip", config["network"]["client_ip"],
        "--target-ip", config["network"]["server_ip"],
        "--target-port", str(config["network"]["receiver_port"]),
        "--seed", str(trial["traffic_seed"]),
        "--fast-tos", str(config["service"]["fast_tos"]),
        "--suspicious-tos", str(config["service"]["suspicious_tos"]),
        "--rtt-probe-rate-pps", str(trial["benign_rtt_probe_rate_pps"]),
    ]
    benign_inner = [
        *sender_common,
        "--source-port", str(config["network"]["benign_source_port"]),
        "--traffic-class", "benign",
        "--rate-pps", str(trial["benign_target_pps"]),
        "--cpu-id", str(cpu_assignment["benign_sender"]),
    ]
    suspicious_inner = [
        *sender_common,
        "--source-port", str(config["network"]["suspicious_source_port"]),
        "--traffic-class", "suspicious",
        "--rate-pps", str(trial["suspicious_target_pps"]),
        "--cpu-id", str(cpu_assignment["suspicious_sender"]),
    ]
    processes: list[subprocess.Popen[str]] = []
    process_records: dict[str, Any] = {}
    try:
        receiver_process = subprocess.Popen(
            nsenter_server(server_pid, receiver_inner),
            cwd=TESTBED_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        processes.append(receiver_process)
        receiver_ready = _wait_for_ready(
            receiver_process, timing["ready_timeout_s"], role="receiver"
        )
        benign_process = subprocess.Popen(
            nsenter_client(server_pid, client_pid, benign_inner),
            cwd=TESTBED_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        suspicious_process = subprocess.Popen(
            nsenter_client(server_pid, client_pid, suspicious_inner),
            cwd=TESTBED_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        processes.extend((benign_process, suspicious_process))
        benign_ready = _wait_for_ready(
            benign_process,
            timing["ready_timeout_s"],
            role="sender",
            traffic_class="benign",
        )
        suspicious_ready = _wait_for_ready(
            suspicious_process,
            timing["ready_timeout_s"],
            role="sender",
            traffic_class="suspicious",
        )
        process_launch_complete_ns = time.monotonic_ns()
        start_selected_ns = time.monotonic_ns()
        start_ns = start_selected_ns + int(
            round(timing["process_start_lead_s"] * 1e9)
        )
        start_record = {
            "event": "start",
            "start_monotonic_ns": start_ns,
        }
        start_line = json.dumps(start_record, sort_keys=True, separators=(",", ":")) + "\n"
        start_signal_write_ns: dict[str, int] = {}
        for role, process in (
            ("receiver", receiver_process),
            ("benign_sender", benign_process),
            ("suspicious_sender", suspicious_process),
        ):
            if process.stdin is None:
                raise RuntimeError(f"{role} start-barrier stdin pipe is absent")
            process.stdin.write(start_line)
            process.stdin.flush()
            start_signal_write_ns[role] = time.monotonic_ns()
        warmup_end_ns = start_ns + int(round(trial["warmup_s"] * 1e9))
        measurement_end_ns = warmup_end_ns + int(
            round(trial["measurement_s"] * 1e9)
        )
        drain_end_ns = measurement_end_ns + int(round(trial["drain_s"] * 1e9))
        _sleep_until(warmup_end_ns)
        tc_measurement_start = tc_snapshot(
            server_pid, client_pid, spec["interface"]
        )
        _sleep_until(measurement_end_ns)
        tc_measurement_end = tc_snapshot(
            server_pid, client_pid, spec["interface"]
        )
        _sleep_until(drain_end_ns)
        timeout_s = timing["process_timeout_slack_s"]
        process_records["receiver"] = _process_record(receiver_process, timeout_s)
        process_records["benign_sender"] = _process_record(
            benign_process, timeout_s
        )
        process_records["suspicious_sender"] = _process_record(
            suspicious_process, timeout_s
        )
    finally:
        for process in processes:
            _terminate(process)
    tc_arm_end = tc_snapshot(server_pid, client_pid, spec["interface"])
    isolation_after = validate_matched_namespace_state(
        config, server_pid, client_pid, expected_anchor_identity
    )
    tc_snapshots = {
        "arm_start": tc_arm_start,
        "measurement_start": tc_measurement_start,
        "measurement_end": tc_measurement_end,
        "arm_end": tc_arm_end,
    }
    tc_live_validation = {
        name: {"errors": validate_live_tc(snapshot, spec)}
        for name, snapshot in tc_snapshots.items()
    }
    tc_live_errors = sorted(
        {
            f"{name}:{error}"
            for name, validation in tc_live_validation.items()
            for error in validation["errors"]
        }
    )
    record: dict[str, Any] = {
        "schema_version": ARM_SCHEMA_VERSION,
        "study_id": config["study_id"],
        "profile": profile["name"],
        "evidentiary": profile["evidentiary"],
        "trial": trial,
        "started_utc": started_utc,
        "finished_utc": utc_now(),
        "arm_started_monotonic_ns": started_ns,
        "arm_finished_monotonic_ns": time.monotonic_ns(),
        "traffic_start_monotonic_ns": start_ns,
        "process_launch_complete_monotonic_ns": process_launch_complete_ns,
        "start_barrier": {
            "all_ready_monotonic_ns": process_launch_complete_ns,
            "start_selected_monotonic_ns": start_selected_ns,
            "start_record": start_record,
            "per_process_write_monotonic_ns": start_signal_write_ns,
            "selected_only_after_all_ready": start_selected_ns
            >= max(
                receiver_ready["monotonic_ns"],
                benign_ready["monotonic_ns"],
                suspicious_ready["monotonic_ns"],
            ),
        },
        "process_ready": {
            "receiver": receiver_ready,
            "benign_sender": benign_ready,
            "suspicious_sender": suspicious_ready,
        },
        "background_cpu": background,
        "cpu_assignment": cpu_assignment,
        "isolation_before": isolation_before,
        "isolation_after": isolation_after,
        "tc_requested_spec": spec,
        "tc_apply": apply_records,
        "tc_live_validation": tc_live_validation,
        "tc_live_validation_errors": tc_live_errors,
        "tc_snapshots": tc_snapshots,
        "processes": process_records,
    }
    record["counter_reconciliation"] = build_counter_reconciliation(
        config,
        process_records["receiver"]["final_record"],
        process_records["benign_sender"]["final_record"],
        process_records["suspicious_sender"]["final_record"],
        tc_arm_start,
        tc_measurement_start,
        tc_measurement_end,
        tc_arm_end,
    )
    record["counter_reconciliation_errors"] = record["counter_reconciliation"][
        "errors"
    ]
    valid, reasons, evidence = determine_validity(config, profile, trial, record)
    record["validity_evidence"] = evidence
    record["valid"] = valid
    record["invalid_reasons"] = reasons
    require_finite_tree(record)
    return record


def _source_hashes(
    config_path: Path, protocol_path: Path
) -> list[dict[str, Any]]:
    paths = [PROJECT_ROOT / relative for relative in FROZEN_SOURCE_RELATIVE_PATHS]
    if config_path.resolve() != paths[0].resolve() or protocol_path.resolve() != paths[1].resolve():
        raise ValueError("source inventory inputs are not canonical config/protocol paths")
    missing = [path for path in paths if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"frozen source file is missing: {missing}")
    records = [
        {
            "path": path.resolve().relative_to(PROJECT_ROOT.resolve()).as_posix(),
            "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size,
        }
        for path in paths
    ]
    if tuple(record["path"] for record in records) != FROZEN_SOURCE_RELATIVE_PATHS:
        raise ValueError("frozen source path inventory order/set changed")
    return records


def _copy_new(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as reader, destination.open("xb") as writer:
        shutil.copyfileobj(reader, writer)


def prepare_output(output_dir: Path) -> None:
    if output_dir.exists():
        if not output_dir.is_dir():
            raise ValueError(f"output path is not a directory: {output_dir}")
        if any(output_dir.iterdir()):
            raise FileExistsError(
                f"refusing stale/nonempty output directory: {output_dir}"
            )
    else:
        output_dir.mkdir(parents=True)


def validate_within_pair_fidelity(
    config: dict[str, Any],
    plan: dict[str, Any],
    arms_by_trial_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    count_tolerance = plan["profile"]["validity"][
        "maximum_within_pair_sent_count_relative_difference"
    ]
    lateness_tolerance = plan["profile"]["validity"][
        "maximum_within_pair_lateness_p99_difference_ns"
    ]
    for pair in plan["pairs"]:
        pair_id = pair["pair_id"]
        arms = {
            arm_id: arms_by_trial_id.get(f"{pair_id}_{arm_id}")
            for arm_id in ("B3", "B5")
        }
        errors: list[str] = []
        comparisons: dict[str, Any] = {}
        if any(arm is None for arm in arms.values()):
            errors.append("missing_arm_record")
        elif any("processes" not in arm for arm in arms.values() if arm is not None):
            errors.append("arm_has_no_process_evidence")
        else:
            assert arms["B3"] is not None and arms["B5"] is not None
            for label, role in (
                ("benign", "benign_sender"),
                ("suspicious", "suspicious_sender"),
            ):
                for phase in ("warmup", "measurement"):
                    values: dict[str, Any] = {}
                    for arm_id in ("B3", "B5"):
                        sender = arms[arm_id]["processes"][role]["final_record"]
                        sent_packets = sender.get("sent", {}).get(phase, {}).get(
                            "packets"
                        )
                        recomputed_p99: int | None = None
                        sample_sha256: str | None = None
                        if (
                            isinstance(sent_packets, int)
                            and not isinstance(sent_packets, bool)
                            and sent_packets >= 0
                        ):
                            try:
                                samples = decode_lateness_samples(
                                    sender.get(
                                        "send_lateness_samples_by_phase", {}
                                    ).get(phase),
                                    expected_count=sent_packets,
                                )
                            except (TypeError, ValueError) as error:
                                errors.append(
                                    f"{label}_{phase}_{arm_id}_lateness_samples:"
                                    f"{type(error).__name__}"
                                )
                            else:
                                recomputed_p99 = _lateness_summary(samples)["p99_ns"]
                                sample_sha256 = sender[
                                    "send_lateness_samples_by_phase"
                                ][phase]["uncompressed_sha256"]
                                if (
                                    sender.get("send_lateness_by_phase", {})
                                    .get(phase, {})
                                    .get("p99_ns")
                                    != recomputed_p99
                                ):
                                    errors.append(
                                        f"{label}_{phase}_{arm_id}_lateness_summary_mismatch"
                                    )
                        values[arm_id] = {
                            "sent_packets": sent_packets,
                            "lateness_p99_ns": recomputed_p99,
                            "lateness_samples_uncompressed_sha256": sample_sha256,
                        }
                    sent_values = [values[arm]["sent_packets"] for arm in ("B3", "B5")]
                    if not all(
                        isinstance(value, int)
                        and not isinstance(value, bool)
                        and value >= 0
                        for value in sent_values
                    ):
                        errors.append(f"{label}_{phase}_sent_counter_missing")
                        sent_relative_difference = None
                    else:
                        sent_relative_difference = abs(sent_values[1] - sent_values[0]) / max(
                            1, max(sent_values)
                        )
                        if sent_relative_difference > count_tolerance:
                            errors.append(f"{label}_{phase}_sent_count_difference")
                    lateness_values = [
                        values[arm]["lateness_p99_ns"] for arm in ("B3", "B5")
                    ]
                    if all(value is None for value in lateness_values):
                        lateness_difference = 0
                    elif all(
                        isinstance(value, int) and not isinstance(value, bool)
                        for value in lateness_values
                    ):
                        lateness_difference = abs(lateness_values[1] - lateness_values[0])
                        if lateness_difference > lateness_tolerance:
                            errors.append(f"{label}_{phase}_lateness_difference")
                    else:
                        lateness_difference = None
                        errors.append(f"{label}_{phase}_lateness_counter_missing")
                    comparisons[f"{label}.{phase}"] = {
                        "arms": values,
                        "sent_count_relative_difference": sent_relative_difference,
                        "lateness_p99_difference_ns": lateness_difference,
                    }
        results.append(
            {
                "pair_id": pair_id,
                "count_relative_difference_maximum": count_tolerance,
                "lateness_p99_difference_ns_maximum": lateness_tolerance,
                "comparisons": comparisons,
                "errors": sorted(set(errors)),
                "passed": not errors,
            }
        )
    return results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=PROJECT_ROOT / "configs" / "matched_scheduler.json",
    )
    parser.add_argument(
        "--profile", choices=("authoritative", "smoke"), default="authoritative"
    )
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--manage-namespaces", action="store_true")
    parser.add_argument("--server-pid", type=int)
    parser.add_argument("--client-pid", type=int)
    parser.add_argument("--plan-only", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config_path = args.config.resolve()
    config = load_config(config_path)
    canonical_config_path = (PROJECT_ROOT / "configs" / "matched_scheduler.json").resolve()
    if args.profile == "authoritative" and config_path != canonical_config_path:
        raise ValueError(
            f"authoritative execution requires canonical config path {canonical_config_path}"
        )
    assert_only_frozen_tc_difference(config)
    plan = build_execution_plan(config, args.profile)
    if args.plan_only:
        print(json.dumps(plan, sort_keys=True, indent=2, allow_nan=False))
        return
    if args.output_dir is None:
        raise ValueError("--output-dir is required unless --plan-only is used")
    output_dir = args.output_dir.resolve()
    if args.profile == "authoritative":
        expected = (
            PROJECT_ROOT / config["execution"]["authoritative_output_dir"]
        ).resolve()
        if output_dir != expected:
            raise ValueError(f"authoritative output must be exactly {expected}")
        if not args.manage_namespaces:
            raise ValueError(
                "authoritative execution requires --manage-namespaces"
            )
    if args.manage_namespaces and (
        args.server_pid is not None or args.client_pid is not None
    ):
        raise ValueError(
            "managed namespaces and explicit PIDs are mutually exclusive"
        )
    if not args.manage_namespaces and (
        args.server_pid is None or args.client_pid is None
    ):
        raise ValueError("provide both anchor PIDs or use --manage-namespaces")

    prepare_output(output_dir)
    _copy_new(config_path, output_dir / "config.json")
    protocol_path = PROJECT_ROOT / config["protocol_file"]
    _copy_new(protocol_path, output_dir / "protocol.md")
    write_new_json(output_dir / "execution_plan.json", plan)
    source_hashes = _source_hashes(config_path, protocol_path)
    write_new_json(output_dir / "source_hashes.json", source_hashes)

    setup_record: dict[str, Any] = {
        "managed": args.manage_namespaces,
        "success": not args.manage_namespaces,
    }
    teardown_record: dict[str, Any] = {
        "managed": args.manage_namespaces,
        "success": not args.manage_namespaces,
    }
    server_pid = args.server_pid
    client_pid = args.client_pid
    campaign_error: str | None = None
    raw_entries: list[dict[str, Any]] = []
    arms_by_trial_id: dict[str, dict[str, Any]] = {}
    started_utc = utc_now()
    try:
        if args.manage_namespaces:
            setup = run_command([ "bash", str(SETUP_SCRIPT)], timeout=30)
            setup_record = {
                "managed": True,
                "success": "MATCHED_SCHEDULER_SETUP_OK" in setup.stdout,
                "returncode": setup.returncode,
                "stdout": setup.stdout,
                "stderr": setup.stderr,
            }
            server_pid = int((RUN_DIR / "server_anchor.pid").read_text().strip())
            client_pid = int((RUN_DIR / "client_anchor.pid").read_text().strip())
        assert server_pid is not None and client_pid is not None
        expected_anchor_identity = capture_anchor_identity(server_pid, client_pid)
        if args.manage_namespaces:
            require_managed_identity_files(expected_anchor_identity)
        setup_record["anchor_identity"] = expected_anchor_identity
        environment = redact_private_strings(system_metadata(config))
        write_new_json(output_dir / "environment.json", environment)
        environment_file_sha256 = file_sha256(output_dir / "environment.json")
        arm_provenance = {
            "config_file": {
                "path": "config.json",
                "sha256": file_sha256(output_dir / "config.json"),
            },
            "config_object_sha256": object_sha256(config),
            "protocol_file": {
                "path": "protocol.md",
                "sha256": file_sha256(output_dir / "protocol.md"),
            },
            "execution_plan_file": {
                "path": "execution_plan.json",
                "sha256": file_sha256(output_dir / "execution_plan.json"),
                "plan_payload_sha256": plan["plan_sha256"],
            },
            "source_hashes_file": {
                "path": "source_hashes.json",
                "sha256": file_sha256(output_dir / "source_hashes.json"),
                "payload_sha256": object_sha256(source_hashes),
            },
            "environment_file": {
                "path": "environment.json",
                "sha256": environment_file_sha256,
            },
        }
        cpu_assignment = environment["resolved_process_cpu_affinity"]
        raw_dir = output_dir / "raw"
        raw_dir.mkdir()
        profile = plan["profile"]
        for ordinal, trial in enumerate(plan["trials"], start=1):
            print(
                f"[{ordinal}/{len(plan['trials'])}] {trial['trial_id']}",
                file=sys.stderr,
                flush=True,
            )
            raw_path = raw_dir / f"{trial['trial_id']}.json"
            try:
                arm = run_arm(
                    config,
                    profile,
                    trial,
                    server_pid,
                    client_pid,
                    cpu_assignment,
                    expected_anchor_identity,
                )
            except Exception as error:
                arm = {
                    "schema_version": ARM_SCHEMA_VERSION,
                    "study_id": config["study_id"],
                    "profile": args.profile,
                    "evidentiary": profile["evidentiary"],
                    "trial": trial,
                    "started_utc": utc_now(),
                    "finished_utc": utc_now(),
                    "valid": False,
                    "invalid_reasons": [
                        f"runner_exception:{type(error).__name__}:{error}"
                    ],
                }
            arm = redact_private_strings(arm)
            arm["provenance"] = arm_provenance
            arms_by_trial_id[trial["trial_id"]] = arm
            write_new_json(raw_path, arm)
            raw_entries.append(
                {
                    "trial_id": trial["trial_id"],
                    "path": raw_path.relative_to(output_dir).as_posix(),
                    "size_bytes": raw_path.stat().st_size,
                    "sha256": file_sha256(raw_path),
                    "valid": bool(arm.get("valid", False)),
                    "invalid_reasons": arm.get("invalid_reasons", []),
                }
            )
            if profile["timing"]["cooldown_between_arms_s"] > 0:
                time.sleep(profile["timing"]["cooldown_between_arms_s"])
    except Exception as error:
        campaign_error = redact_private_strings(
            f"{type(error).__name__}: {error}"
        )
    finally:
        if args.manage_namespaces and setup_record.get("success"):
            try:
                teardown = run_command(
                    ["bash", str(TEARDOWN_SCRIPT)],
                    timeout=30,
                    check=False,
                )
                teardown_record = {
                    "managed": True,
                    "success": (
                        teardown.returncode == 0
                        and "MATCHED_SCHEDULER_TEARDOWN_OK" in teardown.stdout
                    ),
                    "returncode": teardown.returncode,
                    "stdout": teardown.stdout,
                    "stderr": teardown.stderr,
                }
            except Exception as teardown_error:
                teardown_record = {
                    "managed": True,
                    "success": False,
                    "error": (
                        f"{type(teardown_error).__name__}: {teardown_error}"
                    ),
                }

    environment_path = output_dir / "environment.json"
    if not environment_path.exists():
        write_new_json(
            environment_path,
            {
                "captured_utc": utc_now(),
                "complete": False,
                "campaign_error": campaign_error,
                "frozen_cpu_assignment": config["execution"]["cpu_affinity_ids"],
            },
        )
    setup_record = redact_private_strings(setup_record)
    teardown_record = redact_private_strings(teardown_record)
    write_new_json(output_dir / "setup.json", setup_record)
    write_new_json(output_dir / "teardown.json", teardown_record)
    privacy_violations = persisted_privacy_violations(output_dir)
    privacy_scan = {
        "forbidden_identifier_classes": [
            "project_root", "account_home", "hostname"
        ],
        "violations": privacy_violations,
        "passed": not privacy_violations,
    }
    if privacy_violations:
        privacy_error = "persisted_privacy_scan_failed:" + ",".join(
            privacy_violations
        )
        campaign_error = (
            f"{campaign_error}; {privacy_error}"
            if campaign_error
            else privacy_error
        )
    pair_fidelity = validate_within_pair_fidelity(config, plan, arms_by_trial_id)
    pair_fidelity_error_count = sum(not item["passed"] for item in pair_fidelity)
    campaign_manifest = {
        "schema_version": CAMPAIGN_SCHEMA_VERSION,
        "study_id": config["study_id"],
        "profile": args.profile,
        "evidentiary": plan["profile"]["evidentiary"],
        "started_utc": started_utc,
        "finished_utc": utc_now(),
        "config_file_sha256": file_sha256(output_dir / "config.json"),
        "config_object_sha256": object_sha256(config),
        "protocol_sha256": file_sha256(output_dir / "protocol.md"),
        "plan_sha256": plan["plan_sha256"],
        "source_hashes_sha256": object_sha256(source_hashes),
        "environment_file_sha256": file_sha256(output_dir / "environment.json"),
        "setup_success": bool(setup_record.get("success")),
        "teardown_success": bool(teardown_record.get("success")),
        "campaign_error": campaign_error,
        "privacy_scan": privacy_scan,
        "planned_arm_count": len(plan["trials"]),
        "recorded_arm_count": len(raw_entries),
        "valid_arm_count": sum(entry["valid"] for entry in raw_entries),
        "invalid_arm_count": sum(not entry["valid"] for entry in raw_entries),
        "pair_fidelity": pair_fidelity,
        "pair_fidelity_error_count": pair_fidelity_error_count,
        "raw_files": raw_entries,
    }
    campaign_manifest["campaign_manifest_payload_sha256"] = object_sha256(
        campaign_manifest
    )
    write_new_json(output_dir / "campaign_manifest.json", campaign_manifest)
    write_new_json(
        output_dir / "campaign_inventory.json",
        make_tree_manifest(
            output_dir,
            excluded=[output_dir / "campaign_inventory.json"],
        ),
    )
    authoritative_invalid = args.profile == "authoritative" and (
        campaign_manifest["invalid_arm_count"] != 0
        or pair_fidelity_error_count != 0
        or campaign_manifest["recorded_arm_count"]
        != campaign_manifest["planned_arm_count"]
    )
    if campaign_error or not teardown_record.get("success") or authoritative_invalid:
        raise SystemExit(
            "campaign did not pass mechanical execution gates: "
            f"error={campaign_error!r}, "
            f"teardown_success={teardown_record.get('success')}, "
            f"authoritative_invalid={authoritative_invalid}"
        )
    print(f"campaign complete; immutable raw records: {output_dir}")


if __name__ == "__main__":
    main()
