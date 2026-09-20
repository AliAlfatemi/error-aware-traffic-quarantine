#!/usr/bin/env python3
"""Deterministic paired analysis for the frozen matched scheduler study."""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import hashlib
import io
import json
import math
import os
import random
import shutil
import statistics
import struct
import sys
import tempfile
import zlib
from fractions import Fraction
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "testbed"))

from matched_scheduler_lib import (  # noqa: E402
    ARM_IDS,
    ARM_SCHEMA_VERSION,
    CAMPAIGN_SCHEMA_VERSION,
    FINAL_MANIFEST_SCHEMA_VERSION,
    FROZEN_SOURCE_RELATIVE_PATHS,
    PROJECT_ROOT as LIB_PROJECT_ROOT,
    assert_only_frozen_tc_difference,
    build_execution_plan,
    effective_profile,
    file_sha256,
    load_config,
    make_tree_manifest,
    object_sha256,
    read_json,
    requested_tc_spec,
    require_finite_tree,
    tc_command_vectors,
    verify_manifest_files,
    write_new_json,
)


ANALYSIS_SCHEMA_VERSION = "matched-scheduler-analysis-1.0"
ANALYSIS_MANIFEST_SCHEMA_VERSION = "matched-scheduler-analysis-manifest-1.0"
ENDPOINTS = (
    "benign_goodput_Bps",
    "benign_rtt_p99_ms",
    "suspicious_service_Bps",
)
TC_SNAPSHOT_NAMES = (
    "arm_start",
    "measurement_start",
    "measurement_end",
    "arm_end",
)
LATENESS_SAMPLE_ENCODING = "zlib_base64_uint64_le_v1"


def nearest_rank(values: list[int], probability: float) -> int:
    if not values:
        raise ValueError("nearest-rank percentile requires at least one value")
    rank = max(1, math.ceil(probability * len(values)))
    return sorted(values)[rank - 1]


def percentile_interval(
    values: list[float],
    *,
    replicates: int,
    seed: int,
    confidence_level: float,
) -> tuple[float, float]:
    if not values:
        raise ValueError("bootstrap requires nonempty paired effects")
    rng = random.Random(seed)
    n = len(values)
    estimates = []
    for _ in range(replicates):
        estimates.append(sum(values[rng.randrange(n)] for _ in range(n)) / n)
    estimates.sort()
    tail = (1.0 - confidence_level) / 2.0
    lower_index = math.floor(tail * (replicates - 1))
    upper_index = math.ceil((1.0 - tail) * (replicates - 1))
    return estimates[lower_index], estimates[upper_index]


def exact_two_sided_sign_test(values: list[float]) -> dict[str, Any]:
    positive = sum(value > 0 for value in values)
    negative = sum(value < 0 for value in values)
    zeros = len(values) - positive - negative
    n = positive + negative
    if n == 0:
        return {
            "positive": positive,
            "negative": negative,
            "zeros_excluded": zeros,
            "n_nonzero": 0,
            "p_value": 1.0,
        }
    tail_count = sum(math.comb(n, index) for index in range(min(positive, negative) + 1))
    p_value = min(1.0, 2.0 * tail_count / (2**n))
    return {
        "positive": positive,
        "negative": negative,
        "zeros_excluded": zeros,
        "n_nonzero": n,
        "p_value": p_value,
    }


def holm_adjust(p_values: dict[str, float], alpha: float) -> dict[str, dict[str, Any]]:
    ordered = sorted(p_values.items(), key=lambda item: (item[1], item[0]))
    adjusted: dict[str, dict[str, Any]] = {}
    running_max = 0.0
    count = len(ordered)
    for rank, (endpoint, raw_p) in enumerate(ordered, start=1):
        multiplier = count - rank + 1
        running_max = max(running_max, min(1.0, raw_p * multiplier))
        adjusted[endpoint] = {
            "holm_rank": rank,
            "raw_p_value": raw_p,
            "holm_adjusted_p_value": running_max,
            "reject_at_alpha": running_max <= alpha,
        }
    return adjusted


def derive_endpoints(arm: dict[str, Any]) -> dict[str, float]:
    trial = arm["trial"]
    duration = float(trial["measurement_s"])
    if duration <= 0:
        raise ValueError("measurement duration must be positive")
    receiver = arm["processes"]["receiver"]["final_record"]
    benign = arm["processes"]["benign_sender"]["final_record"]
    # Primary service is assigned strictly by receiver arrival time.  The
    # compatibility branch keeps the small pure-function unit fixture useful;
    # completed-tree verification separately rejects raw records that lack the
    # arrival-window matrix.
    if "counts_by_arrival_window" in receiver:
        counts = receiver["counts_by_arrival_window"]["measurement"]
    else:
        counts = receiver["counts"]["measurement"]
    rtt_samples = benign["measurement_rtt_ns"]
    if not rtt_samples:
        raise ValueError("valid arm has no RTT samples")
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in rtt_samples):
        raise ValueError("RTT sample list contains an invalid value")
    recomputed_p99 = nearest_rank(rtt_samples, 0.99)
    if benign.get("measurement_rtt_p99_ns") != recomputed_p99:
        raise ValueError("sender RTT p99 does not match retained raw samples")
    endpoints = {
        "benign_goodput_Bps": counts["benign_bytes"] / duration,
        "benign_rtt_p99_ms": recomputed_p99 / 1_000_000.0,
        "suspicious_service_Bps": counts["suspicious_bytes"] / duration,
    }
    require_finite_tree(endpoints)
    return endpoints


def offered_fraction(arm: dict[str, Any], label: str) -> float | None:
    sender = arm["processes"][f"{label}_sender"]["final_record"]
    planned = sender["planned_packets"]["measurement"]
    sent = sender["sent"]["measurement"]["packets"]
    return sent / planned if planned else None


def _counter(snapshot: dict[str, Any], name: str) -> int | None:
    qdiscs = snapshot["commands"]["qdisc"]["records"]
    root = next((record for record in qdiscs if record.get("handle") == "1:"), None)
    if root is None:
        return None
    if _nonnegative_int(root.get(name)):
        return root[name]
    stats = root.get("stats", {})
    if _nonnegative_int(stats.get(name)):
        return stats[name]
    stats2 = root.get("stats2", {})
    if name == "drops":
        value = stats2.get("queue", {}).get("drops")
    else:
        value = stats2.get("basic", {}).get(name)
    return value if _nonnegative_int(value) else None


def measurement_drop_delta(arm: dict[str, Any]) -> int | None:
    before = _counter(arm["tc_snapshots"]["measurement_start"], "drops")
    after = _counter(arm["tc_snapshots"]["measurement_end"], "drops")
    if before is None or after is None or after < before:
        return None
    return after - before


def measurement_qdisc_accounting(arm: dict[str, Any]) -> dict[str, float | int] | None:
    start_snapshot = arm["tc_snapshots"]["measurement_start"]
    end_snapshot = arm["tc_snapshots"]["measurement_end"]
    before = _counter(start_snapshot, "bytes")
    after = _counter(end_snapshot, "bytes")
    start_ns = start_snapshot["capture_finished_monotonic_ns"]
    end_ns = end_snapshot["capture_started_monotonic_ns"]
    if before is None or after is None or after < before or end_ns <= start_ns:
        return None
    interval_s = (end_ns - start_ns) / 1e9
    return {
        "bytes": after - before,
        "interval_s": interval_s,
        "Bps": (after - before) / interval_s,
    }


def _rate_Bps(value: Any) -> int:
    """Parse the machine-readable rate forms emitted by supported tc JSON."""

    if isinstance(value, bool):
        raise ValueError("boolean is not a tc rate")
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        converted = float(value)
    elif isinstance(value, str):
        compact = value.strip().replace(" ", "")
        units = {
            "Bps": 1.0,
            "Kbit": 1_000.0 / 8.0,
            "Mbit": 1_000_000.0 / 8.0,
            "Gbit": 1_000_000_000.0 / 8.0,
            "bit": 1.0 / 8.0,
        }
        converted = math.nan
        for suffix, multiplier in units.items():
            if compact.endswith(suffix):
                converted = float(compact[: -len(suffix)]) * multiplier
                break
    else:
        converted = math.nan
    if not math.isfinite(converted) or converted < 0 or not converted.is_integer():
        raise ValueError(f"invalid/non-integral tc byte rate: {value!r}")
    return int(converted)


def _integer(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} is boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            pass
    raise ValueError(f"{label} is not an integer: {value!r}")


def normalize_live_tc(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Reduce a raw tc snapshot to its complete static scheduler semantics.

    Dynamic packet/token statistics and capture timestamps are deliberately
    omitted.  Counts, identities, parentage, rates, ceilings, buffers,
    quantums, priorities, link layer, and the exact classifier matches remain.
    """

    commands = snapshot.get("commands")
    if not isinstance(commands, dict) or set(commands) != {"qdisc", "class", "filter"}:
        raise ValueError("tc snapshot must contain exactly qdisc/class/filter commands")
    records_by_category: dict[str, list[dict[str, Any]]] = {}
    for category in ("qdisc", "class", "filter"):
        command = commands[category]
        records = command.get("records") if isinstance(command, dict) else None
        expected_argv_prefix = ["tc", "-s", "-d", "-j", category, "show", "dev"]
        argv = command.get("argv") if isinstance(command, dict) else None
        if (
            not isinstance(argv, list)
            or argv[:7] != expected_argv_prefix
            or len(argv) != 8
            or not isinstance(argv[7], str)
        ):
            raise ValueError(f"tc {category} snapshot argv is not exact")
        if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
            raise ValueError(f"tc {category} records are not a JSON-object list")
        records_by_category[category] = records

    qdiscs = []
    for raw in records_by_category["qdisc"]:
        options = raw.get("options", {})
        if not isinstance(options, dict):
            raise ValueError("tc qdisc options are not an object")
        entry: dict[str, Any] = {
            "kind": raw.get("kind"),
            "handle": raw.get("handle"),
            "parent": raw.get("parent"),
            "root": raw.get("root") is True,
        }
        if raw.get("kind") == "htb":
            entry["default_minor"] = _integer(options.get("default"), "htb default")
            entry["r2q"] = _integer(options.get("r2q"), "htb r2q")
            entry["direct_qlen_packets"] = _integer(
                options.get("direct_qlen"), "htb direct_qlen"
            )
        elif raw.get("kind") == "bfifo":
            entry["limit_bytes"] = _integer(options.get("limit"), "bfifo limit")
        else:
            entry["options"] = options
        qdiscs.append(entry)

    classes = []
    for raw in records_by_category["class"]:
        options = raw.get("options", {})
        if not isinstance(options, dict):
            raise ValueError("tc class options are not an object")
        merged = {**raw, **options}
        classid = raw.get("classid", raw.get("handle"))
        entry = {
            "kind": raw.get("kind", raw.get("class")),
            "classid": classid,
            "parent": raw.get("parent"),
            "root": raw.get("root") is True,
            "rate_Bps": _rate_Bps(merged.get("rate")),
            "ceil_Bps": _rate_Bps(merged.get("ceil")),
            "burst_bytes": _integer(merged.get("burst"), f"{classid} burst"),
            "cburst_bytes": _integer(merged.get("cburst"), f"{classid} cburst"),
            "quantum_bytes": (
                None
                if merged.get("quantum") is None
                else _integer(merged.get("quantum"), f"{classid} quantum")
            ),
            "prio": (
                None
                if merged.get("prio") is None
                else _integer(merged.get("prio"), f"{classid} prio")
            ),
            "linklayer": merged.get("linklayer", "ethernet"),
        }
        classes.append(entry)

    raw_filters = records_by_category["filter"]
    if len(raw_filters) != 6:
        raise ValueError(f"tc filter topology has {len(raw_filters)} records, expected 6")
    filters = []
    for pref, expected_flowid in ((1, "1:10"), (2, "1:20")):
        same_pref = [item for item in raw_filters if item.get("pref") == pref]
        if len(same_pref) != 3:
            raise ValueError(f"tc u32 preference {pref} does not have three records")
        if any(
            item.get("kind") != "u32"
            or item.get("protocol") != "ip"
            or item.get("parent") != "1:"
            or item.get("chain") != 0
            for item in same_pref
        ):
            raise ValueError(f"tc u32 preference {pref} metadata mismatch")
        headers = [item for item in same_pref if not item.get("options")]
        tables = [
            item
            for item in same_pref
            if item.get("options", {}).get("ht_divisor") == 1
        ]
        rules = [
            item
            for item in same_pref
            if item.get("options", {}).get("flowid") == expected_flowid
        ]
        if len(headers) != 1 or len(tables) != 1 or len(rules) != 1:
            raise ValueError(f"tc u32 preference {pref} header/table/rule topology mismatch")
        table_options = tables[0].get("options", {})
        rule, rule_options = rules[0], rules[0].get("options", {})
        match = rule_options.get("match")
        if not isinstance(match, dict):
            raise ValueError(f"tc u32 preference {pref} rule has no match object")
        filters.append(
            {
                "kind": "u32",
                "parent": "1:",
                "protocol": "ip",
                "pref": pref,
                "chain": 0,
                "header_options_absent": True,
                "table": {
                    "fh": table_options.get("fh"),
                    "ht_divisor": table_options.get("ht_divisor"),
                },
                "rule": {
                    "fh": rule_options.get("fh", rule.get("fh")),
                    "bkt": rule_options.get("bkt", rule.get("bkt")),
                    "key_ht": rule_options.get("key_ht", rule.get("key_ht")),
                    "order": rule_options.get("order", rule.get("order")),
                    "flowid": expected_flowid,
                    "match": {
                        "value": str(match.get("value")),
                        "mask": str(match.get("mask")),
                        "off": match.get("off"),
                    },
                },
            }
        )
    normalized = {
        "qdiscs": sorted(qdiscs, key=lambda item: (str(item["handle"]), str(item["parent"]))),
        "classes": sorted(classes, key=lambda item: str(item["classid"])),
        "filters": sorted(filters, key=lambda item: item["pref"]),
    }
    require_finite_tree(normalized)
    return normalized


def _expected_normalized_tc(spec: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    """Construct the exact expected normalized form, preserving tc's omissions."""

    expected = {
        "qdiscs": [
            {
                "kind": "htb",
                "handle": "1:",
                "parent": None,
                "root": True,
                # tc class-id components are hexadecimal even when the command
                # token has no 0x prefix (``default 20`` -> JSON ``0x20``).
                "default_minor": int(
                    str(spec["root"]["default_class_minor"]), 16
                ),
                "r2q": spec["root"]["r2q"],
                "direct_qlen_packets": spec["root"]["direct_qlen_packets"],
            },
            {
                "kind": "bfifo",
                "handle": spec["classes"]["fast"]["bfifo_handle"],
                "parent": spec["classes"]["fast"]["classid"],
                "root": False,
                "limit_bytes": spec["classes"]["fast"]["bfifo_limit_bytes"],
            },
            {
                "kind": "bfifo",
                "handle": spec["classes"]["suspicious"]["bfifo_handle"],
                "parent": spec["classes"]["suspicious"]["classid"],
                "root": False,
                "limit_bytes": spec["classes"]["suspicious"]["bfifo_limit_bytes"],
            },
        ],
        "classes": [],
        "filters": [],
    }
    observed_classes = {item["classid"]: item for item in observed["classes"]}
    class_specs = {
        "1:1": spec["root"],
        spec["classes"]["fast"]["classid"]: spec["classes"]["fast"],
        spec["classes"]["suspicious"]["classid"]: spec["classes"]["suspicious"],
    }
    for classid, values in class_specs.items():
        sample = observed_classes.get(classid, {})
        expected["classes"].append(
            {
                "kind": "htb",
                "classid": classid,
                "parent": None if classid == "1:1" and sample.get("root") else values.get("parent", "1:"),
                "root": classid == "1:1" and sample.get("root") is True,
                "rate_Bps": values["rate_Bps"],
                "ceil_Bps": values["ceil_Bps"],
                "burst_bytes": values["burst_bytes"],
                "cburst_bytes": values["cburst_bytes"],
                "quantum_bytes": (
                    None
                    if classid == "1:1" and sample.get("quantum_bytes") is None
                    else values["quantum_bytes"]
                ),
                "prio": (
                    None
                    if classid == "1:1" and sample.get("prio") is None
                    else values["priority"]
                ),
                "linklayer": values["linklayer"],
            }
        )
    # Supported iproute2 emits protocol/pref/parent at the outer level; retain
    # and exact-compare each field along with the u32 match and flow identity.
    for pref, flowid, tos, table in (
        (1, "1:10", spec["classes"]["fast"]["tos"], "800"),
        (2, "1:20", spec["classes"]["suspicious"]["tos"], "801"),
    ):
        expected["filters"].append(
            {
                "kind": "u32",
                "parent": "1:",
                "protocol": "ip",
                "pref": pref,
                "chain": 0,
                "header_options_absent": True,
                "table": {"fh": f"{table}:", "ht_divisor": 1},
                "rule": {
                    "fh": f"{table}::800",
                    "bkt": "0",
                    "key_ht": table,
                    "order": 2048,
                    "flowid": flowid,
                    "match": {
                        "value": f"{tos:02x}0000" if tos else "0",
                        "mask": "ff0000",
                        "off": 0,
                    },
                },
            }
        )
    for category in expected:
        key = "handle" if category == "qdiscs" else "classid" if category == "classes" else "pref"
        expected[category].sort(key=lambda item: str(item[key]))
    return expected


def validate_normalized_live_tc(snapshot: dict[str, Any], spec: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    try:
        observed = normalize_live_tc(snapshot)
        expected = _expected_normalized_tc(spec, observed)
    except (KeyError, TypeError, ValueError) as error:
        return {}, [f"unparseable tc snapshot: {error}"]
    errors = []
    if any(
        snapshot["commands"][category]["argv"][-1] != spec["interface"]
        for category in ("qdisc", "class", "filter")
    ):
        errors.append("tc snapshot command interface differs from requested interface")
    if observed != expected:
        errors.append("normalized live tc state differs from requested static specification")
    return observed, errors


def _flatten_tree(value: Any, prefix: str = "") -> dict[str, Any]:
    if not isinstance(value, dict):
        return {prefix: value}
    result: dict[str, Any] = {}
    for key, child in value.items():
        child_path = f"{prefix}.{key}" if prefix else key
        result.update(_flatten_tree(child, child_path))
    return result


def normalized_tc_pair_differences(left: dict[str, Any], right: dict[str, Any]) -> set[str]:
    """Return static normalized differences using class identities, not list indices."""

    def keyed(value: dict[str, Any]) -> dict[str, Any]:
        return {
            "qdiscs": {item["handle"]: item for item in value["qdiscs"]},
            "classes": {item["classid"]: item for item in value["classes"]},
            "filters": {
                f"{item['rule']['flowid']}@{item['pref']}": item
                for item in value["filters"]
            },
        }

    left_flat, right_flat = _flatten_tree(keyed(left)), _flatten_tree(keyed(right))
    return {
        key
        for key in set(left_flat) | set(right_flat)
        if left_flat.get(key) != right_flat.get(key)
    }


def _without_arm_fields(trial: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in trial.items()
        if key
        not in {
            "arm_id",
            "arm_name",
            "arm_position_within_pair",
            "trial_id",
        }
    }


def _parse_linux_cpu_list(value: str) -> set[int]:
    result: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            raise ValueError(f"empty Linux CPU-list component: {value!r}")
        if "-" in part:
            first_text, last_text = part.split("-", 1)
            first, last = int(first_text), int(last_text)
            if first < 0 or last < first:
                raise ValueError(f"invalid Linux CPU-list range: {part!r}")
            result.update(range(first, last + 1))
        else:
            cpu_id = int(part)
            if cpu_id < 0:
                raise ValueError(f"invalid Linux CPU id: {cpu_id}")
            result.add(cpu_id)
    return result


def _verify_environment(config: dict[str, Any], environment: dict[str, Any]) -> None:
    assignment = config["execution"]["cpu_affinity_ids"]
    if environment.get("resolved_process_cpu_affinity") != assignment:
        raise ValueError("environment resolved CPU assignment differs from frozen ids")
    available = environment.get("available_cpu_ids")
    if not isinstance(available, list) or not set(assignment.values()) <= set(available):
        raise ValueError("environment CPU affinity mask omits a frozen assigned CPU")
    expected = config["execution"]["cpu_affinity_selection"][
        "expected_linux_topology"
    ]
    observed = environment.get("verified_cpu_topology")
    if not isinstance(observed, dict) or set(observed) != set(expected):
        raise ValueError("environment has no exact verified CPU topology")
    sibling_sets: list[set[int]] = []
    physical_cores = set()
    for role, expected_record in expected.items():
        record = observed.get(role)
        if not isinstance(record, dict):
            raise ValueError(f"environment CPU topology missing role {role}")
        for key, value in expected_record.items():
            if record.get(key) != value:
                raise ValueError(f"environment CPU topology mismatch: {role}.{key}")
        siblings = _parse_linux_cpu_list(record.get("thread_siblings_list", ""))
        if record["cpu_id"] not in siblings:
            raise ValueError(f"assigned CPU absent from its sibling list: {role}")
        sibling_sets.append(siblings)
        physical_cores.add((record["physical_package_id"], record["core_id"]))
    if len(physical_cores) != len(expected):
        raise ValueError("assigned CPUs do not map to distinct physical cores")
    for index, siblings in enumerate(sibling_sets):
        for other in sibling_sets[index + 1 :]:
            if siblings & other:
                raise ValueError("two assigned CPUs are SMT siblings")


def _planned_packet_count(duration_s: float, rate_pps: float, offset_ns: int) -> int:
    if rate_pps <= 0:
        return 0
    duration_ns = int(round(duration_s * 1_000_000_000))
    if offset_ns >= duration_ns:
        return 0
    rate = Fraction(str(rate_pps))
    remaining = duration_ns - 1 - offset_ns
    return (remaining * rate.numerator) // (1_000_000_000 * rate.denominator) + 1


def _schedule_offset_ns(seed: int, traffic_class: str, rate_pps: float) -> int:
    if rate_pps <= 0:
        return 0
    period_ns = max(1, int(1_000_000_000 / rate_pps))
    digest = hashlib.sha256(f"{seed}:{traffic_class}".encode("ascii")).digest()
    return int.from_bytes(digest[:8], "big") % period_ns


def _nonnegative_int(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 0


def _decode_lateness_samples(
    evidence: Any,
    *,
    expected_sample_count: int,
    maximum_sample_count: int | None = None,
    label: str,
) -> tuple[list[int] | None, list[str]]:
    """Strictly decode one bounded, lossless send-lateness sample stream."""

    keys = {"encoding", "sample_count", "uncompressed_sha256", "data_base64"}
    if not isinstance(evidence, dict) or set(evidence) != keys:
        return None, [f"{label}:encoded_sample_shape"]
    if evidence.get("encoding") != LATENESS_SAMPLE_ENCODING:
        return None, [f"{label}:encoded_sample_encoding"]
    if not _nonnegative_int(expected_sample_count):
        return None, [f"{label}:expected_sample_count_invalid"]
    if (
        maximum_sample_count is not None
        and (
            not _nonnegative_int(maximum_sample_count)
            or expected_sample_count > maximum_sample_count
        )
    ):
        return None, [f"{label}:expected_sample_count_exceeds_schedule"]
    if evidence.get("sample_count") != expected_sample_count:
        return None, [f"{label}:encoded_sample_count_mismatch"]
    digest = evidence.get("uncompressed_sha256")
    encoded = evidence.get("data_base64")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or not isinstance(encoded, str)
    ):
        return None, [f"{label}:encoded_sample_metadata_invalid"]
    expected_bytes = expected_sample_count * 8
    maximum_compressed_bytes = max(128, expected_bytes * 2 + 1024)
    maximum_base64_characters = 4 * ((maximum_compressed_bytes + 2) // 3)
    if len(encoded) > maximum_base64_characters:
        return None, [f"{label}:encoded_sample_compressed_size_exceeded"]
    try:
        compressed = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        return None, [f"{label}:encoded_sample_base64_invalid"]
    if base64.b64encode(compressed).decode("ascii") != encoded:
        return None, [f"{label}:encoded_sample_base64_noncanonical"]
    if len(compressed) > maximum_compressed_bytes:
        return None, [f"{label}:encoded_sample_compressed_size_exceeded"]
    try:
        decoder = zlib.decompressobj()
        raw = decoder.decompress(compressed, expected_bytes + 1)
    except zlib.error:
        return None, [f"{label}:encoded_sample_zlib_invalid"]
    if (
        len(raw) != expected_bytes
        or not decoder.eof
        or decoder.unconsumed_tail
        or decoder.unused_data
    ):
        return None, [f"{label}:encoded_sample_stream_or_length_invalid"]
    if hashlib.sha256(raw).hexdigest() != digest:
        return None, [f"{label}:encoded_sample_sha256_mismatch"]
    samples = [value[0] for value in struct.iter_unpack("<Q", raw)]
    if len(samples) != expected_sample_count:
        return None, [f"{label}:decoded_sample_count_mismatch"]
    return samples, []


def _lateness_summary(samples: list[int]) -> dict[str, int | float | None]:
    return {
        "sample_count": len(samples),
        "mean_ns": sum(samples) / len(samples) if samples else None,
        "max_ns": max(samples) if samples else None,
        "p99_ns": nearest_rank(samples, 0.99) if samples else None,
    }


def _validate_counter_record(
    counter: Any,
    *,
    packet_size: int,
    label: str,
) -> list[str]:
    keys = {
        "benign_packets",
        "benign_bytes",
        "suspicious_packets",
        "suspicious_bytes",
        "benign_rtt_probe_packets",
    }
    if not isinstance(counter, dict) or set(counter) != keys:
        return [f"{label}:counter_shape"]
    errors = []
    for key in keys:
        if not _nonnegative_int(counter[key]):
            errors.append(f"{label}:{key}:not_nonnegative_integer")
    if errors:
        return errors
    for traffic_class in ("benign", "suspicious"):
        if counter[f"{traffic_class}_bytes"] != (
            counter[f"{traffic_class}_packets"] * packet_size
        ):
            errors.append(f"{label}:{traffic_class}:byte_packet_mismatch")
    if counter["benign_rtt_probe_packets"] > counter["benign_packets"]:
        errors.append(f"{label}:probe_count_exceeds_benign_packets")
    return errors


def _sum_counter_records(records: list[dict[str, int]]) -> dict[str, int]:
    return {
        key: sum(record[key] for record in records)
        for key in records[0]
    }


def _udp_snmp_errors(record: dict[str, Any], label: str) -> list[str]:
    """Validate the retained namespace-local UDP counter ledger exactly."""

    before = record.get("udp_snmp_before")
    after = record.get("udp_snmp_after")
    delta = record.get("udp_snmp_delta")
    if not all(isinstance(item, dict) for item in (before, after, delta)):
        return [f"{label}_udp_snmp_ledger_missing"]
    if not before or set(before) != set(after) or set(before) != set(delta):
        return [f"{label}_udp_snmp_ledger_shape"]
    errors = []
    for key in before:
        if (
            not _nonnegative_int(before[key])
            or not _nonnegative_int(after[key])
            or not _nonnegative_int(delta[key])
        ):
            errors.append(f"{label}_udp_snmp_counter_invalid:{key}")
        elif after[key] < before[key] or delta[key] != after[key] - before[key]:
            errors.append(f"{label}_udp_snmp_delta_mismatch:{key}")
    return errors


def _namespace_evidence_errors(
    config: dict[str, Any],
    before: Any,
    after: Any,
) -> list[str]:
    errors: list[str] = []
    network = config["network"]
    for boundary, evidence in (("before", before), ("after", after)):
        if not isinstance(evidence, dict):
            errors.append(f"namespace_{boundary}:missing")
            continue
        if evidence.get("errors") != []:
            errors.append(f"namespace_{boundary}:reported_errors")
        guard = evidence.get("generic_isolation_guard", {})
        if guard.get("returncode") != 0:
            errors.append(f"namespace_{boundary}:generic_guard_failed")
        exact = evidence.get("exact_state")
        if not isinstance(exact, dict) or set(exact) != {"server", "client"}:
            errors.append(f"namespace_{boundary}:exact_state_shape")
            continue
        expected_role = {
            "server": (network["server_interface"], network["server_ip"]),
            "client": (network["client_interface"], network["client_ip"]),
        }
        for role, (interface, address) in expected_role.items():
            snapshot = exact[role]
            links = snapshot.get("links", [])
            if sorted(str(item.get("ifname")) for item in links) != sorted(
                ["lo", interface]
            ):
                errors.append(f"namespace_{boundary}:{role}:interfaces")
            ipv4 = sorted(
                f"{item.get('local')}/{item.get('prefixlen')}"
                for interface_record in snapshot.get("ipv4_addresses", [])
                for item in interface_record.get("addr_info", [])
                if item.get("family") == "inet"
            )
            if ipv4 != sorted(
                [network["loopback_ipv4"], f"{address}/{network['prefix_length']}"]
            ):
                errors.append(f"namespace_{boundary}:{role}:ipv4_addresses")
            ipv6 = [
                item
                for interface_record in snapshot.get("ipv6_addresses", [])
                for item in interface_record.get("addr_info", [])
                if item.get("family") == "inet6"
            ]
            if (
                ipv6
                or snapshot.get("ipv6_main_routes") != []
                or snapshot.get("ipv6_disabled") != "1"
            ):
                errors.append(f"namespace_{boundary}:{role}:ipv6_policy")
            routes = sorted(
                (str(item.get("dst")), str(item.get("dev")))
                for item in snapshot.get("ipv4_main_routes", [])
            )
            if routes != [(network["main_route"], interface)]:
                errors.append(f"namespace_{boundary}:{role}:routes")
        if network.get("neighbor_policy") != (
            "static_permanent_peer_entries_before_tc"
        ):
            errors.append(f"namespace_{boundary}:neighbor_policy_not_frozen")
        peer_expectations = {
            "server": ("client", network["client_ip"]),
            "client": ("server", network["server_ip"]),
        }
        for role, (peer_role, peer_ip) in peer_expectations.items():
            peer_interface = expected_role[peer_role][0]
            peer_link = next(
                (
                    item
                    for item in exact[peer_role].get("links", [])
                    if item.get("ifname") == peer_interface
                ),
                None,
            )
            expected_neighbor = {
                "dst": peer_ip,
                "dev": expected_role[role][0],
                "lladdr": (
                    str(peer_link.get("address", "")).lower()
                    if isinstance(peer_link, dict)
                    else ""
                ),
                "state": ["PERMANENT"],
            }
            observed_neighbors = [
                {
                    "dst": item.get("dst"),
                    "dev": item.get("dev"),
                    "lladdr": str(item.get("lladdr", "")).lower(),
                    "state": item.get("state"),
                }
                for item in exact[role].get("neighbors", [])
            ]
            if observed_neighbors != [expected_neighbor]:
                errors.append(f"namespace_{boundary}:{role}:permanent_neighbor")
    if isinstance(before, dict) and isinstance(after, dict):
        first_identity = before.get("anchor_identity")
        last_identity = after.get("anchor_identity")
        if not isinstance(first_identity, dict) or first_identity != last_identity:
            errors.append("namespace_anchor_identity_changed")
        elif set(first_identity) != {"server", "client"}:
            errors.append("namespace_anchor_identity_shape")
        else:
            server, client = first_identity["server"], first_identity["client"]
            required = {"pid", "start_ticks", "owner_uid", "netns_id", "userns_id"}
            if set(server) != required or set(client) != required:
                errors.append("namespace_anchor_identity_fields")
            elif (
                server["netns_id"] == client["netns_id"]
                or server["userns_id"] != client["userns_id"]
            ):
                errors.append("namespace_anchor_isolation_identity")
    return errors


def _tc_record_counter(
    snapshot: dict[str, Any], category: str, identity: str, name: str
) -> int | None:
    records = snapshot.get("commands", {}).get(category, {}).get("records", [])
    record = next(
        (
            item
            for item in records
            if str(item.get("classid", item.get("handle"))) == identity
        ),
        None,
    )
    if not isinstance(record, dict):
        return None
    direct = record.get(name)
    if _nonnegative_int(direct):
        return direct
    stats = record.get("stats", {})
    direct = stats.get(name) if isinstance(stats, dict) else None
    if _nonnegative_int(direct):
        return direct
    stats2 = record.get("stats2", {})
    if not isinstance(stats2, dict):
        return None
    if name in {"packets", "bytes"}:
        value = stats2.get("basic", {}).get(name)
    else:
        value = stats2.get("queue", {}).get(name)
    return value if _nonnegative_int(value) else None


def _tc_record_delta(
    before: dict[str, Any],
    after: dict[str, Any],
    category: str,
    identity: str,
    name: str,
) -> int | None:
    first = _tc_record_counter(before, category, identity, name)
    last = _tc_record_counter(after, category, identity, name)
    if first is None or last is None or first < 0 or last < first:
        return None
    return last - first


def _require_authenticated_profile(
    config: dict[str, Any], profile: dict[str, Any]
) -> dict[str, Any]:
    """Reject a profile payload not exactly derived from the frozen config.

    The execution plan is authenticated before analysis. Independent raw
    recomputation receives that exact plan profile instead of silently falling
    back to the authoritative top-level validity defaults.
    """

    if not isinstance(profile, dict):
        raise ValueError("authenticated execution-plan profile is not an object")
    profile_name = profile.get("name")
    if not isinstance(profile_name, str):
        raise ValueError("authenticated execution-plan profile has no name")
    expected = effective_profile(config, profile_name)
    if profile != expected:
        raise ValueError(
            "authenticated execution-plan profile differs from frozen config"
        )
    return profile


def recompute_counter_reconciliation(
    config: dict[str, Any],
    authenticated_profile: dict[str, Any],
    receiver: dict[str, Any],
    benign: dict[str, Any],
    suspicious: dict[str, Any],
    snapshots: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    profile = _require_authenticated_profile(config, authenticated_profile)
    validity = profile["validity"]
    """Reproduce the runner's qdisc/application ledger from raw counters."""

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
            isinstance(value, int) and not isinstance(value, bool)
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
            if not isinstance(sent_packets, int) or isinstance(sent_packets, bool):
                errors.append(f"missing {label} {phase} sender counter")
            elif cohort_received > sent_packets:
                errors.append(
                    f"{label} {phase}-origin receiver cohort exceeds successful sends"
                )
    root_measurement_packets = _tc_record_delta(
        snapshots["measurement_start"],
        snapshots["measurement_end"],
        "qdisc",
        "1:",
        "packets",
    )
    root_measurement_bytes = _tc_record_delta(
        snapshots["measurement_start"],
        snapshots["measurement_end"],
        "qdisc",
        "1:",
        "bytes",
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
            validity["qdisc_packet_conservation_absolute_tolerance"],
            math.ceil(
                sent_total
                * validity["counter_reconciliation_relative_tolerance"]
            ),
        )
        if abs(root_measurement_packets - received_total) > tolerance:
            errors.append(
                "root qdisc measurement departures do not match receiver "
                "arrival-window packets"
            )
        if root_measurement_packets > sent_total + tolerance:
            errors.append("qdisc measurement delta exceeds sender success beyond tolerance")
        if root_measurement_bytes != root_measurement_packets * qdisc_packet_bytes:
            errors.append("root qdisc measurement bytes do not use frozen 1242-byte SKB unit")

    root_arm = {
        name: _tc_record_delta(
            snapshots["arm_start"], snapshots["arm_end"], "qdisc", "1:", name
        )
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
    absolute_tolerance = validity[
        "qdisc_packet_conservation_absolute_tolerance"
    ]
    if any(value is None for value in root_arm.values()):
        errors.append("root qdisc arm counters are missing or nonmonotonic")
    else:
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
            name: _tc_record_delta(
                snapshots["arm_start"],
                snapshots["arm_end"],
                "qdisc",
                qdisc_handle,
                name,
            )
            for name in ("packets", "bytes", "drops")
        }
        class_arm[label] = {
            name: _tc_record_delta(
                snapshots["arm_start"],
                snapshots["arm_end"],
                "class",
                classid,
                name,
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

    backlogs = {}
    for snapshot_name in TC_SNAPSHOT_NAMES:
        snapshot = snapshots[snapshot_name]
        root_backlog = _tc_record_counter(snapshot, "qdisc", "1:", "backlog")
        leaf_backlogs = {
            "fast": _tc_record_counter(snapshot, "qdisc", "10:", "backlog"),
            "suspicious": _tc_record_counter(
                snapshot, "qdisc", "20:", "backlog"
            ),
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


def _receiver_raw_errors(config: dict[str, Any], receiver: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    packet_size = config["traffic"]["packet_payload_bytes"]
    windows = receiver.get("counts_by_arrival_window")
    phases = receiver.get("counts_by_sender_phase")
    matrix = receiver.get("sender_phase_by_arrival_window")
    expected_windows = {"before_start", "warmup", "measurement", "drain"}
    expected_phases = {"warmup", "measurement"}
    if not isinstance(windows, dict) or set(windows) != expected_windows:
        return ["receiver_arrival_window_counter_shape"]
    if not isinstance(phases, dict) or set(phases) != expected_phases:
        return ["receiver_sender_phase_counter_shape"]
    if not isinstance(matrix, dict) or set(matrix) != expected_phases:
        return ["receiver_cross_boundary_matrix_shape"]
    for window, counter in windows.items():
        errors.extend(
            _validate_counter_record(
                counter, packet_size=packet_size, label=f"arrival.{window}"
            )
        )
    for phase, counter in phases.items():
        errors.extend(
            _validate_counter_record(
                counter, packet_size=packet_size, label=f"sender_phase.{phase}"
            )
        )
        if not isinstance(matrix.get(phase), dict) or set(matrix[phase]) != expected_windows:
            errors.append(f"receiver_cross_boundary_matrix_shape:{phase}")
            continue
        for window, cell in matrix[phase].items():
            errors.extend(
                _validate_counter_record(
                    cell,
                    packet_size=packet_size,
                    label=f"matrix.{phase}.{window}",
                )
            )
    if errors:
        return errors
    for phase in expected_phases:
        if phases[phase] != _sum_counter_records(
            [matrix[phase][window] for window in sorted(expected_windows)]
        ):
            errors.append(f"receiver_matrix_sender_phase_sum:{phase}")
    for window in expected_windows:
        if windows[window] != _sum_counter_records(
            [matrix[phase][window] for phase in sorted(expected_phases)]
        ):
            errors.append(f"receiver_matrix_arrival_window_sum:{window}")
    measurement_origin = matrix["measurement"]
    warmup_origin = matrix["warmup"]
    expected_origin_cohort = {
        "arrived_during_measurement": measurement_origin["measurement"],
        "arrived_during_drain": measurement_origin["drain"],
        "arrived_before_measurement_window": {
            key: measurement_origin["before_start"][key]
            + measurement_origin["warmup"][key]
            for key in measurement_origin["warmup"]
        },
    }
    if receiver.get("measurement_origin_cohort") != expected_origin_cohort:
        errors.append("receiver_measurement_origin_cohort_mismatch")
    if receiver.get("cross_boundary") != {
        "warmup_origin_arrived_during_measurement": warmup_origin["measurement"],
        "measurement_origin_arrived_during_drain": measurement_origin["drain"],
    }:
        errors.append("receiver_cross_boundary_summary_mismatch")
    if receiver.get("primary_service_window") != (
        "receiver_arrival_[warmup_end,measurement_end)"
    ):
        errors.append("receiver_primary_service_window_mismatch")
    for field in (
        "malformed_packets",
        "wrong_size_packets",
        "benign_echo_failures",
        "socket_rxq_overflow_drops",
    ):
        if receiver.get(field) != 0:
            errors.append(f"receiver_nonzero_{field}")
    total_records = list(windows.values())
    total_probes = sum(item["benign_rtt_probe_packets"] for item in total_records)
    total_benign = sum(item["benign_packets"] for item in total_records)
    if receiver.get("benign_echo_attempts") != total_probes:
        errors.append("receiver_echo_attempt_count_mismatch")
    if receiver.get("nonprobe_benign_packets_not_echoed") != total_benign - total_probes:
        errors.append("receiver_nonprobe_echo_policy_count_mismatch")
    expected_out_of_window = sum(
        windows[window][f"{label}_packets"]
        for window in ("before_start", "drain")
        for label in ("benign", "suspicious")
    )
    if receiver.get("out_of_window_packets") != expected_out_of_window:
        errors.append("receiver_out_of_window_count_mismatch")
    if receiver.get("echo_policy") != "only_flagged_rtt_probes_are_echoed":
        errors.append("receiver_echo_policy_mismatch")
    errors.extend(_udp_snmp_errors(receiver, "receiver"))
    udp_delta = receiver.get("udp_snmp_delta")
    if not isinstance(udp_delta, dict):
        errors.append("receiver_udp_snmp_delta_missing")
    elif udp_delta.get("InErrors") != 0 or udp_delta.get("RcvbufErrors") != 0:
        errors.append("receiver_udp_snmp_receive_errors")
    return errors


def _sender_raw_errors(
    config: dict[str, Any],
    profile: dict[str, Any],
    trial: dict[str, Any],
    label: str,
    sender: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    expected_rate = trial[f"{label}_target_pps"]
    packet_size = config["traffic"]["packet_payload_bytes"]
    if sender.get("traffic_class") != label:
        errors.append(f"{label}_sender_class_mismatch")
    if sender.get("role") != "sender" or sender.get("final") is not True:
        errors.append(f"{label}_sender_role_or_final_mismatch")
    expected_tos = config["service"][
        "fast_tos" if label == "benign" else "suspicious_tos"
    ]
    expected_source_port = config["network"][f"{label}_source_port"]
    if sender.get("tos") != expected_tos:
        errors.append(f"{label}_sender_tos_mismatch")
    if sender.get("source_port") != expected_source_port:
        errors.append(f"{label}_sender_source_port_mismatch")
    if sender.get("target_port") != config["network"]["receiver_port"]:
        errors.append(f"{label}_sender_target_port_mismatch")
    if sender.get("seed") != trial["traffic_seed"]:
        errors.append(f"{label}_sender_seed_mismatch")
    if sender.get("target_rate_pps") != expected_rate:
        errors.append(f"{label}_sender_rate_mismatch")
    if sender.get("packet_size_bytes") != packet_size:
        errors.append(f"{label}_sender_packet_size_mismatch")
    expected_offset = _schedule_offset_ns(trial["traffic_seed"], label, expected_rate)
    if sender.get("schedule_offset_ns") != expected_offset:
        errors.append(f"{label}_sender_schedule_offset_mismatch")
    planned_warmup = _planned_packet_count(trial["warmup_s"], expected_rate, expected_offset)
    planned_total = _planned_packet_count(
        trial["warmup_s"] + trial["measurement_s"], expected_rate, expected_offset
    )
    planned = {
        "warmup": planned_warmup,
        "measurement": planned_total - planned_warmup,
        "total": planned_total,
    }
    if sender.get("planned_packets") != planned:
        errors.append(f"{label}_sender_planned_schedule_mismatch")
    if sender.get("missed_deadline_policy") != "skip_expired_slot_never_catch_up":
        errors.append(f"{label}_sender_missed_deadline_policy_mismatch")
    missed = sender.get("missed_deadlines")
    sent = sender.get("sent")
    send_errors = sender.get("send_errors_by_phase")
    lateness = sender.get("send_lateness_by_phase")
    encoded_lateness = sender.get("send_lateness_samples_by_phase")
    if not all(isinstance(value, dict) for value in (missed, sent, send_errors, lateness)):
        return errors + [f"{label}_sender_schedule_evidence_missing"]
    phase_set = {"warmup", "measurement"}
    if set(sent) != phase_set:
        errors.append(f"{label}_sender_sent_phase_shape")
    if set(send_errors) != phase_set:
        errors.append(f"{label}_sender_send_error_phase_shape")
    if set(lateness) != phase_set:
        errors.append(f"{label}_sender_lateness_phase_shape")
    if not isinstance(encoded_lateness, dict) or set(encoded_lateness) != phase_set:
        errors.append(f"{label}_sender_encoded_lateness_phase_shape")
    if set(missed) != {"warmup", "measurement", "total", "rtt_probes"}:
        errors.append(f"{label}_sender_missed_deadline_shape")
    missed_total = 0
    send_error_total = 0
    decoded_lateness: dict[str, list[int]] = {}
    for phase in ("warmup", "measurement"):
        phase_sent = sent.get(phase)
        if not isinstance(phase_sent, dict) or set(phase_sent) != {
            "packets", "bytes", "rtt_probe_packets"
        }:
            errors.append(f"{label}_sender_sent_shape:{phase}")
            continue
        if any(not _nonnegative_int(value) for value in phase_sent.values()):
            errors.append(f"{label}_sender_sent_noninteger:{phase}")
            continue
        if phase_sent["bytes"] != phase_sent["packets"] * packet_size:
            errors.append(f"{label}_sender_sent_bytes:{phase}")
        if phase_sent["rtt_probe_packets"] > phase_sent["packets"]:
            errors.append(f"{label}_sender_probe_count:{phase}")
        phase_missed = missed.get(phase)
        phase_send_errors = send_errors.get(phase)
        if not _nonnegative_int(phase_missed) or not _nonnegative_int(phase_send_errors):
            errors.append(f"{label}_sender_missed_or_send_errors:{phase}")
            continue
        missed_total += phase_missed
        send_error_total += phase_send_errors
        if phase_sent["packets"] + phase_missed + phase_send_errors != planned[phase]:
            errors.append(f"{label}_sender_schedule_conservation:{phase}")
        if phase_send_errors != 0:
            errors.append(f"{label}_sender_send_errors_nonzero:{phase}")
        phase_lateness = lateness.get(phase)
        if not isinstance(phase_lateness, dict):
            errors.append(f"{label}_sender_lateness_missing:{phase}")
            continue
        if set(phase_lateness) != {"sample_count", "mean_ns", "max_ns", "p99_ns"}:
            errors.append(f"{label}_sender_lateness_shape:{phase}")
        decoded, decode_errors = _decode_lateness_samples(
            encoded_lateness.get(phase) if isinstance(encoded_lateness, dict) else None,
            expected_sample_count=phase_sent["packets"],
            maximum_sample_count=planned[phase],
            label=f"{label}_sender_lateness_samples:{phase}",
        )
        errors.extend(decode_errors)
        if decoded is not None:
            decoded_lateness[phase] = decoded
            expected_lateness_summary = _lateness_summary(decoded)
            if phase_lateness != expected_lateness_summary or (
                decoded
                and not isinstance(phase_lateness.get("mean_ns"), float)
            ):
                errors.append(f"{label}_sender_lateness_exact_recompute:{phase}")
        if phase_lateness.get("sample_count") != phase_sent["packets"]:
            errors.append(f"{label}_sender_lateness_count:{phase}")
        p99 = phase_lateness.get("p99_ns")
        if phase_sent["packets"]:
            mean_ns = phase_lateness.get("mean_ns")
            max_ns = phase_lateness.get("max_ns")
            if (
                isinstance(mean_ns, bool)
                or not isinstance(mean_ns, (int, float))
                or not math.isfinite(float(mean_ns))
                or mean_ns < 0
                or not _nonnegative_int(max_ns)
                or mean_ns > max_ns
            ):
                errors.append(f"{label}_sender_lateness_summary_invalid:{phase}")
            if not _nonnegative_int(p99):
                errors.append(f"{label}_sender_lateness_p99_missing:{phase}")
            elif not _nonnegative_int(max_ns) or p99 > max_ns:
                errors.append(f"{label}_sender_lateness_p99_exceeds_max:{phase}")
            elif p99 > profile["validity"]["maximum_send_lateness_p99_ns"]:
                errors.append(f"{label}_sender_lateness_p99_gate:{phase}")
        elif any(
            phase_lateness.get(field) is not None
            for field in ("mean_ns", "max_ns", "p99_ns")
        ):
            errors.append(f"{label}_sender_empty_lateness_summary:{phase}")
        if planned[phase] and (
            phase_missed + phase_send_errors
        ) / planned[phase] > profile["validity"]["maximum_missed_schedule_fraction"]:
            errors.append(f"{label}_sender_missed_schedule_fraction:{phase}")
    if sender.get("send_errors") != send_error_total:
        errors.append(f"{label}_sender_send_error_total_mismatch")
    if missed.get("total") != missed_total:
        errors.append(f"{label}_sender_missed_total_mismatch")
    if sender.get("socket_rxq_overflow_drops") != 0:
        errors.append(f"{label}_sender_socket_overflow")
    if set(decoded_lateness) == phase_set:
        all_lateness = (
            decoded_lateness["warmup"] + decoded_lateness["measurement"]
        )
        total_summary = _lateness_summary(all_lateness)
        expected_total_summary = {
            "send_lateness_sample_count": total_summary["sample_count"],
            "send_lateness_mean_ns": total_summary["mean_ns"],
            "send_lateness_max_ns": total_summary["max_ns"],
            "send_lateness_p99_ns": total_summary["p99_ns"],
        }
        if any(sender.get(key) != value for key, value in expected_total_summary.items()):
            errors.append(f"{label}_sender_total_lateness_exact_recompute")
        if all_lateness and not isinstance(sender.get("send_lateness_mean_ns"), float):
            errors.append(f"{label}_sender_total_lateness_mean_type")
    else:
        errors.append(f"{label}_sender_lateness_samples_incomplete")
    errors.extend(_udp_snmp_errors(sender, f"{label}_sender"))
    udp_delta = sender.get("udp_snmp_delta")
    if not isinstance(udp_delta, dict):
        errors.append(f"{label}_sender_udp_snmp_delta_missing")
    elif udp_delta.get("InErrors") != 0 or udp_delta.get("RcvbufErrors") != 0:
        errors.append(f"{label}_sender_udp_snmp_receive_errors")

    probes = sender.get("rtt_probes")
    if not isinstance(probes, dict):
        return errors + [f"{label}_sender_probe_evidence_missing"]
    if sender.get("rtt_probe_policy") != "fixed_rate_flagged_subset_echo_only":
        errors.append(f"{label}_sender_probe_policy_mismatch")
    if label == "benign":
        probe_rate = trial["benign_rtt_probe_rate_pps"]
        ratio = expected_rate / probe_rate
        expected_every = int(round(ratio))
        expected_planned_probes = {
            "warmup": (
                (planned["warmup"] - 1) // expected_every + 1
                if planned["warmup"]
                else 0
            ),
            "measurement": (
                (planned["total"] - 1) // expected_every
                - ((planned["warmup"] - 1) // expected_every)
                if planned["measurement"]
                else 0
            ),
        }
        if probes.get("target_rate_pps") != probe_rate:
            errors.append("benign_sender_probe_rate_mismatch")
        if probes.get("selection_every_n_benign_packets") != expected_every:
            errors.append("benign_sender_probe_selection_mismatch")
        if probes.get("planned") != expected_planned_probes:
            errors.append("benign_sender_probe_plan_mismatch")
        missed_probes = missed.get("rtt_probes")
        if not isinstance(missed_probes, dict) or set(missed_probes) != {
            "warmup", "measurement"
        }:
            errors.append("benign_sender_missed_probe_shape")
        else:
            for phase in ("warmup", "measurement"):
                if (
                    not _nonnegative_int(missed_probes[phase])
                    or missed_probes[phase] > expected_planned_probes[phase]
                    or sent.get(phase, {}).get("rtt_probe_packets", 0)
                    + missed_probes[phase]
                    > expected_planned_probes[phase]
                ):
                    errors.append(f"benign_sender_missed_probe_count:{phase}")
                elif (
                    send_errors.get(phase) == 0
                    and sent.get(phase, {}).get("rtt_probe_packets", 0)
                    + missed_probes[phase]
                    != expected_planned_probes[phase]
                ):
                    errors.append(f"benign_sender_probe_schedule_conservation:{phase}")
        expected_probe_sent = {
            phase: sent.get(phase, {}).get("rtt_probe_packets")
            for phase in ("warmup", "measurement")
        }
        if probes.get("sent") != expected_probe_sent:
            errors.append("benign_sender_probe_sent_mismatch")
        rtt_samples = sender.get("measurement_rtt_ns")
        if not isinstance(rtt_samples, list) or any(
            not _nonnegative_int(value) for value in rtt_samples
        ):
            errors.append("benign_sender_rtt_samples_invalid")
        else:
            recomputed_p99 = nearest_rank(rtt_samples, 0.99) if rtt_samples else None
            received = len(rtt_samples)
            sent_measurement_probes = sent.get("measurement", {}).get(
                "rtt_probe_packets", 0
            )
            unacked = sent_measurement_probes - received
            expected_loss_fraction = (
                unacked / sent_measurement_probes
                if sent_measurement_probes
                else None
            )
            if unacked < 0:
                errors.append("benign_sender_probe_received_exceeds_sent")
            if sender.get("measurement_rtt_p99_ns") != recomputed_p99:
                errors.append("benign_sender_rtt_p99_mismatch")
            if probes.get("measurement_conditional_rtt_p99_ns") != recomputed_p99:
                errors.append("benign_sender_conditional_rtt_p99_mismatch")
            if probes.get("measurement_received") != received:
                errors.append("benign_sender_probe_received_mismatch")
            if probes.get("measurement_unacknowledged") != unacked:
                errors.append("benign_sender_probe_unacked_mismatch")
            if probes.get("measurement_loss_packets") != unacked:
                errors.append("benign_sender_probe_loss_mismatch")
            if probes.get("measurement_loss_fraction") != expected_loss_fraction:
                errors.append("benign_sender_probe_loss_fraction_mismatch")
            if sender.get("measurement_echo_received_packets") != received:
                errors.append("benign_sender_echo_received_mismatch")
            if sender.get("measurement_echo_unacknowledged_packets") != unacked:
                errors.append("benign_sender_echo_unacked_mismatch")
            if sender.get("rtt_loss_reason") != (
                None if rtt_samples else "no_valid_measurement_echo_received"
            ):
                errors.append("benign_sender_rtt_loss_reason_mismatch")
            if received < profile["validity"]["minimum_measurement_rtt_probes_received"]:
                errors.append("benign_sender_minimum_rtt_probe_gate")
        for field in ("echo_malformed", "echo_wrong_class", "echo_duplicates", "echo_nonprobe"):
            if sender.get(field) != 0:
                errors.append(f"benign_sender_nonzero_{field}")
    else:
        expected_no_probes = {
            "target_rate_pps": 0.0,
            "selection_every_n_benign_packets": None,
            "planned": {"warmup": 0, "measurement": 0},
            "sent": {"warmup": 0, "measurement": 0},
            "measurement_received": 0,
            "measurement_unacknowledged": 0,
            "measurement_loss_packets": 0,
            "measurement_loss_fraction": None,
            "measurement_conditional_rtt_p99_ns": None,
        }
        if probes != expected_no_probes:
            errors.append("suspicious_sender_probe_evidence_nonzero_or_malformed")
        expected_no_probe_fields = {
            "measurement_rtt_ns": [],
            "measurement_rtt_p99_ns": None,
            "warmup_rtt_count": 0,
            "echo_unacknowledged_packets": 0,
            "measurement_echo_unacknowledged_packets": 0,
            "measurement_echo_received_packets": 0,
            "echo_malformed": 0,
            "echo_wrong_class": 0,
            "echo_duplicates": 0,
            "echo_nonprobe": 0,
            "rtt_loss_reason": "no_valid_measurement_echo_received",
        }
        if any(
            sender.get(field) != expected
            for field, expected in expected_no_probe_fields.items()
        ):
            errors.append("suspicious_sender_nonprobe_state_mismatch")
    return errors


def _stored_validity_evidence_errors(
    record: dict[str, Any],
    profile: dict[str, Any],
    benign: dict[str, Any],
    suspicious: dict[str, Any],
    receiver: dict[str, Any],
) -> list[str]:
    evidence = record.get("validity_evidence")
    if not isinstance(evidence, dict):
        return ["stored_validity_evidence_missing"]
    errors = []
    if evidence.get("schema_version") != "matched-scheduler-validity-evidence-1.0":
        errors.append("stored_validity_evidence_schema")
    if evidence.get("primary_service_window") != "receiver_arrival_measurement":
        errors.append("stored_validity_evidence_primary_window")
    if evidence.get("invalid_reasons") != record.get("invalid_reasons"):
        errors.append("stored_validity_evidence_reason_list")
    checks = evidence.get("checks")
    expected_check_keys = {
        *(f"background_cpu.{role}" for role in ("receiver", "benign_sender", "suspicious_sender")),
        "cpu_assignment",
        "namespace_before",
        "namespace_after",
        "tc_live_all_snapshots",
        "ready_record_identity",
        "all_processes_ready",
        "post_readiness_start_selection",
        "phase_snapshot_lateness",
        *(f"process.{role}" for role in ("receiver", "benign_sender", "suspicious_sender")),
        "start_signal_receipts",
        "process_final_identity",
        "receiver_packet_format",
        "receiver_arrival_window_counters",
        *(
            f"{check}.{label}.{phase}"
            for check in (
                "schedule_conservation",
                "send_errors",
                "missed_fraction",
                "lateness",
                "lateness_samples",
            )
            for label in ("benign", "suspicious")
            for phase in ("warmup", "measurement")
        ),
        *(f"lateness_samples_overall.{label}" for label in ("benign", "suspicious")),
        "rtt_probe_metadata",
        "rtt_probe_minimum",
        "rtt_probe_arithmetic",
        "conditional_rtt_p99",
        "suspicious_has_no_rtt_probes",
        "echo_instrumentation",
        *(f"socket_overflow.{role}" for role in ("receiver", "benign_sender", "suspicious_sender")),
        "counter_reconciliation",
    }
    regime = record.get("trial", {}).get("regime")
    if regime in {"borrowable_overload", "both_saturated"}:
        expected_check_keys.update(
            {
                "overload_offered_fraction.benign",
                "overload_offered_fraction.suspicious",
            }
        )
    if not isinstance(checks, dict) or any(
        not isinstance(check, dict) or not isinstance(check.get("passed"), bool)
        for check in (checks.values() if isinstance(checks, dict) else [])
    ):
        errors.append("stored_validity_check_shape")
    elif set(checks) != expected_check_keys:
        errors.append("stored_validity_check_set_mismatch")
    elif record.get("valid") is True and not all(
        check["passed"] for check in checks.values()
    ):
        errors.append("stored_valid_arm_has_failed_check")

    expected_sender_fidelity = {}
    for label, sender in (("benign", benign), ("suspicious", suspicious)):
        expected_sender_fidelity[label] = {}
        for phase in ("warmup", "measurement"):
            planned = sender["planned_packets"][phase]
            sent = sender["sent"][phase]["packets"]
            missed = sender["missed_deadlines"][phase]
            send_errors = sender["send_errors_by_phase"][phase]
            expected_sender_fidelity[label][phase] = {
                "planned": planned,
                "sent": sent,
                "missed": missed,
                "send_errors": send_errors,
                "missed_fraction": missed / planned if planned else 0.0,
                "lateness_p99_ns": sender["send_lateness_by_phase"][phase][
                    "p99_ns"
                ],
            }
    if evidence.get("sender_fidelity") != expected_sender_fidelity:
        errors.append("stored_validity_sender_fidelity_mismatch")
    probes = benign["rtt_probes"]
    expected_probe_delivery = {
        "planned": probes["planned"]["measurement"],
        "sent": probes["sent"]["measurement"],
        "received": probes["measurement_received"],
        "unacked": probes["measurement_unacknowledged"],
        "loss_packets": probes["measurement_loss_packets"],
        "loss_fraction": probes["measurement_loss_fraction"],
        "conditional_p99_ns": benign["measurement_rtt_p99_ns"],
    }
    if evidence.get("probe_delivery") != expected_probe_delivery:
        errors.append("stored_validity_probe_delivery_mismatch")
    expected_socket = {}
    for role, process_record in (
        ("receiver", receiver),
        ("benign_sender", benign),
        ("suspicious_sender", suspicious),
    ):
        expected_socket[role] = {
            "SO_RXQ_OVFL": process_record["socket_rxq_overflow_drops"],
            "InErrors": process_record["udp_snmp_delta"].get("InErrors"),
            "RcvbufErrors": process_record["udp_snmp_delta"].get("RcvbufErrors"),
        }
    if evidence.get("socket_overflow") != expected_socket:
        errors.append("stored_validity_socket_evidence_mismatch")
    # Frozen thresholds must be the ones used by the profile whose raw record
    # is being verified; their values are rechecked in primitive gates above.
    if profile["validity"]["maximum_send_lateness_p99_ns"] <= 0:
        errors.append("stored_validity_profile_threshold_invalid")
    return errors


def recompute_arm_invalid_reasons(
    config: dict[str, Any],
    trial: dict[str, Any],
    record: dict[str, Any],
    *,
    authenticated_profile: dict[str, Any],
) -> list[str]:
    """Independently derive arm validity from primitive raw evidence.

    This deliberately does not call the runner's validity function and never
    consumes the stored ``valid`` value as evidence.
    """

    reasons: list[str] = []
    try:
        require_finite_tree(record)
    except (TypeError, ValueError) as error:
        reasons.append(f"nonfinite_or_unsupported_raw:{error}")
    required = {
        "schema_version",
        "study_id",
        "profile",
        "evidentiary",
        "trial",
        "start_barrier",
        "background_cpu",
        "cpu_assignment",
        "isolation_before",
        "isolation_after",
        "tc_requested_spec",
        "tc_apply",
        "tc_snapshots",
        "processes",
    }
    missing = sorted(required - set(record))
    if missing:
        return sorted(set(reasons + [f"incomplete_arm_record:{','.join(missing)}"]))
    if record.get("schema_version") != ARM_SCHEMA_VERSION:
        reasons.append("arm_schema_mismatch")
    if record.get("study_id") != config["study_id"]:
        reasons.append("arm_study_id_mismatch")
    if record.get("trial") != trial:
        reasons.append("arm_trial_mismatch")
    try:
        profile = _require_authenticated_profile(config, authenticated_profile)
    except (KeyError, TypeError, ValueError) as error:
        return sorted(set(reasons + [f"arm_profile_invalid:{error}"]))
    if record.get("profile") != profile["name"]:
        reasons.append("arm_profile_differs_from_execution_plan")
    if record.get("evidentiary") is not profile["evidentiary"]:
        reasons.append("arm_evidentiary_flag_mismatch")

    assignment = config["execution"]["cpu_affinity_ids"]
    if record.get("cpu_assignment") != assignment:
        reasons.append("arm_cpu_assignment_mismatch")
    background = record.get("background_cpu", {})
    assigned_samples = background.get("assigned_cpus")
    if not isinstance(assigned_samples, dict) or set(assigned_samples) != set(assignment):
        reasons.append("background_assigned_cpu_shape")
    else:
        recomputed_busy = []
        for role, cpu_id in assignment.items():
            sample = assigned_samples[role]
            busy = sample.get("busy_ticks_delta")
            total = sample.get("total_ticks_delta")
            if (
                sample.get("cpu_id") != cpu_id
                or not _nonnegative_int(busy)
                or not _nonnegative_int(total)
                or total <= 0
                or busy > total
            ):
                reasons.append(f"background_cpu_sample_invalid:{role}")
                continue
            expected_percent = busy / total * 100.0
            if sample.get("busy_percent") != expected_percent:
                reasons.append(f"background_cpu_percent_mismatch:{role}")
            recomputed_busy.append(expected_percent)
            if expected_percent > profile["validity"][
                "maximum_background_busy_pct_each_assigned_cpu"
            ]:
                reasons.append(f"background_cpu_gate:{role}:cpu{cpu_id}")
        if recomputed_busy and background.get(
            "maximum_assigned_cpu_busy_percent"
        ) != max(recomputed_busy):
            reasons.append("background_maximum_busy_percent_mismatch")
    aggregate = background.get("whole_host_aggregate_descriptive_only")
    if not isinstance(aggregate, dict) or aggregate.get(
        "used_as_invalidation_trigger"
    ) is not False:
        reasons.append("background_host_aggregate_not_descriptive_only")

    reasons.extend(
        _namespace_evidence_errors(
            config, record.get("isolation_before"), record.get("isolation_after")
        )
    )
    expected_spec = requested_tc_spec(
        config, trial["arm_id"], trial["reservation_id"]
    )
    if record.get("tc_requested_spec") != expected_spec:
        reasons.append("tc_requested_spec_mismatch")
    apply = record.get("tc_apply")
    vectors = tc_command_vectors(expected_spec)
    if not isinstance(apply, list) or len(apply) != len(vectors):
        reasons.append("tc_apply_record_count_mismatch")
    else:
        for index, (entry, vector) in enumerate(zip(apply, vectors, strict=True)):
            if entry.get("index") != index or entry.get("argv") != vector:
                reasons.append(f"tc_apply_vector_mismatch:{index}")
            allowed_absence = entry.get("allowed_initial_root_absence") is True
            if entry.get("returncode") != 0 and not (index == 0 and allowed_absence):
                reasons.append(f"tc_apply_failed:{index}")
            if allowed_absence and index != 0:
                reasons.append(f"tc_apply_improper_allowed_absence:{index}")

    snapshots = record.get("tc_snapshots")
    if not isinstance(snapshots, dict) or set(snapshots) != set(TC_SNAPSHOT_NAMES):
        reasons.append("tc_snapshot_set_mismatch")
        snapshots = {}
    else:
        previous_finished = None
        for name in TC_SNAPSHOT_NAMES:
            snapshot = snapshots[name]
            started = snapshot.get("capture_started_monotonic_ns")
            finished = snapshot.get("capture_finished_monotonic_ns")
            if (
                not _nonnegative_int(started)
                or not _nonnegative_int(finished)
                or finished < started
                or (previous_finished is not None and started < previous_finished)
            ):
                reasons.append(f"tc_snapshot_timing:{name}")
            previous_finished = finished if _nonnegative_int(finished) else previous_finished
            _normalized, tc_errors = validate_normalized_live_tc(snapshot, expected_spec)
            reasons.extend(f"tc_snapshot:{name}:{error}" for error in tc_errors)
            stored_validation = record.get("tc_live_validation", {}).get(name)
            if not isinstance(stored_validation, dict) or stored_validation.get("errors") != []:
                reasons.append(f"stored_tc_validation_not_clean:{name}")
        if record.get("tc_live_validation_errors") != []:
            reasons.append("stored_tc_validation_aggregate_not_clean")
        traffic_start = record.get("traffic_start_monotonic_ns")
        if _nonnegative_int(traffic_start):
            warmup_boundary = traffic_start + int(round(trial["warmup_s"] * 1e9))
            measurement_boundary = warmup_boundary + int(
                round(trial["measurement_s"] * 1e9)
            )
            maximum_snapshot_lateness = profile["validity"][
                "maximum_phase_snapshot_start_lateness_ns"
            ]
            for name, boundary in (
                ("measurement_start", warmup_boundary),
                ("measurement_end", measurement_boundary),
            ):
                lateness = snapshots[name]["capture_started_monotonic_ns"] - boundary
                if lateness < 0 or lateness > maximum_snapshot_lateness:
                    reasons.append(f"phase_snapshot_lateness_gate:{name}")
        else:
            reasons.append("traffic_start_timestamp_invalid")

    processes = record.get("processes")
    expected_roles = {"receiver", "benign_sender", "suspicious_sender"}
    if not isinstance(processes, dict) or set(processes) != expected_roles:
        reasons.append("process_record_set_mismatch")
        return sorted(set(reasons))
    finals: dict[str, dict[str, Any]] = {}
    for role in sorted(expected_roles):
        wrapper = processes[role]
        final = wrapper.get("final_record")
        if (
            wrapper.get("returncode") != 0
            or not isinstance(final, dict)
            or final.get("error") is not None
            or wrapper.get("stdout_non_json_line_count") != 0
        ):
            reasons.append(f"process_failed_or_malformed:{role}")
            continue
        finals[role] = final
        if final.get("schema_version") != "matched-scheduler-traffic-1.0":
            reasons.append(f"process_schema_mismatch:{role}")
        if final.get("cpu_affinity") != [assignment[role]]:
            reasons.append(f"process_cpu_affinity_mismatch:{role}")
        if final.get("requested_socket_buffer_bytes") != config["traffic"][
            "socket_buffer_request_bytes"
        ]:
            reasons.append(f"process_socket_buffer_request_mismatch:{role}")
        buffers = final.get("actual_socket_buffers")
        if not isinstance(buffers, dict) or any(
            not _nonnegative_int(buffers.get(key)) or buffers.get(key) <= 0
            for key in ("receive_bytes", "send_bytes")
        ):
            reasons.append(f"process_socket_buffer_evidence_invalid:{role}")
    if set(finals) != expected_roles:
        return sorted(set(reasons))

    receiver = finals["receiver"]
    benign = finals["benign_sender"]
    suspicious = finals["suspicious_sender"]
    if receiver.get("role") != "receiver" or receiver.get("final") is not True:
        reasons.append("receiver_role_or_final_mismatch")
    if receiver.get("packet_size_bytes") != config["traffic"]["packet_payload_bytes"]:
        reasons.append("receiver_packet_size_mismatch")
    start_ns = record.get("traffic_start_monotonic_ns")
    warmup_end_ns = start_ns + int(round(trial["warmup_s"] * 1e9)) if _nonnegative_int(start_ns) else None
    measurement_end_ns = (
        warmup_end_ns + int(round(trial["measurement_s"] * 1e9))
        if warmup_end_ns is not None
        else None
    )
    drain_end_ns = (
        measurement_end_ns + int(round(trial["drain_s"] * 1e9))
        if measurement_end_ns is not None
        else None
    )
    for role, final in finals.items():
        if (
            final.get("start_monotonic_ns") != start_ns
            or final.get("warmup_end_monotonic_ns") != warmup_end_ns
            or final.get("measurement_end_monotonic_ns") != measurement_end_ns
        ):
            reasons.append(f"process_phase_boundary_mismatch:{role}")
        if (
            not _nonnegative_int(final.get("end_monotonic_ns"))
            or drain_end_ns is None
            or final["end_monotonic_ns"] < drain_end_ns
        ):
            reasons.append(f"process_ended_before_drain:{role}")
    barrier_writes = record.get("start_barrier", {}).get(
        "per_process_write_monotonic_ns", {}
    )
    ready_evidence = record.get("process_ready", {})
    for role, final in finals.items():
        receipt_ns = final.get("start_signal_received_monotonic_ns")
        ready_ns = ready_evidence.get(role, {}).get("monotonic_ns")
        write_ns = (
            barrier_writes.get(role)
            if isinstance(barrier_writes, dict)
            else None
        )
        if (
            not _nonnegative_int(receipt_ns)
            or not _nonnegative_int(ready_ns)
            or not _nonnegative_int(write_ns)
            or receipt_ns < ready_ns
            or not _nonnegative_int(start_ns)
            or receipt_ns >= start_ns
        ):
            reasons.append(f"process_start_signal_receipt_invalid:{role}")
    reasons.extend(_receiver_raw_errors(config, receiver))
    reasons.extend(_sender_raw_errors(config, profile, trial, "benign", benign))
    reasons.extend(
        _sender_raw_errors(config, profile, trial, "suspicious", suspicious)
    )
    if trial["regime"] in {"borrowable_overload", "both_saturated"}:
        minimum_offered = profile["validity"][
            "minimum_overload_offered_fraction"
        ]
        for label, sender in (("benign", benign), ("suspicious", suspicious)):
            planned = sender.get("planned_packets", {}).get("measurement")
            sent = sender.get("sent", {}).get("measurement", {}).get("packets")
            if (
                not _nonnegative_int(planned)
                or planned == 0
                or not _nonnegative_int(sent)
                or sent / planned < minimum_offered
            ):
                reasons.append(f"overload_offered_fraction_gate:{label}")
    if snapshots:
        recomputed_reconciliation = recompute_counter_reconciliation(
            config, profile, receiver, benign, suspicious, snapshots
        )
        if record.get("counter_reconciliation") != recomputed_reconciliation:
            reasons.append("stored_counter_reconciliation_differs_from_raw")
        if record.get("counter_reconciliation_errors") != recomputed_reconciliation[
            "errors"
        ]:
            reasons.append("stored_counter_reconciliation_error_list_mismatch")

    # Independent application/qdisc conservation over both the primary
    # arrival window and complete arm.  The frozen absolute tolerance covers
    # snapshot-boundary races; the byte equality itself is exact.
    if snapshots:
        packet_unit = config["traffic"]["accounting"][
            "configured_qdisc_accounted_bytes_per_packet"
        ]
        tolerance = profile["validity"][
            "qdisc_packet_conservation_absolute_tolerance"
        ]
        measurement_sender_success = sum(
            sender["sent"]["measurement"]["packets"]
            for sender in (benign, suspicious)
        )
        measurement_tolerance = max(
            tolerance,
            math.ceil(
                measurement_sender_success
                * profile["validity"]["counter_reconciliation_relative_tolerance"]
            ),
        )
        measurement_packets = _tc_record_delta(
            snapshots["measurement_start"],
            snapshots["measurement_end"],
            "qdisc",
            "1:",
            "packets",
        )
        measurement_bytes = _tc_record_delta(
            snapshots["measurement_start"],
            snapshots["measurement_end"],
            "qdisc",
            "1:",
            "bytes",
        )
        measurement_arrivals = sum(
            receiver["counts_by_arrival_window"]["measurement"][
                f"{label}_packets"
            ]
            for label in ("benign", "suspicious")
        )
        if measurement_packets is None or measurement_bytes is None:
            reasons.append("qdisc_measurement_counter_missing")
        else:
            if abs(measurement_packets - measurement_arrivals) > measurement_tolerance:
                reasons.append("qdisc_measurement_arrival_conservation")
            if measurement_packets > measurement_sender_success + measurement_tolerance:
                reasons.append("qdisc_measurement_sender_conservation")
            if measurement_bytes != measurement_packets * packet_unit:
                reasons.append("qdisc_measurement_byte_unit_mismatch")
        root_arm = {
            name: _tc_record_delta(
                snapshots["arm_start"], snapshots["arm_end"], "qdisc", "1:", name
            )
            for name in ("packets", "bytes", "drops")
        }
        sent_arm = sum(
            sender["sent"][phase]["packets"]
            for sender in (benign, suspicious)
            for phase in ("warmup", "measurement")
        )
        arrival_arm = sum(
            counter[f"{label}_packets"]
            for counter in receiver["counts_by_arrival_window"].values()
            for label in ("benign", "suspicious")
        )
        if any(value is None for value in root_arm.values()):
            reasons.append("qdisc_arm_counter_missing")
        else:
            if abs(root_arm["packets"] + root_arm["drops"] - sent_arm) > tolerance:
                reasons.append("qdisc_arm_send_conservation")
            if abs(root_arm["packets"] - arrival_arm) > tolerance:
                reasons.append("qdisc_arm_arrival_conservation")
            if root_arm["bytes"] != root_arm["packets"] * packet_unit:
                reasons.append("qdisc_arm_byte_unit_mismatch")
        for name in ("packets", "bytes", "drops"):
            leaf_values = [
                _tc_record_delta(
                    snapshots["arm_start"],
                    snapshots["arm_end"],
                    "qdisc",
                    handle,
                    name,
                )
                for handle in ("10:", "20:")
            ]
            class_values = [
                _tc_record_delta(
                    snapshots["arm_start"],
                    snapshots["arm_end"],
                    "class",
                    classid,
                    name,
                )
                for classid in ("1:10", "1:20")
            ]
            if root_arm[name] is None or any(value is None for value in leaf_values):
                reasons.append(f"qdisc_leaf_counter_missing:{name}")
            elif sum(leaf_values) != root_arm[name]:
                reasons.append(f"qdisc_leaf_root_conservation:{name}")
            if root_arm[name] is None or any(value is None for value in class_values):
                reasons.append(f"qdisc_child_class_counter_missing:{name}")
            elif sum(class_values) != root_arm[name]:
                reasons.append(f"qdisc_child_class_root_conservation:{name}")
        for boundary in ("arm_start", "arm_end"):
            backlog = _tc_record_counter(snapshots[boundary], "qdisc", "1:", "backlog")
            if backlog != 0:
                reasons.append(f"qdisc_nonzero_root_backlog:{boundary}")
        for boundary in TC_SNAPSHOT_NAMES:
            root_backlog = _tc_record_counter(
                snapshots[boundary], "qdisc", "1:", "backlog"
            )
            leaf_backlogs = [
                _tc_record_counter(snapshots[boundary], "qdisc", handle, "backlog")
                for handle in ("10:", "20:")
            ]
            if root_backlog is None or any(value is None for value in leaf_backlogs):
                reasons.append(f"qdisc_backlog_counter_missing:{boundary}")
            elif sum(leaf_backlogs) != root_backlog:
                reasons.append(f"qdisc_backlog_leaf_sum:{boundary}")

    # Ready handshakes are primitive evidence; all three must precede the
    # common start by the frozen lead.  The runner records them under this
    # canonical mapping once all processes have completed socket setup.
    ready_records = record.get("process_ready")
    if not isinstance(ready_records, dict) or set(ready_records) != expected_roles:
        reasons.append("all_process_ready_evidence_missing")
    else:
        start_ns = record.get("traffic_start_monotonic_ns")
        minimum_lead_ns = int(
            round(profile["timing"]["minimum_all_process_ready_lead_s"] * 1e9)
        )
        expected_ready_fields = {
            "receiver": {
                "role": "receiver",
                "bind_ip": config["network"]["server_ip"],
                "port": config["network"]["receiver_port"],
                "cpu_affinity": [assignment["receiver"]],
            },
            "benign_sender": {
                "role": "sender",
                "traffic_class": "benign",
                "bind_ip": config["network"]["client_ip"],
                "source_port": config["network"]["benign_source_port"],
                "cpu_affinity": [assignment["benign_sender"]],
                "rtt_probe_rate_pps": trial["benign_rtt_probe_rate_pps"],
            },
            "suspicious_sender": {
                "role": "sender",
                "traffic_class": "suspicious",
                "bind_ip": config["network"]["client_ip"],
                "source_port": config["network"]["suspicious_source_port"],
                "cpu_affinity": [assignment["suspicious_sender"]],
                "rtt_probe_rate_pps": 0.0,
            },
        }
        for role, ready in ready_records.items():
            ready_ns = ready.get("monotonic_ns") if isinstance(ready, dict) else None
            if (
                not _nonnegative_int(start_ns)
                or not _nonnegative_int(ready_ns)
                or start_ns - ready_ns < minimum_lead_ns
            ):
                reasons.append(f"process_ready_lead_gate:{role}")
            if (
                not isinstance(ready, dict)
                or ready.get("event") != "ready"
                or any(
                    ready.get(key) != value
                    for key, value in expected_ready_fields[role].items()
                )
            ):
                reasons.append(f"process_ready_identity_mismatch:{role}")
        barrier = record.get("start_barrier")
        ready_times = {
            role: (
                ready_records[role].get("monotonic_ns")
                if isinstance(ready_records[role], dict)
                else None
            )
            for role in expected_roles
        }
        if not isinstance(barrier, dict):
            reasons.append("post_readiness_start_barrier_missing")
        else:
            all_ready_ns = barrier.get("all_ready_monotonic_ns")
            selected_ns = barrier.get("start_selected_monotonic_ns")
            write_times = barrier.get("per_process_write_monotonic_ns")
            selected_lead_ns = int(
                round(profile["timing"]["process_start_lead_s"] * 1e9)
            )
            if (
                not all(_nonnegative_int(value) for value in ready_times.values())
                or not _nonnegative_int(all_ready_ns)
                or all_ready_ns < max(ready_times.values())
                or all_ready_ns != record.get("process_launch_complete_monotonic_ns")
                or not _nonnegative_int(selected_ns)
                or selected_ns < all_ready_ns
                or selected_ns < max(ready_times.values())
                or barrier.get("selected_only_after_all_ready") is not True
                or selected_ns + selected_lead_ns != start_ns
                or barrier.get("start_record")
                != {"event": "start", "start_monotonic_ns": start_ns}
                or not isinstance(write_times, dict)
                or set(write_times) != expected_roles
                or not all(
                    _nonnegative_int(value) and selected_ns <= value < start_ns
                    for value in (write_times.values() if isinstance(write_times, dict) else [])
                )
            ):
                reasons.append("post_readiness_start_barrier_invalid")

    reasons.extend(
        _stored_validity_evidence_errors(
            record, profile, benign, suspicious, receiver
        )
    )

    stored_reconciliation = record.get("counter_reconciliation")
    if not isinstance(stored_reconciliation, dict) or stored_reconciliation.get(
        "errors"
    ) != []:
        reasons.append("stored_counter_reconciliation_not_clean")
    return sorted(set(reasons))


def validate_pair(
    config: dict[str, Any],
    pair_id: str,
    arms: dict[str, dict[str, Any]],
    *,
    independently_validate_raw: bool = False,
    authenticated_profile: dict[str, Any] | None = None,
) -> list[str]:
    reasons: list[str] = []
    if set(arms) != set(ARM_IDS):
        return [f"pair has arms {sorted(arms)}, expected {list(ARM_IDS)}"]
    b3, b5 = arms["B3"], arms["B5"]
    if independently_validate_raw:
        if authenticated_profile is None:
            raise ValueError(
                "independent pair validation requires authenticated plan profile"
            )
        profile = _require_authenticated_profile(config, authenticated_profile)
        for arm_id, arm in (("B3", b3), ("B5", b5)):
            raw_reasons = recompute_arm_invalid_reasons(
                config,
                arm["trial"],
                arm,
                authenticated_profile=profile,
            )
            recomputed_valid = not raw_reasons
            if arm.get("valid") is not recomputed_valid:
                reasons.append(f"{arm_id}:stored_validity_disagrees_with_raw_evidence")
            if recomputed_valid and arm.get("invalid_reasons") != []:
                reasons.append(f"{arm_id}:valid_arm_has_stored_invalid_reasons")
            if not recomputed_valid and not arm.get("invalid_reasons"):
                reasons.append(f"{arm_id}:invalid_arm_has_no_stored_invalid_reason")
            reasons.extend(f"{arm_id}:{reason}" for reason in raw_reasons)
    elif not b3.get("valid") or not b5.get("valid"):
        for arm_id, arm in (("B3", b3), ("B5", b5)):
            for reason in arm.get("invalid_reasons", ["valid flag is false"]):
                reasons.append(f"{arm_id}:{reason}")
    if _without_arm_fields(b3["trial"]) != _without_arm_fields(b5["trial"]):
        reasons.append("paired trial factors or offered schedule differ")
    for arm_id, arm in arms.items():
        if arm.get("schema_version") != ARM_SCHEMA_VERSION:
            reasons.append(f"{arm_id}:unexpected arm schema")
        if arm["trial"].get("pair_id") != pair_id:
            reasons.append(f"{arm_id}:pair id mismatch")
        if arm.get("tc_requested_spec") != requested_tc_spec(
            config, arm_id, arm["trial"]["reservation_id"]
        ):
            reasons.append(f"{arm_id}:requested tc spec differs from frozen config")
    if b3.get("cpu_assignment") != b5.get("cpu_assignment"):
        reasons.append("process CPU affinity differs within pair")
    process_match_fields = {
        "receiver": (
            "packet_size_bytes",
            "requested_socket_buffer_bytes",
            "actual_socket_buffers",
            "cpu_affinity",
        ),
        "benign_sender": (
            "seed",
            "tos",
            "source_port",
            "target_port",
            "target_rate_pps",
            "packet_size_bytes",
            "schedule_offset_ns",
            "planned_packets",
            "missed_deadline_policy",
            "rtt_probe_policy",
            "requested_socket_buffer_bytes",
            "actual_socket_buffers",
            "cpu_affinity",
        ),
        "suspicious_sender": (
            "seed",
            "tos",
            "source_port",
            "target_port",
            "target_rate_pps",
            "packet_size_bytes",
            "schedule_offset_ns",
            "planned_packets",
            "missed_deadline_policy",
            "rtt_probe_policy",
            "requested_socket_buffer_bytes",
            "actual_socket_buffers",
            "cpu_affinity",
        ),
    }
    for role, fields in process_match_fields.items():
        b3_record = b3.get("processes", {}).get(role, {}).get("final_record", {})
        b5_record = b5.get("processes", {}).get(role, {}).get("final_record", {})
        for field in fields:
            if b3_record.get(field) != b5_record.get(field):
                reasons.append(f"{role} matched field differs: {field}")
    if independently_validate_raw:
        count_tolerance = profile["validity"][
            "maximum_within_pair_sent_count_relative_difference"
        ]
        lateness_tolerance = profile["validity"][
            "maximum_within_pair_lateness_p99_difference_ns"
        ]
        for label in ("benign", "suspicious"):
            role = f"{label}_sender"
            left_sender = b3["processes"][role]["final_record"]
            right_sender = b5["processes"][role]["final_record"]
            rate = b3["trial"][f"{label}_target_pps"]
            offset = _schedule_offset_ns(
                b3["trial"]["traffic_seed"], label, rate
            )
            planned_warmup = _planned_packet_count(
                b3["trial"]["warmup_s"], rate, offset
            )
            planned_total = _planned_packet_count(
                b3["trial"]["warmup_s"] + b3["trial"]["measurement_s"],
                rate,
                offset,
            )
            maximum_by_phase = {
                "warmup": planned_warmup,
                "measurement": planned_total - planned_warmup,
            }
            for phase in ("warmup", "measurement"):
                left_count = left_sender["sent"][phase]["packets"]
                right_count = right_sender["sent"][phase]["packets"]
                denominator = max(
                    left_count,
                    right_count,
                    1,
                )
                if abs(left_count - right_count) / denominator > count_tolerance:
                    reasons.append(
                        f"within_pair_sent_count_gate:{label}:{phase}"
                    )
                decoded_pair = []
                decode_failed = False
                for arm_id, sender, count in (
                    ("B3", left_sender, left_count),
                    ("B5", right_sender, right_count),
                ):
                    samples, sample_errors = _decode_lateness_samples(
                        sender.get("send_lateness_samples_by_phase", {}).get(phase),
                        expected_sample_count=count,
                        maximum_sample_count=maximum_by_phase[phase],
                        label=f"within_pair:{arm_id}:{label}:{phase}",
                    )
                    reasons.extend(sample_errors)
                    if samples is None:
                        decode_failed = True
                    else:
                        decoded_pair.append(samples)
                if decode_failed:
                    continue
                left_p99, right_p99 = (
                    nearest_rank(samples, 0.99) if samples else None
                    for samples in decoded_pair
                )
                if (left_p99 is None) != (right_p99 is None):
                    reasons.append(
                        f"within_pair_lateness_presence_gate:{label}:{phase}"
                    )
                elif left_p99 is not None and abs(left_p99 - right_p99) > lateness_tolerance:
                    reasons.append(
                        f"within_pair_lateness_p99_gate:{label}:{phase}"
                    )
        expected_tc_differences = {
            "classes.1:10.ceil_Bps",
            "classes.1:20.ceil_Bps",
        }
        for snapshot_name in TC_SNAPSHOT_NAMES:
            try:
                left = normalize_live_tc(b3["tc_snapshots"][snapshot_name])
                right = normalize_live_tc(b5["tc_snapshots"][snapshot_name])
                differences = normalized_tc_pair_differences(left, right)
            except (KeyError, TypeError, ValueError) as error:
                reasons.append(f"tc_pair_equivalence:{snapshot_name}:unparseable:{error}")
                continue
            if differences != expected_tc_differences:
                reasons.append(
                    f"tc_pair_equivalence:{snapshot_name}:unexpected_differences:"
                    f"{','.join(sorted(differences))}"
                )
    return sorted(set(reasons))


def recompute_pair_fidelity(
    plan: dict[str, Any], arms: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Independently reproduce the campaign's matched-offer fidelity ledger."""

    arms_by_trial_id = {
        arm.get("trial", {}).get("trial_id"): arm
        for arm in arms
        if isinstance(arm, dict)
    }
    count_tolerance = plan["profile"]["validity"][
        "maximum_within_pair_sent_count_relative_difference"
    ]
    lateness_tolerance = plan["profile"]["validity"][
        "maximum_within_pair_lateness_p99_difference_ns"
    ]
    results = []
    for pair in plan["pairs"]:
        pair_id = pair["pair_id"]
        pair_arms = {
            arm_id: arms_by_trial_id.get(f"{pair_id}_{arm_id}")
            for arm_id in ARM_IDS
        }
        errors: list[str] = []
        comparisons: dict[str, Any] = {}
        if any(arm is None for arm in pair_arms.values()):
            errors.append("missing_arm_record")
        elif any(
            "processes" not in arm
            for arm in pair_arms.values()
            if arm is not None
        ):
            errors.append("arm_has_no_process_evidence")
        else:
            for label, role in (
                ("benign", "benign_sender"),
                ("suspicious", "suspicious_sender"),
            ):
                rate = pair[f"{label}_target_pps"]
                offset = _schedule_offset_ns(pair["traffic_seed"], label, rate)
                planned_warmup = _planned_packet_count(
                    pair["warmup_s"], rate, offset
                )
                planned_total = _planned_packet_count(
                    pair["warmup_s"] + pair["measurement_s"], rate, offset
                )
                maximum_by_phase = {
                    "warmup": planned_warmup,
                    "measurement": planned_total - planned_warmup,
                }
                for phase in ("warmup", "measurement"):
                    values = {}
                    for arm_id in ARM_IDS:
                        assert pair_arms[arm_id] is not None
                        sender = pair_arms[arm_id]["processes"][role]["final_record"]
                        sent_packets = (
                            sender.get("sent", {}).get(phase, {}).get("packets")
                        )
                        recomputed_p99 = None
                        sample_sha256 = None
                        if _nonnegative_int(sent_packets):
                            samples, sample_errors = _decode_lateness_samples(
                                sender.get(
                                    "send_lateness_samples_by_phase", {}
                                ).get(phase),
                                expected_sample_count=sent_packets,
                                maximum_sample_count=maximum_by_phase[phase],
                                label=f"pair_fidelity:{arm_id}:{label}:{phase}",
                            )
                            if sample_errors:
                                errors.append(
                                    f"{label}_{phase}_{arm_id}_lateness_samples:"
                                    "ValueError"
                                )
                            else:
                                assert samples is not None
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
                    sent_values = [values[arm]["sent_packets"] for arm in ARM_IDS]
                    if not all(
                        _nonnegative_int(value)
                        for value in sent_values
                    ):
                        errors.append(f"{label}_{phase}_sent_counter_missing")
                        sent_difference = None
                    else:
                        sent_difference = abs(sent_values[1] - sent_values[0]) / max(
                            1, max(sent_values)
                        )
                        if sent_difference > count_tolerance:
                            errors.append(f"{label}_{phase}_sent_count_difference")
                    lateness_values = [
                        values[arm]["lateness_p99_ns"] for arm in ARM_IDS
                    ]
                    if all(value is None for value in lateness_values):
                        lateness_difference = 0
                    elif all(
                        isinstance(value, int) and not isinstance(value, bool)
                        for value in lateness_values
                    ):
                        lateness_difference = abs(
                            lateness_values[1] - lateness_values[0]
                        )
                        if lateness_difference > lateness_tolerance:
                            errors.append(f"{label}_{phase}_lateness_difference")
                    else:
                        lateness_difference = None
                        errors.append(f"{label}_{phase}_lateness_counter_missing")
                    comparisons[f"{label}.{phase}"] = {
                        "arms": values,
                        "sent_count_relative_difference": sent_difference,
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
    require_finite_tree(results)
    return results


def _verify_campaign(
    result_dir: Path,
    config: dict[str, Any],
    plan: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    campaign = read_json(result_dir / "campaign_manifest.json")
    if campaign.get("schema_version") != CAMPAIGN_SCHEMA_VERSION:
        raise ValueError("unexpected campaign manifest schema")
    payload_hash = campaign.get("campaign_manifest_payload_sha256")
    campaign_payload = {
        key: value
        for key, value in campaign.items()
        if key != "campaign_manifest_payload_sha256"
    }
    if payload_hash != object_sha256(campaign_payload):
        raise ValueError("campaign manifest payload hash mismatch")
    if campaign.get("study_id") != config["study_id"]:
        raise ValueError("campaign study id mismatch")
    if campaign.get("profile") != plan["profile"]["name"]:
        raise ValueError("campaign profile mismatch")
    if campaign.get("evidentiary") is not plan["profile"]["evidentiary"]:
        raise ValueError("campaign evidentiary flag mismatch")
    expected_privacy_scan = {
        "forbidden_identifier_classes": [
            "project_root",
            "account_home",
            "hostname",
        ],
        "violations": [],
        "passed": True,
    }
    if campaign.get("privacy_scan") != expected_privacy_scan:
        raise ValueError("campaign privacy scan did not pass exactly")
    if campaign["config_object_sha256"] != object_sha256(config):
        raise ValueError("campaign config object hash mismatch")
    if campaign["config_file_sha256"] != file_sha256(result_dir / "config.json"):
        raise ValueError("copied config file hash mismatch")
    if read_json(result_dir / "config.json") != config:
        raise ValueError("copied config differs from frozen config")
    if campaign["protocol_sha256"] != config["protocol_sha256"]:
        raise ValueError("campaign protocol hash mismatch")
    if file_sha256(result_dir / "protocol.md") != config["protocol_sha256"]:
        raise ValueError("copied protocol hash mismatch")
    if read_json(result_dir / "execution_plan.json") != plan:
        raise ValueError("execution plan differs from deterministic frozen plan")
    if campaign["plan_sha256"] != plan["plan_sha256"]:
        raise ValueError("campaign plan hash mismatch")
    if not campaign["setup_success"] or not campaign["teardown_success"]:
        raise ValueError("campaign setup/teardown gate did not pass")
    if campaign["campaign_error"] is not None:
        raise ValueError(f"campaign ended with an error: {campaign['campaign_error']}")

    raw_entries = campaign["raw_files"]
    if not isinstance(raw_entries, list):
        raise ValueError("campaign raw_files is not a list")
    raw_entry_keys = {
        "trial_id",
        "path",
        "size_bytes",
        "sha256",
        "valid",
        "invalid_reasons",
    }
    if any(not isinstance(entry, dict) or set(entry) != raw_entry_keys for entry in raw_entries):
        raise ValueError("campaign raw file entry has an unexpected shape")
    verify_manifest_files(result_dir, raw_entries)
    if campaign["planned_arm_count"] != len(plan["trials"]):
        raise ValueError("planned arm count differs from frozen plan")
    if campaign["recorded_arm_count"] != len(raw_entries):
        raise ValueError("recorded arm count disagrees with raw manifest")
    expected_ordered_paths = [
        f"raw/{trial['trial_id']}.json" for trial in plan["trials"]
    ]
    expected_paths = set(expected_ordered_paths)
    actual_paths = {entry["path"] for entry in raw_entries}
    if [entry.get("path") for entry in raw_entries] != expected_ordered_paths:
        raise ValueError("raw manifest order differs from frozen execution plan")
    disk_paths = {
        path.relative_to(result_dir).as_posix()
        for path in (result_dir / "raw").glob("*.json")
    }
    if actual_paths != expected_paths or disk_paths != expected_paths:
        raise ValueError("raw arm set is missing, extra, or not the frozen plan")
    inventory = read_json(result_dir / "campaign_inventory.json")
    if inventory.get("schema_version") != FINAL_MANIFEST_SCHEMA_VERSION:
        raise ValueError("unexpected campaign inventory schema")
    if inventory.get("root_name") != result_dir.name:
        raise ValueError("campaign inventory root name mismatch")
    if not isinstance(inventory.get("files"), list) or any(
        not isinstance(entry, dict)
        or set(entry) != {"path", "size_bytes", "sha256"}
        for entry in inventory.get("files", [])
    ):
        raise ValueError("campaign inventory entry shape mismatch")
    if [entry["path"] for entry in inventory["files"]] != sorted(
        entry["path"] for entry in inventory["files"]
    ):
        raise ValueError("campaign inventory path order is not canonical")
    verify_manifest_files(result_dir, inventory["files"])
    if inventory.get("file_count") != len(inventory["files"]):
        raise ValueError("campaign inventory file_count mismatch")
    if inventory.get("content_fingerprint_sha256") != object_sha256(
        inventory["files"]
    ):
        raise ValueError("campaign inventory fingerprint mismatch")
    declared_campaign_paths = {entry["path"] for entry in inventory["files"]}
    actual_campaign_paths = {
        path.relative_to(result_dir).as_posix()
        for path in result_dir.rglob("*")
        if path.is_file()
        and path.relative_to(result_dir).as_posix() != "campaign_inventory.json"
        and path.relative_to(result_dir).as_posix() != "manifest.json"
        and not path.relative_to(result_dir).as_posix().startswith("analysis/")
    }
    if declared_campaign_paths != actual_campaign_paths:
        raise ValueError("campaign inventory has an undeclared or missing file")

    source_entries = read_json(result_dir / "source_hashes.json")
    if not isinstance(source_entries, list):
        raise ValueError("source hash payload is not a list")
    if any(
        not isinstance(entry, dict)
        or set(entry) != {"path", "sha256", "size_bytes"}
        for entry in source_entries
    ):
        raise ValueError("source hash entry has an unexpected shape")
    if [entry.get("path") for entry in source_entries] != list(
        FROZEN_SOURCE_RELATIVE_PATHS
    ):
        raise ValueError("source hash set/order is not the exact canonical source set")
    if object_sha256(source_entries) != campaign["source_hashes_sha256"]:
        raise ValueError("source hash list payload mismatch")
    for entry in source_entries:
        source = PROJECT_ROOT / entry["path"]
        if (
            not source.is_file()
            or source.stat().st_size != entry["size_bytes"]
            or file_sha256(source) != entry["sha256"]
        ):
            raise ValueError(f"analysis source drift: {entry['path']}")
    arms = [read_json(result_dir / entry["path"]) for entry in raw_entries]
    expected_provenance = {
        "config_file": {
            "path": "config.json",
            "sha256": file_sha256(result_dir / "config.json"),
        },
        "config_object_sha256": object_sha256(config),
        "protocol_file": {
            "path": "protocol.md",
            "sha256": file_sha256(result_dir / "protocol.md"),
        },
        "execution_plan_file": {
            "path": "execution_plan.json",
            "sha256": file_sha256(result_dir / "execution_plan.json"),
            "plan_payload_sha256": plan["plan_sha256"],
        },
        "source_hashes_file": {
            "path": "source_hashes.json",
            "sha256": file_sha256(result_dir / "source_hashes.json"),
            "payload_sha256": object_sha256(source_entries),
        },
        "environment_file": {
            "path": "environment.json",
            "sha256": file_sha256(result_dir / "environment.json"),
        },
    }
    if campaign.get("environment_file_sha256") != expected_provenance["environment_file"]["sha256"]:
        raise ValueError("campaign environment hash mismatch")
    _verify_environment(config, read_json(result_dir / "environment.json"))
    plan_by_id = {trial["trial_id"]: trial for trial in plan["trials"]}
    valid_arm_count = 0
    for entry, arm in zip(raw_entries, arms, strict=True):
        trial_id = arm.get("trial", {}).get("trial_id")
        if trial_id not in plan_by_id or arm["trial"] != plan_by_id[trial_id]:
            raise ValueError(f"raw trial metadata differs from plan: {trial_id}")
        if arm.get("provenance") != expected_provenance:
            raise ValueError(f"raw provenance mismatch: {trial_id}")
        if entry.get("trial_id") != trial_id:
            raise ValueError(f"raw manifest trial id mismatch: {trial_id}")
        if entry.get("valid") is not arm.get("valid"):
            raise ValueError(f"raw manifest valid flag mismatch: {trial_id}")
        if entry.get("invalid_reasons") != arm.get("invalid_reasons"):
            raise ValueError(f"raw manifest invalid reasons mismatch: {trial_id}")
        if arm.get("valid") is True:
            valid_arm_count += 1
        require_finite_tree(arm)
    if campaign.get("valid_arm_count") != valid_arm_count:
        raise ValueError("campaign valid_arm_count mismatch")
    if campaign.get("invalid_arm_count") != len(arms) - valid_arm_count:
        raise ValueError("campaign invalid_arm_count mismatch")
    pair_fidelity = recompute_pair_fidelity(plan, arms)
    if campaign.get("pair_fidelity") != pair_fidelity:
        raise ValueError("campaign pair-fidelity ledger differs from raw recomputation")
    pair_fidelity_error_count = sum(not item["passed"] for item in pair_fidelity)
    if campaign.get("pair_fidelity_error_count") != pair_fidelity_error_count:
        raise ValueError("campaign pair-fidelity error count mismatch")
    setup = read_json(result_dir / "setup.json")
    teardown = read_json(result_dir / "teardown.json")
    if campaign["setup_success"] is not bool(setup.get("success")):
        raise ValueError("campaign/setup success mismatch")
    if campaign["teardown_success"] is not bool(teardown.get("success")):
        raise ValueError("campaign/teardown success mismatch")
    return campaign, arms


def _summary(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"n": 0}
    return {
        "n": len(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "minimum": min(values),
        "maximum": max(values),
    }


def _fmt(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float):
        return format(value, ".12g")
    return str(value)


def _pair_csv_columns() -> list[str]:
    columns = [
        "pair_id",
        "analysis_family",
        "regime",
        "measurement_s",
        "block",
        "reservation_id",
        "fast_reservation_fraction",
        "suspicious_reservation_fraction",
        "fast_reserved_Bps",
        "suspicious_reserved_Bps",
        "fast_bfifo_bytes",
        "suspicious_bfifo_bytes",
        "valid_pair",
        "invalid_reasons",
        "B3_benign_offered_fraction",
        "B5_benign_offered_fraction",
        "B3_suspicious_offered_fraction",
        "B5_suspicious_offered_fraction",
        "B3_root_qdisc_drops",
        "B5_root_qdisc_drops",
        "B3_root_qdisc_accounted_bytes",
        "B5_root_qdisc_accounted_bytes",
        "B3_root_qdisc_accounted_Bps",
        "B5_root_qdisc_accounted_Bps",
    ]
    for endpoint in ENDPOINTS:
        columns.extend((f"B3_{endpoint}", f"B5_{endpoint}", f"effect_{endpoint}"))
    return columns


def _pairs_csv_bytes(rows: list[dict[str, Any]]) -> bytes:
    columns = _pair_csv_columns()
    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: _fmt(row.get(key)) for key in columns})
    return handle.getvalue().encode("utf-8")


def _write_pairs_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("x", encoding="utf-8", newline="") as handle:
        handle.write(_pairs_csv_bytes(rows).decode("utf-8"))


def _write_new_json_atomically(path: Path, value: Any) -> None:
    """Atomically publish a create-only JSON file on the same filesystem."""

    descriptor, temporary_text = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_text)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, sort_keys=True, indent=2, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        # Hard-link publication is atomic and fails rather than replacing a
        # concurrently created evidence manifest.
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _recompute_analysis(
    config: dict[str, Any],
    plan: dict[str, Any],
    campaign: dict[str, Any],
    arms: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Recompute every derived analysis artifact solely from authenticated raw data."""

    profile_name = campaign["profile"]
    grouped: dict[str, dict[str, dict[str, Any]]] = {}
    duplicate_arm_records = []
    for arm in arms:
        trial = arm["trial"]
        pair = grouped.setdefault(trial["pair_id"], {})
        if trial["arm_id"] in pair:
            duplicate_arm_records.append(trial["trial_id"])
        pair[trial["arm_id"]] = arm
    if duplicate_arm_records:
        raise ValueError(f"duplicate raw arm records: {duplicate_arm_records}")

    pair_rows: list[dict[str, Any]] = []
    invalid_pairs: list[dict[str, Any]] = []
    valid_effects: dict[str, dict[str, list[float]]] = {}
    expected_pair_ids = {pair["pair_id"] for pair in plan["pairs"]}
    if set(grouped) != expected_pair_ids:
        raise ValueError("raw pair set differs from frozen plan")
    for pair in sorted(plan["pairs"], key=lambda item: item["pair_order"]):
        pair_id = pair["pair_id"]
        pair_arms = grouped[pair_id]
        reasons = validate_pair(
            config,
            pair_id,
            pair_arms,
            independently_validate_raw=True,
            authenticated_profile=plan["profile"],
        )
        row: dict[str, Any] = {
            "pair_id": pair_id,
            "analysis_family": pair["analysis_family"],
            "regime": pair["regime"],
            "measurement_s": pair["measurement_s"],
            "block": pair["block"],
            "reservation_id": pair["reservation_id"],
            "fast_reservation_fraction": pair["fast_reservation_fraction"],
            "suspicious_reservation_fraction": pair["suspicious_reservation_fraction"],
            "fast_reserved_Bps": pair["fast_reserved_Bps"],
            "suspicious_reserved_Bps": pair["suspicious_reserved_Bps"],
            "fast_bfifo_bytes": pair["fast_bfifo_bytes"],
            "suspicious_bfifo_bytes": pair["suspicious_bfifo_bytes"],
            "valid_pair": not reasons,
            "invalid_reasons": "|".join(reasons),
        }
        if reasons:
            invalid_pairs.append(
                {
                    "pair_id": pair_id,
                    "analysis_family": pair["analysis_family"],
                    "regime": pair["regime"],
                    "block": pair["block"],
                    "reasons": reasons,
                }
            )
        else:
            endpoints_by_arm = {
                arm_id: derive_endpoints(pair_arms[arm_id]) for arm_id in ARM_IDS
            }
            family_key = (
                f"{pair['analysis_family']}|{pair['regime']}|"
                f"{float(pair['measurement_s']):.9g}|{pair['reservation_id']}"
            )
            family_effects = valid_effects.setdefault(
                family_key, {endpoint: [] for endpoint in ENDPOINTS}
            )
            for endpoint in ENDPOINTS:
                row[f"B3_{endpoint}"] = endpoints_by_arm["B3"][endpoint]
                row[f"B5_{endpoint}"] = endpoints_by_arm["B5"][endpoint]
                effect = (
                    endpoints_by_arm["B5"][endpoint]
                    - endpoints_by_arm["B3"][endpoint]
                )
                row[f"effect_{endpoint}"] = effect
                family_effects[endpoint].append(effect)
            for arm_id in ARM_IDS:
                arm = pair_arms[arm_id]
                row[f"{arm_id}_benign_offered_fraction"] = offered_fraction(
                    arm, "benign"
                )
                row[f"{arm_id}_suspicious_offered_fraction"] = offered_fraction(
                    arm, "suspicious"
                )
                row[f"{arm_id}_root_qdisc_drops"] = measurement_drop_delta(arm)
                qdisc = measurement_qdisc_accounting(arm)
                row[f"{arm_id}_root_qdisc_accounted_bytes"] = (
                    qdisc["bytes"] if qdisc else None
                )
                row[f"{arm_id}_root_qdisc_accounted_Bps"] = (
                    qdisc["Bps"] if qdisc else None
                )
        pair_rows.append(row)

    primary_key = (
        f"standard|{config['statistics']['primary_regime']}|"
        f"{float(config['statistics']['primary_measurement_s']):.9g}|"
        f"{config['service']['primary_reservation_id']}"
    )
    primary_effects = valid_effects.get(
        primary_key, {endpoint: [] for endpoint in ENDPOINTS}
    )
    endpoint_config = {
        endpoint["id"]: endpoint
        for endpoint in config["statistics"]["primary_endpoints"]
    }
    primary_results = {}
    sign_tests = {}
    for endpoint in ENDPOINTS:
        values = primary_effects[endpoint]
        if values:
            stable_seed = (
                config["statistics"]["bootstrap_seed"]
                + int.from_bytes(
                    hashlib.sha256(endpoint.encode("ascii")).digest()[:4], "big"
                )
            )
            ci_low, ci_high = percentile_interval(
                values,
                replicates=config["statistics"]["bootstrap_replicates"],
                seed=stable_seed,
                confidence_level=config["statistics"]["confidence_level"],
            )
            sign = exact_two_sided_sign_test(values)
            estimate = statistics.fmean(values)
            threshold = endpoint_config[endpoint]["practical_threshold"]
            primary_results[endpoint] = {
                "n_valid_pairs": len(values),
                "paired_effects": values,
                "mean_treatment_minus_comparator": estimate,
                "median_treatment_minus_comparator": statistics.median(values),
                "minimum_paired_effect": min(values),
                "maximum_paired_effect": max(values),
                "paired_percentile_bootstrap_ci95": [ci_low, ci_high],
                "bootstrap_replicates": config["statistics"][
                    "bootstrap_replicates"
                ],
                "bootstrap_seed_endpoint_specific": stable_seed,
                "exact_sign_test": sign,
                "practical_threshold": threshold,
                "absolute_mean_reaches_practical_threshold": abs(estimate)
                >= threshold,
            }
            sign_tests[endpoint] = sign["p_value"]
        else:
            primary_results[endpoint] = {
                "n_valid_pairs": 0,
                "paired_effects": [],
                "analysis_available": False,
                "reason": "no valid primary pairs",
                "practical_threshold": endpoint_config[endpoint][
                    "practical_threshold"
                ],
            }
            sign_tests[endpoint] = 1.0
    holm = holm_adjust(sign_tests, config["statistics"]["alpha"])
    for endpoint in ENDPOINTS:
        primary_results[endpoint]["holm_family"] = holm[endpoint]

    secondary = {}
    for key, endpoint_values in sorted(valid_effects.items()):
        if key == primary_key:
            continue
        family, regime, measurement_s, reservation_id = key.split("|")
        secondary[key] = {
            "analysis_family": family,
            "regime": regime,
            "measurement_s": float(measurement_s),
            "reservation_id": reservation_id,
            "reservation": config["service"]["reservation_profiles"][reservation_id],
            "descriptive_only": True,
            "paired_effect_summaries": {
                endpoint: _summary(endpoint_values[endpoint])
                for endpoint in ENDPOINTS
            },
        }

    planned_primary = sum(
        pair["analysis_family"] == "standard"
        and pair["regime"] == config["statistics"]["primary_regime"]
        and pair["measurement_s"] == config["statistics"]["primary_measurement_s"]
        and pair["reservation_id"] == config["service"]["primary_reservation_id"]
        for pair in plan["pairs"]
    )
    all_pairs_valid = not invalid_pairs and len(pair_rows) == len(plan["pairs"])
    complete_primary = all(
        primary_results[endpoint]["n_valid_pairs"] == planned_primary
        for endpoint in ENDPOINTS
    )
    mechanical_pass = (
        campaign["setup_success"]
        and campaign["teardown_success"]
        and campaign["recorded_arm_count"] == campaign["planned_arm_count"]
        and all_pairs_valid
        and complete_primary
    )
    summary = {
        "schema_version": ANALYSIS_SCHEMA_VERSION,
        "study_id": config["study_id"],
        "profile": profile_name,
        "evidentiary": campaign["evidentiary"],
        "evidence_boundary": config["evidence_boundary"],
        "xdp_used": False,
        "classification": "sender_supplied_oracle_tos_no_maturation",
        "primary_reservation_id": config["service"]["primary_reservation_id"],
        "primary_reservation_policy": config["service"]["primary_reservation_policy"],
        "accounting_boundary": config["traffic"]["accounting"],
        "service_counter_window": "receiver_arrival_[warmup_end,measurement_end)",
        "rtt_endpoint_conditioning": (
            "nearest-rank p99 over benign RTT probes successfully echoed and "
            "received during the measurement phase; probe loss is reported "
            "separately and the p99 is conditional on delivery"
        ),
        "effect_direction": "B5_work_conserving_minus_B3_fixed_ceilings",
        "config_sha256": object_sha256(config),
        "protocol_sha256": config["protocol_sha256"],
        "campaign_manifest_payload_sha256": campaign[
            "campaign_manifest_payload_sha256"
        ],
        "planned_pair_count": len(plan["pairs"]),
        "valid_pair_count": len(pair_rows) - len(invalid_pairs),
        "invalid_pair_count": len(invalid_pairs),
        "planned_primary_pair_count": planned_primary,
        "valid_primary_pair_count": min(
            primary_results[endpoint]["n_valid_pairs"] for endpoint in ENDPOINTS
        ),
        "primary": primary_results,
        "secondary_descriptive": secondary,
        "multiplicity_family": list(ENDPOINTS),
        "holm_alpha": config["statistics"]["alpha"],
        "mechanical_gate": {
            "all_planned_arms_recorded": campaign["recorded_arm_count"]
            == campaign["planned_arm_count"],
            "setup_passed": campaign["setup_success"],
            "identity_checked_teardown_passed": campaign["teardown_success"],
            "all_planned_pairs_valid": all_pairs_valid,
            "complete_primary_n": complete_primary,
            "study_B_pass": mechanical_pass,
        },
        "claim_permitted": (
            mechanical_pass and campaign["evidentiary"]
        ),
        "claim_boundary": (
            "causal effect of HTB borrowing versus fixed child ceilings only "
            "in this rootless, oracle-labeled, single-host veth diagnostic"
        ),
        "explicit_nonclaims": [
            "online detection",
            "XDP verifier acceptance, attachment, or performance",
            "capture-level generalization",
            "physical-link or multi-host behavior",
            "deployable DDoS protection",
        ],
    }
    require_finite_tree(summary)

    return pair_rows, invalid_pairs, summary


def analyze(result_dir: Path, *, config_path: Path) -> dict[str, Any]:
    """Analyze a campaign and publish the analysis directory transactionally."""

    config_path = config_path.resolve()
    config = load_config(config_path)
    assert_only_frozen_tc_difference(config)
    copied_campaign = read_json(result_dir / "campaign_manifest.json")
    if copied_campaign.get("evidentiary") and config_path != (
        PROJECT_ROOT / "configs" / "matched_scheduler.json"
    ).resolve():
        raise ValueError("authoritative analysis requires the canonical config path")
    profile_name = copied_campaign["profile"]
    plan = build_execution_plan(config, profile_name)
    campaign, arms = _verify_campaign(result_dir, config, plan)
    analysis_dir = result_dir / "analysis"
    final_manifest = result_dir / "manifest.json"
    if analysis_dir.exists():
        raise FileExistsError(f"refusing existing analysis directory: {analysis_dir}")
    if final_manifest.exists():
        raise FileExistsError("refusing to replace final manifest")

    # The staging directory is a sibling of the result tree, so publication by
    # rename is atomic and cannot expose a partially written analysis tree.
    staging_root = Path(
        tempfile.mkdtemp(prefix=f".{result_dir.name}.analysis-", dir=result_dir.parent)
    )
    staged_analysis = staging_root / "analysis"
    staged_analysis.mkdir()
    try:
        pair_rows, invalid_pairs, summary = _recompute_analysis(
            config, plan, campaign, arms
        )
        _write_pairs_csv(staged_analysis / "paired_effects.csv", pair_rows)
        write_new_json(staged_analysis / "invalid_pairs.json", invalid_pairs)
        write_new_json(staged_analysis / "summary.json", summary)
        analysis_inventory = make_tree_manifest(
            staged_analysis, excluded=[staged_analysis / "manifest.json"]
        )
        analysis_inventory["schema_version"] = ANALYSIS_MANIFEST_SCHEMA_VERSION
        # Published name is stable even though the staging parent is random.
        analysis_inventory["root_name"] = "analysis"
        write_new_json(staged_analysis / "manifest.json", analysis_inventory)
        if analysis_dir.exists() or final_manifest.exists():
            raise FileExistsError("analysis/final manifest appeared during staging")
        os.rename(staged_analysis, analysis_dir)
        staging_root.rmdir()
        final_inventory = make_tree_manifest(
            result_dir, excluded=[final_manifest]
        )
        _write_new_json_atomically(final_manifest, final_inventory)
        return summary
    except BaseException:
        # Never remove a successfully published directory.  If publication
        # happened but final-manifest creation failed, its complete analysis
        # remains visibly unsealed and verification fails closed.
        if staging_root.exists():
            shutil.rmtree(staging_root)
        raise


def _verify_inventory_exact(
    root: Path,
    manifest: dict[str, Any],
    *,
    excluded_relative_paths: set[str],
) -> None:
    if manifest.get("schema_version") not in {
        FINAL_MANIFEST_SCHEMA_VERSION,
        ANALYSIS_MANIFEST_SCHEMA_VERSION,
    }:
        raise ValueError(f"unexpected inventory schema at {root}")
    if manifest.get("root_name") != root.name:
        raise ValueError(f"inventory root name mismatch at {root}")
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise ValueError(f"inventory at {root} has no file list")
    expected_entry_keys = {"path", "size_bytes", "sha256"}
    if any(not isinstance(entry, dict) or set(entry) != expected_entry_keys for entry in entries):
        raise ValueError(f"inventory at {root} has a malformed entry")
    entry_paths = [entry["path"] for entry in entries]
    if any(not isinstance(path, str) or not path for path in entry_paths):
        raise ValueError(f"inventory at {root} has an invalid path")
    if len(set(entry_paths)) != len(entry_paths):
        raise ValueError(f"inventory at {root} contains duplicate paths")
    if entry_paths != sorted(entry_paths):
        raise ValueError(f"inventory paths are not canonical sorted order at {root}")
    verify_manifest_files(root, entries)
    declared = {entry["path"] for entry in entries}
    actual = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"result tree contains a symlink: {path}")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            if relative not in excluded_relative_paths:
                actual.add(relative)
    if declared != actual:
        raise ValueError(
            f"inventory path set mismatch: missing={sorted(declared - actual)}, "
            f"undeclared={sorted(actual - declared)}"
        )
    if manifest.get("file_count") != len(entries):
        raise ValueError("inventory file_count mismatch")
    if manifest.get("content_fingerprint_sha256") != object_sha256(entries):
        raise ValueError("inventory content fingerprint mismatch")


def verify_completed_result_tree(
    result_dir: Path,
    *,
    config_path: Path,
    require_study_pass: bool = True,
) -> dict[str, Any]:
    """Verify a completed result tree without recreating any analysis file.

    This is intentionally read-only. It authenticates every file through the
    nested manifests, revalidates campaign/source/protocol/config provenance,
    reconstructs the frozen plan and B3/B5 equivalence gates, and checks that
    the stored binary Study-B decision follows from the valid-pair set.
    """

    result_dir = result_dir.resolve()
    config_path = config_path.resolve()
    canonical_config = (PROJECT_ROOT / "configs" / "matched_scheduler.json").resolve()
    if config_path != canonical_config:
        raise ValueError(f"completed-tree verifier requires canonical config {canonical_config}")
    config = load_config(config_path)
    assert_only_frozen_tc_difference(config)
    final_manifest_path = result_dir / "manifest.json"
    if not final_manifest_path.is_file():
        raise ValueError("completed tree has no final manifest.json")
    final_manifest = read_json(final_manifest_path)
    if final_manifest.get("schema_version") != FINAL_MANIFEST_SCHEMA_VERSION:
        raise ValueError("unexpected final manifest schema")
    _verify_inventory_exact(
        result_dir,
        final_manifest,
        excluded_relative_paths={"manifest.json"},
    )

    analysis_dir = result_dir / "analysis"
    analysis_manifest = read_json(analysis_dir / "manifest.json")
    if analysis_manifest.get("schema_version") != ANALYSIS_MANIFEST_SCHEMA_VERSION:
        raise ValueError("unexpected analysis manifest schema")
    _verify_inventory_exact(
        analysis_dir,
        analysis_manifest,
        excluded_relative_paths={"manifest.json"},
    )
    if {entry["path"] for entry in analysis_manifest["files"]} != {
        "invalid_pairs.json",
        "paired_effects.csv",
        "summary.json",
    }:
        raise ValueError("analysis manifest does not contain the exact artifact set")

    campaign_preview = read_json(result_dir / "campaign_manifest.json")
    plan = build_execution_plan(config, campaign_preview["profile"])
    campaign, arms = _verify_campaign(result_dir, config, plan)
    stored_summary = read_json(analysis_dir / "summary.json")
    if stored_summary.get("schema_version") != ANALYSIS_SCHEMA_VERSION:
        raise ValueError("unexpected analysis summary schema")
    if stored_summary.get("config_sha256") != object_sha256(config):
        raise ValueError("analysis/config hash mismatch")
    if stored_summary.get("protocol_sha256") != config["protocol_sha256"]:
        raise ValueError("analysis/protocol hash mismatch")
    if (
        stored_summary.get("campaign_manifest_payload_sha256")
        != campaign["campaign_manifest_payload_sha256"]
    ):
        raise ValueError("analysis/campaign manifest hash mismatch")

    # This recomputes validity, arrival-window endpoints, paired effects,
    # bootstrap intervals, sign tests, Holm adjustment, secondary summaries,
    # and the mechanical decision.  Stored analysis values are never inputs.
    recomputed_rows, recomputed_invalid, recomputed_summary = _recompute_analysis(
        config, plan, campaign, arms
    )
    if read_json(analysis_dir / "invalid_pairs.json") != recomputed_invalid:
        raise ValueError("stored invalid-pair decisions do not match recomputation")
    if (analysis_dir / "paired_effects.csv").read_bytes() != _pairs_csv_bytes(
        recomputed_rows
    ):
        raise ValueError("stored paired-effects CSV does not exactly match recomputation")
    if stored_summary != recomputed_summary:
        raise ValueError(
            "stored summary/statistics/gates do not exactly match deterministic recomputation"
        )

    expected_study_pass = recomputed_summary["mechanical_gate"]["study_B_pass"]
    expected_claim = recomputed_summary["claim_permitted"]
    if require_study_pass and not expected_study_pass:
        raise ValueError("verified result tree is complete but study_B_pass is false")
    return {
        "verified": True,
        "read_only": True,
        "study_id": config["study_id"],
        "profile": campaign["profile"],
        "study_B_pass": expected_study_pass,
        "claim_permitted": expected_claim,
        "planned_arms": campaign["planned_arm_count"],
        "valid_pairs": recomputed_summary["valid_pair_count"],
        "invalid_pairs": recomputed_summary["invalid_pair_count"],
        "final_content_fingerprint_sha256": final_manifest[
            "content_fingerprint_sha256"
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument(
        "--config",
        type=Path,
        default=PROJECT_ROOT / "configs" / "matched_scheduler.json",
    )
    parser.add_argument(
        "--verify-completed",
        action="store_true",
        help="read-only verification of an already analyzed tree",
    )
    parser.add_argument(
        "--allow-failed-study",
        action="store_true",
        help="verification succeeds when hashes are valid but study_B_pass is false",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result_dir = args.input_dir.resolve()
    config = load_config(args.config.resolve())
    if args.allow_failed_study and not args.verify_completed:
        raise ValueError("--allow-failed-study is only valid with --verify-completed")
    if args.verify_completed:
        verification = verify_completed_result_tree(
            result_dir,
            config_path=args.config.resolve(),
            require_study_pass=not args.allow_failed_study,
        )
        print(json.dumps(verification, sort_keys=True))
        return
    copied_campaign = read_json(result_dir / "campaign_manifest.json")
    if copied_campaign["evidentiary"]:
        expected = (
            LIB_PROJECT_ROOT / config["execution"]["authoritative_output_dir"]
        ).resolve()
        if result_dir != expected:
            raise ValueError(
                f"authoritative analysis input must be exactly {expected}"
            )
    summary = analyze(result_dir, config_path=args.config.resolve())
    print(
        json.dumps(
            {
                "study_B_pass": summary["mechanical_gate"]["study_B_pass"],
                "valid_pairs": summary["valid_pair_count"],
                "invalid_pairs": summary["invalid_pair_count"],
                "summary": str(result_dir / "analysis" / "summary.json"),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
