#!/usr/bin/env python3
"""Shared, deterministic definitions for the matched HTB diagnostic.

This module has no privilege-requiring side effects.  The live runner imports
it to construct the exact execution plan and tc command vector; the analyzer
imports the same definitions to reject a result tree that does not match the
frozen plan.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import math
import os
import random
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_SCHEMA_VERSION = "matched-scheduler-config-1.0"
PLAN_SCHEMA_VERSION = "matched-scheduler-plan-1.0"
ARM_SCHEMA_VERSION = "matched-scheduler-arm-1.0"
CAMPAIGN_SCHEMA_VERSION = "matched-scheduler-campaign-1.0"
FINAL_MANIFEST_SCHEMA_VERSION = "matched-scheduler-final-manifest-1.0"
ARM_IDS = ("B3", "B5")
FROZEN_SOURCE_RELATIVE_PATHS = (
    "configs/matched_scheduler.json",
    "STUDY_C_EXECUTION_PROTOCOL.md",
    "EXPERIMENTAL_PROTOCOL_FINAL.md",
    "testbed/run_matched_scheduler.py",
    "testbed/matched_scheduler_lib.py",
    "testbed/matched_scheduler_traffic.py",
    "testbed/setup_matched_scheduler_netns.sh",
    "testbed/teardown_matched_scheduler_netns.sh",
    "testbed/lib_isolation_guard.sh",
    "testbed/validate_isolation.sh",
    "testbed/MATCHED_SCHEDULER.md",
    "experiments/matched_scheduler_analysis.py",
)
ALLOWED_TREATMENT_DIFFERENCES = frozenset(
    {
        "arm_id",
        "arm_name",
        "classes.fast.ceil_Bps",
        "classes.suspicious.ceil_Bps",
    }
)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path: Path) -> Any:
    return json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
    )


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def object_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def protocol_semantic_sha256(config: dict[str, Any]) -> str:
    """Bind protocol prose to every config field except its circular file hash."""

    semantic_config = {
        key: value for key, value in config.items() if key != "protocol_sha256"
    }
    return object_sha256(semantic_config)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_new_json(path: Path, value: Any) -> None:
    """Create JSON without ever replacing an existing evidence file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, sort_keys=True, indent=2, allow_nan=False)
        handle.write("\n")


def require_finite_tree(value: Any, path: str = "root") -> None:
    if isinstance(value, bool) or value is None or isinstance(value, (str, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"non-finite value at {path}: {value}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            require_finite_tree(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            require_finite_tree(item, f"{path}.{key}")
        return
    raise TypeError(f"unsupported value at {path}: {type(value).__name__}")


def _number(value: Any, name: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite number")
    result = float(value)
    if not math.isfinite(result) or (positive and result <= 0):
        raise ValueError(f"{name} must be {'positive and ' if positive else ''}finite")
    return result


def _require_exact_keys(value: dict[str, Any], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise ValueError(
            f"{name} key set differs: got {sorted(value)}, expected {sorted(expected)}"
        )


def load_config(
    path: Path,
    *,
    project_root: Path = PROJECT_ROOT,
    verify_protocol: bool = True,
) -> dict[str, Any]:
    config = read_json(path)
    _require_exact_keys(
        config,
        {
            "schema_version", "study_id", "frozen_date", "protocol_file",
            "protocol_sha256", "preregistration_status", "evidence_boundary",
            "arms", "network", "service", "traffic", "timing", "execution",
            "statistics", "validity", "profiles",
        },
        "config",
    )
    if config.get("schema_version") != CONFIG_SCHEMA_VERSION:
        raise ValueError(f"unsupported config schema: {config.get('schema_version')}")
    if set(config.get("arms", {})) != {"comparator", "treatment"}:
        raise ValueError("config must define exactly comparator and treatment arms")
    for arm_role in ("comparator", "treatment"):
        _require_exact_keys(config["arms"][arm_role], {"id", "name"}, f"arms.{arm_role}")
    if config["arms"]["comparator"]["id"] != "B3":
        raise ValueError("the frozen comparator must be B3")
    if config["arms"]["treatment"]["id"] != "B5":
        raise ValueError("the frozen treatment must be B5")

    network = config["network"]
    _require_exact_keys(
        network,
        {
            "allowed_subnet", "server_ip", "client_ip", "prefix_length",
            "loopback_ipv4", "ipv6_policy", "main_route", "neighbor_policy", "server_interface",
            "client_interface", "receiver_port", "benign_source_port",
            "suspicious_source_port", "default_route_permitted",
        },
        "network",
    )
    subnet = ipaddress.ip_network(network["allowed_subnet"], strict=True)
    if not subnet.is_private and str(subnet) != "198.51.100.0/24":
        raise ValueError("only RFC 5737 TEST-NET-2 is allowed")
    if str(subnet) != "198.51.100.0/24":
        raise ValueError("frozen network must be 198.51.100.0/24")
    for key in ("server_ip", "client_ip"):
        require_testnet_address(network[key], config)
    if network.get("default_route_permitted") is not False:
        raise ValueError("a default route must never be permitted")
    if (
        network.get("loopback_ipv4") != "127.0.0.1/8"
        or network.get("ipv6_policy") != "disabled_in_both_namespaces"
        or network.get("main_route") != "198.51.100.8/30"
        or network.get("neighbor_policy")
        != "static_permanent_peer_entries_before_tc"
    ):
        raise ValueError("frozen namespace address/route/IPv6 policy differs")

    service = config["service"]
    _require_exact_keys(
        service,
        {
            "total_Bps", "buffer_time_s", "primary_reservation_id",
            "primary_reservation_policy", "reservation_profiles", "htb_r2q",
            "root_direct_qlen_packets",
            "root_burst_bytes", "root_cburst_bytes", "child_burst_bytes",
            "child_cburst_bytes", "burst_cburst_rationale", "root_quantum_bytes",
            "fast_tos", "suspicious_tos",
        },
        "service",
    )
    for key in (
        "total_Bps",
        "buffer_time_s",
        "root_burst_bytes",
        "root_cburst_bytes",
        "child_burst_bytes",
        "child_cburst_bytes",
    ):
        _number(service[key], f"service.{key}", positive=True)
    if service["root_direct_qlen_packets"] != 0:
        raise ValueError("root HTB direct_qlen must be exactly zero")
    expected_reservation_ids = {
        "fast50_suspicious50",
        "fast70_suspicious30",
        "fast85_suspicious15",
    }
    if set(service["reservation_profiles"]) != expected_reservation_ids:
        raise ValueError("reservation profiles must be exactly 50/50, 70/30, and 85/15")
    if service["primary_reservation_id"] != "fast70_suspicious30":
        raise ValueError("70/30 must remain the primary reservation")
    policy = service["primary_reservation_policy"]
    _require_exact_keys(
        policy,
        {"basis", "statement", "optimized_or_tuned_against_outcomes"},
        "service.primary_reservation_policy",
    )
    if (
        policy.get("basis") != "transparent_illustrative_slo_policy_allocation"
        or policy.get("optimized_or_tuned_against_outcomes") is not False
    ):
        raise ValueError("primary 70/30 policy must be explicitly illustrative and unoptimized")
    for reservation_id, reservation in service["reservation_profiles"].items():
        _require_exact_keys(
            reservation,
            {
                "fast_fraction", "suspicious_fraction", "fast_reserved_Bps",
                "suspicious_reserved_Bps", "fast_bfifo_bytes",
                "suspicious_bfifo_bytes", "fast_quantum_bytes",
                "suspicious_quantum_bytes",
            },
            f"service.reservation_profiles.{reservation_id}",
        )
        fast_fraction = _number(
            reservation["fast_fraction"],
            f"service.reservation_profiles.{reservation_id}.fast_fraction",
            positive=True,
        )
        suspicious_fraction = _number(
            reservation["suspicious_fraction"],
            f"service.reservation_profiles.{reservation_id}.suspicious_fraction",
            positive=True,
        )
        if not math.isclose(fast_fraction + suspicious_fraction, 1.0, abs_tol=1e-12):
            raise ValueError(f"reservation fractions do not sum to one: {reservation_id}")
        fast_rate = reservation["fast_reserved_Bps"]
        suspicious_rate = reservation["suspicious_reserved_Bps"]
        if fast_rate + suspicious_rate != service["total_Bps"]:
            raise ValueError(f"child reservations do not sum to total: {reservation_id}")
        if fast_rate != round(service["total_Bps"] * fast_fraction):
            raise ValueError(f"FAST rate/fraction mismatch: {reservation_id}")
        if suspicious_rate != round(service["total_Bps"] * suspicious_fraction):
            raise ValueError(f"suspicious rate/fraction mismatch: {reservation_id}")
        for label, rate_key, limit_key in (
            ("fast", "fast_reserved_Bps", "fast_bfifo_bytes"),
            ("suspicious", "suspicious_reserved_Bps", "suspicious_bfifo_bytes"),
        ):
            expected = round(reservation[rate_key] * service["buffer_time_s"])
            if reservation[limit_key] != expected:
                raise ValueError(
                    f"{reservation_id} {label} bfifo is not exactly 20 ms of its reservation"
                )
        if (
            reservation["fast_quantum_bytes"] + reservation["suspicious_quantum_bytes"]
            != 200000
        ):
            raise ValueError(f"child quantums must sum to 200000: {reservation_id}")

    traffic = config["traffic"]
    _require_exact_keys(
        traffic,
        {
            "transport", "packet_payload_bytes", "schedule",
            "missed_deadline_policy", "schedule_seed_first", "rtt_probe_rate_pps",
            "rtt_probe_selection", "echo_policy", "socket_buffer_request_bytes",
            "regimes", "accounting",
        },
        "traffic",
    )
    if set(traffic["regimes"]) != {
        "no_attack", "low_total", "borrowable_overload", "both_saturated"
    }:
        raise ValueError("traffic regimes differ from the frozen four-regime design")
    payload = traffic["packet_payload_bytes"]
    if isinstance(payload, bool) or not isinstance(payload, int) or not 576 <= payload <= 1472:
        raise ValueError("UDP payload must be an integer in [576, 1472]")
    for regime, rates in traffic["regimes"].items():
        _require_exact_keys(rates, {"benign_pps", "suspicious_pps"}, f"traffic.regimes.{regime}")
        for label in ("benign_pps", "suspicious_pps"):
            rate = _number(rates[label], f"traffic.regimes.{regime}.{label}")
            if rate < 0:
                raise ValueError("packet rates cannot be negative")
    borrowable = traffic["regimes"].get("borrowable_overload", {})
    payload_bytes = traffic["packet_payload_bytes"]
    minimum_suspicious_reservation = min(
        profile["suspicious_reserved_Bps"]
        for profile in service["reservation_profiles"].values()
    )
    maximum_fast_reservation = max(
        profile["fast_reserved_Bps"]
        for profile in service["reservation_profiles"].values()
    )
    if not (
        (borrowable.get("benign_pps", 0) + borrowable.get("suspicious_pps", 0))
        * payload_bytes
        > service["total_Bps"]
        and borrowable.get("benign_pps", 0) * payload_bytes
        > maximum_fast_reservation
        and borrowable.get("suspicious_pps", 0) * payload_bytes
        < minimum_suspicious_reservation
    ):
        raise ValueError(
            "primary borrowable overload must exceed root/FAST service while leaving "
            "suspicious offered payload below every sensitivity reservation"
        )
    both_saturated = traffic["regimes"].get("both_saturated", {})
    primary_reservation = service["reservation_profiles"][service["primary_reservation_id"]]
    if not (
        both_saturated.get("benign_pps", 0) * payload_bytes
        > primary_reservation["fast_reserved_Bps"]
        and both_saturated.get("suspicious_pps", 0) * payload_bytes
        > primary_reservation["suspicious_reserved_Bps"]
        and (
            both_saturated.get("benign_pps", 0)
            + both_saturated.get("suspicious_pps", 0)
        )
        * payload_bytes
        > service["total_Bps"]
    ):
        raise ValueError("both_saturated must backlog both primary 70/30 classes")
    if (
        traffic.get("rtt_probe_rate_pps") != 100
        or traffic.get("rtt_probe_selection")
        != "deterministic_evenly_spaced_subset_of_benign_schedule"
        or traffic.get("echo_policy") != "only_flagged_rtt_probes_are_echoed"
        or traffic.get("missed_deadline_policy")
        != "skip_expired_slot_never_catch_up"
    ):
        raise ValueError("the frozen sparse-probe/deadline policy is not exact")
    for regime, rates in traffic["regimes"].items():
        benign_rate = rates["benign_pps"]
        if benign_rate and benign_rate % traffic["rtt_probe_rate_pps"] != 0:
            raise ValueError(f"{regime} benign rate must be divisible by probe rate")
    accounting = traffic["accounting"]
    _require_exact_keys(
        accounting,
        {
            "application_payload_offered_rate", "application_service_rate",
            "tc_accounted_rate", "physical_wire_rate_measured",
            "ipv4_udp_header_bytes", "veth_qdisc_observed_overhead_bytes",
            "configured_qdisc_accounted_bytes_per_packet", "qdisc_unit_statement",
            "non_equivalence_statement",
        },
        "traffic.accounting",
    )
    if (
        accounting.get("veth_qdisc_observed_overhead_bytes") != 42
        or accounting.get("configured_qdisc_accounted_bytes_per_packet")
        != payload_bytes + accounting.get("veth_qdisc_observed_overhead_bytes", -1)
        or accounting.get("ipv4_udp_header_bytes") != 28
    ):
        raise ValueError(
            "frozen veth qdisc/SKB accounting must be 1200+42=1242 bytes; "
            "the IPv4/UDP header-only unit is distinct"
        )
    if (
        (borrowable["benign_pps"] + borrowable["suspicious_pps"])
        * accounting["configured_qdisc_accounted_bytes_per_packet"]
        <= service["total_Bps"]
    ):
        raise ValueError("borrowable overload must also exceed root service in configured qdisc bytes")

    _require_exact_keys(
        config["timing"],
        {
            "warmup_s", "measurement_s", "drain_s",
            "duration_check_measurement_s", "process_start_lead_s",
            "minimum_all_process_ready_lead_s", "cooldown_between_arms_s",
            "ready_timeout_s", "process_timeout_slack_s",
        },
        "timing",
    )
    for key in ("warmup_s", "measurement_s", "drain_s", "duration_check_measurement_s"):
        _number(config["timing"][key], f"timing.{key}", positive=True)
    _require_exact_keys(
        config["execution"],
        {
            "execution_order_seed", "randomize_pair_sequence",
            "randomize_arm_order_within_pair", "standard_blocks", "duration_check",
            "reservation_sensitivity", "cpu_affinity_ids",
            "cpu_affinity_selection", "authoritative_output_dir",
        },
        "execution",
    )
    if config["execution"]["standard_blocks"] != {
        "no_attack": 10,
        "low_total": 10,
        "borrowable_overload": 30,
        "both_saturated": 10,
    }:
        raise ValueError("authoritative block counts differ from the frozen protocol")
    if config["execution"]["duration_check"] != {
        "regime": "borrowable_overload",
        "blocks": 5,
    }:
        raise ValueError("duration-check design differs from the frozen protocol")
    sensitivity = config["execution"]["reservation_sensitivity"]
    _require_exact_keys(
        sensitivity,
        {"regime", "blocks_per_profile", "reservation_ids", "inferential_status"},
        "execution.reservation_sensitivity",
    )
    if (
        sensitivity["regime"] != "borrowable_overload"
        or sensitivity["blocks_per_profile"] != 5
        or sensitivity["reservation_ids"]
        != [
            "fast50_suspicious50",
            "fast70_suspicious30",
            "fast85_suspicious15",
        ]
        or sensitivity["inferential_status"] != "secondary_descriptive"
    ):
        raise ValueError("reservation sensitivity differs from the frozen design")
    if accounting.get("physical_wire_rate_measured") is not False:
        raise ValueError("the rootless study must not claim physical-wire measurement")
    if config["statistics"]["bootstrap_replicates"] != 10000:
        raise ValueError("the frozen analysis requires 10,000 bootstrap resamples")
    cpu_ids = config["execution"]["cpu_affinity_ids"]
    if set(cpu_ids) != {"receiver", "benign_sender", "suspicious_sender"}:
        raise ValueError("exactly three process CPU-affinity ids are required")
    if (
        cpu_ids != {"receiver": 4, "benign_sender": 6, "suspicious_sender": 8}
        or any(
            isinstance(cpu_id, bool) or not isinstance(cpu_id, int) or cpu_id < 0
            for cpu_id in cpu_ids.values()
        )
        or len(set(cpu_ids.values())) != 3
    ):
        raise ValueError("frozen process CPU ids must be exactly receiver=4, benign=6, suspicious=8")
    cpu_selection = config["execution"]["cpu_affinity_selection"]
    _require_exact_keys(
        cpu_selection,
        {"basis", "topology", "expected_linux_topology", "fixed_for_entire_campaign"},
        "execution.cpu_affinity_selection",
    )
    if (
        cpu_selection.get("basis")
        != "pre_authoritative_per_cpu_background_control_not_endpoint_outcomes"
        or cpu_selection.get("fixed_for_entire_campaign") is not True
    ):
        raise ValueError("CPU selection provenance is missing or outcome-tuned")
    expected_topology = {
        "receiver": {
            "cpu_id": 4,
            "physical_package_id": 0,
            "core_id": 2,
            "numa_node": 0,
        },
        "benign_sender": {
            "cpu_id": 6,
            "physical_package_id": 0,
            "core_id": 5,
            "numa_node": 0,
        },
        "suspicious_sender": {
            "cpu_id": 8,
            "physical_package_id": 0,
            "core_id": 3,
            "numa_node": 0,
        },
    }
    if cpu_selection.get("expected_linux_topology") != expected_topology:
        raise ValueError("frozen CPU topology mapping is not exact")
    validity = config["validity"]
    _require_exact_keys(
        validity,
        {
            "minimum_overload_offered_fraction", "maximum_missed_schedule_fraction",
            "maximum_send_lateness_p99_ns",
            "maximum_phase_snapshot_start_lateness_ns",
            "maximum_within_pair_sent_count_relative_difference",
            "maximum_within_pair_lateness_p99_difference_ns",
            "minimum_measurement_rtt_probes_received",
            "require_zero_udp_socket_overflow",
            "require_zero_udp_inerrors_rcvbuferrors",
            "require_zero_echo_instrumentation_errors",
            "qdisc_packet_conservation_absolute_tolerance",
            "maximum_background_busy_pct_each_assigned_cpu",
            "whole_host_aggregate_is_descriptive_only", "background_sample_s",
            "counter_reconciliation_relative_tolerance", "require_exact_packet_size",
            "require_no_default_route", "require_test_net_only", "require_tc_json",
            "require_all_planned_pairs_for_mechanical_pass",
        },
        "validity",
    )
    if (
        validity.get("maximum_background_busy_pct_each_assigned_cpu") != 20.0
        or validity.get("whole_host_aggregate_is_descriptive_only") is not True
    ):
        raise ValueError("background gate must be 20% on each assigned CPU only")
    frozen_validity = {
        "maximum_missed_schedule_fraction": 0.01,
        "maximum_send_lateness_p99_ns": 2_000_000,
        "maximum_phase_snapshot_start_lateness_ns": 50_000_000,
        "maximum_within_pair_sent_count_relative_difference": 0.005,
        "maximum_within_pair_lateness_p99_difference_ns": 1_000_000,
        "minimum_measurement_rtt_probes_received": 500,
        "require_zero_udp_socket_overflow": True,
        "require_zero_udp_inerrors_rcvbuferrors": True,
        "require_zero_echo_instrumentation_errors": True,
        "qdisc_packet_conservation_absolute_tolerance": 32,
    }
    for key, expected in frozen_validity.items():
        if validity.get(key) != expected:
            raise ValueError(f"frozen validity setting differs: {key}")
    if config["timing"].get("minimum_all_process_ready_lead_s") != 0.25:
        raise ValueError("authoritative all-process ready lead must be 0.25 s")

    _require_exact_keys(config["profiles"], {"authoritative", "smoke"}, "profiles")
    _require_exact_keys(
        config["profiles"]["authoritative"],
        {"evidentiary", "label"},
        "profiles.authoritative",
    )
    _require_exact_keys(
        config["profiles"]["smoke"],
        {
            "evidentiary", "label", "warmup_s", "measurement_s", "drain_s",
            "duration_check_measurement_s", "process_start_lead_s",
            "minimum_all_process_ready_lead_s", "cooldown_between_arms_s",
            "standard_blocks", "duration_check_blocks",
            "reservation_sensitivity_blocks_per_profile", "rate_scale",
            "minimum_measurement_rtt_probes_received",
            "maximum_missed_schedule_fraction", "maximum_send_lateness_p99_ns",
            "maximum_phase_snapshot_start_lateness_ns",
            "maximum_within_pair_sent_count_relative_difference",
            "maximum_within_pair_lateness_p99_difference_ns",
        },
        "profiles.smoke",
    )

    if verify_protocol:
        protocol = project_root / config["protocol_file"]
        actual = file_sha256(protocol)
        if actual != config["protocol_sha256"]:
            raise ValueError(
                f"protocol hash mismatch: expected {config['protocol_sha256']}, got {actual}"
            )
        semantic_marker = (
            "Study-C semantic design SHA-256: "
            + protocol_semantic_sha256(config)
        )
        protocol_text = protocol.read_text(encoding="utf-8")
        if protocol_text.count(semantic_marker) != 1:
            raise ValueError(
                "protocol does not contain exactly one matching Study-B semantic design digest"
            )
    require_finite_tree(config)
    return config


def require_testnet_address(address: str, config: dict[str, Any]) -> None:
    allowed = ipaddress.ip_network(config["network"]["allowed_subnet"], strict=True)
    parsed = ipaddress.ip_address(address)
    if parsed.version != 4 or parsed not in allowed:
        raise ValueError(f"address {address} is outside frozen TEST-NET {allowed}")


def effective_profile(config: dict[str, Any], profile_name: str) -> dict[str, Any]:
    if profile_name not in config["profiles"]:
        raise ValueError(f"unknown profile: {profile_name}")
    profile = copy.deepcopy(config["profiles"][profile_name])
    timing = copy.deepcopy(config["timing"])
    validity = copy.deepcopy(config["validity"])
    standard_blocks = copy.deepcopy(config["execution"]["standard_blocks"])
    duration_blocks = int(config["execution"]["duration_check"]["blocks"])
    sensitivity_blocks = int(
        config["execution"]["reservation_sensitivity"]["blocks_per_profile"]
    )
    rate_scale = 1.0
    if profile_name != "authoritative":
        for key in (
            "warmup_s",
            "measurement_s",
            "drain_s",
            "duration_check_measurement_s",
            "process_start_lead_s",
            "cooldown_between_arms_s",
            "minimum_all_process_ready_lead_s",
        ):
            if key in profile:
                timing[key] = profile[key]
        if "background_sample_s" in profile:
            validity["background_sample_s"] = profile["background_sample_s"]
        for key in (
            "minimum_measurement_rtt_probes_received",
            "maximum_missed_schedule_fraction",
            "maximum_send_lateness_p99_ns",
            "maximum_phase_snapshot_start_lateness_ns",
            "maximum_within_pair_sent_count_relative_difference",
            "maximum_within_pair_lateness_p99_difference_ns",
        ):
            if key in profile:
                validity[key] = profile[key]
        standard_blocks = copy.deepcopy(profile["standard_blocks"])
        duration_blocks = int(profile["duration_check_blocks"])
        sensitivity_blocks = int(profile["reservation_sensitivity_blocks_per_profile"])
        rate_scale = _number(profile.get("rate_scale", 1.0), "profile.rate_scale", positive=True)
    result = {
        "name": profile_name,
        "label": profile["label"],
        "evidentiary": bool(profile["evidentiary"]),
        "timing": timing,
        "validity": validity,
        "standard_blocks": standard_blocks,
        "duration_check_blocks": duration_blocks,
        "reservation_sensitivity_blocks_per_profile": sensitivity_blocks,
        "rate_scale": rate_scale,
    }
    require_finite_tree(result)
    return result


def _stable_int(text: str) -> int:
    return int.from_bytes(hashlib.sha256(text.encode("utf-8")).digest()[:8], "big")


def build_execution_plan(config: dict[str, Any], profile_name: str) -> dict[str, Any]:
    profile = effective_profile(config, profile_name)
    pairs: list[dict[str, Any]] = []
    stable_index = 0
    primary_reservation_id = config["service"]["primary_reservation_id"]

    def reservation_fields(reservation_id: str) -> dict[str, Any]:
        reservation = config["service"]["reservation_profiles"][reservation_id]
        return {
            "reservation_id": reservation_id,
            "fast_reservation_fraction": reservation["fast_fraction"],
            "suspicious_reservation_fraction": reservation["suspicious_fraction"],
            "fast_reserved_Bps": reservation["fast_reserved_Bps"],
            "suspicious_reserved_Bps": reservation["suspicious_reserved_Bps"],
            "fast_bfifo_bytes": reservation["fast_bfifo_bytes"],
            "suspicious_bfifo_bytes": reservation["suspicious_bfifo_bytes"],
        }

    for regime in (
        "no_attack",
        "low_total",
        "borrowable_overload",
        "both_saturated",
    ):
        for block in range(int(profile["standard_blocks"][regime])):
            rates = config["traffic"]["regimes"][regime]
            pairs.append(
                {
                    "pair_id": f"standard_{regime}_{block:03d}",
                    "analysis_family": "standard",
                    "regime": regime,
                    "block": block,
                    "warmup_s": profile["timing"]["warmup_s"],
                    "measurement_s": profile["timing"]["measurement_s"],
                    "drain_s": profile["timing"]["drain_s"],
                    "benign_target_pps": rates["benign_pps"] * profile["rate_scale"],
                    "suspicious_target_pps": rates["suspicious_pps"] * profile["rate_scale"],
                    "benign_rtt_probe_rate_pps": config["traffic"]["rtt_probe_rate_pps"]
                    * profile["rate_scale"],
                    "traffic_seed": int(config["traffic"]["schedule_seed_first"]) + stable_index,
                    **reservation_fields(primary_reservation_id),
                }
            )
            stable_index += 1
    duration_regime = config["execution"]["duration_check"]["regime"]
    duration_rates = config["traffic"]["regimes"][duration_regime]
    for block in range(profile["duration_check_blocks"]):
        pairs.append(
            {
                "pair_id": f"duration_{duration_regime}_{block:03d}",
                "analysis_family": "duration_60s" if profile_name == "authoritative" else "duration_smoke",
                "regime": duration_regime,
                "block": block,
                "warmup_s": profile["timing"]["warmup_s"],
                "measurement_s": profile["timing"]["duration_check_measurement_s"],
                "drain_s": profile["timing"]["drain_s"],
                "benign_target_pps": duration_rates["benign_pps"] * profile["rate_scale"],
                "suspicious_target_pps": duration_rates["suspicious_pps"] * profile["rate_scale"],
                "benign_rtt_probe_rate_pps": config["traffic"]["rtt_probe_rate_pps"]
                * profile["rate_scale"],
                "traffic_seed": int(config["traffic"]["schedule_seed_first"]) + stable_index,
                **reservation_fields(primary_reservation_id),
            }
        )
        stable_index += 1
    sensitivity = config["execution"]["reservation_sensitivity"]
    sensitivity_regime = sensitivity["regime"]
    sensitivity_rates = config["traffic"]["regimes"][sensitivity_regime]
    sensitivity_seed_first = int(config["traffic"]["schedule_seed_first"]) + stable_index
    for reservation_id in sensitivity["reservation_ids"]:
        for block in range(profile["reservation_sensitivity_blocks_per_profile"]):
            pairs.append(
                {
                    "pair_id": f"reservation_{reservation_id}_{sensitivity_regime}_{block:03d}",
                    "analysis_family": "reservation_sensitivity",
                    "inferential_status": "secondary_descriptive",
                    "regime": sensitivity_regime,
                    "block": block,
                    "warmup_s": profile["timing"]["warmup_s"],
                    "measurement_s": profile["timing"]["measurement_s"],
                    "drain_s": profile["timing"]["drain_s"],
                    "benign_target_pps": sensitivity_rates["benign_pps"] * profile["rate_scale"],
                    "suspicious_target_pps": sensitivity_rates["suspicious_pps"] * profile["rate_scale"],
                    "benign_rtt_probe_rate_pps": config["traffic"]["rtt_probe_rate_pps"]
                    * profile["rate_scale"],
                    "traffic_seed": sensitivity_seed_first + block,
                    **reservation_fields(reservation_id),
                }
            )

    def stratum_key(pair: dict[str, Any]) -> tuple[Any, ...]:
        return (
            pair["analysis_family"],
            pair["regime"],
            pair["reservation_id"],
            pair["measurement_s"],
        )

    # Freeze exact within-stratum balance before randomizing the global pair
    # sequence.  Even strata are exactly half B5-first.  Five-pair strata
    # alternate deterministically between 3/2 and 2/3 across sorted strata.
    strata: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for pair in pairs:
        strata.setdefault(stratum_key(pair), []).append(pair)
    arm_order_by_pair: dict[str, list[str]] = {}
    seed = int(config["execution"]["execution_order_seed"])
    for stratum_index, key in enumerate(sorted(strata, key=repr)):
        members = sorted(strata[key], key=lambda item: item["pair_id"])
        member_rng = random.Random(seed ^ _stable_int(repr(key)))
        member_rng.shuffle(members)
        b5_first_count = len(members) // 2
        if len(members) % 2 and stratum_index % 2 == 0:
            b5_first_count += 1
        for index, member in enumerate(members):
            arm_order_by_pair[member["pair_id"]] = (
                ["B5", "B3"] if index < b5_first_count else ["B3", "B5"]
            )

    order_rng = random.Random(seed)
    if config["execution"]["randomize_pair_sequence"]:
        order_rng.shuffle(pairs)
    arm_by_id = {
        config["arms"]["comparator"]["id"]: config["arms"]["comparator"]["name"],
        config["arms"]["treatment"]["id"]: config["arms"]["treatment"]["name"],
    }
    trials: list[dict[str, Any]] = []
    for pair_order, pair in enumerate(pairs):
        arm_order = (
            list(arm_order_by_pair[pair["pair_id"]])
            if config["execution"]["randomize_arm_order_within_pair"]
            else list(ARM_IDS)
        )
        pair["pair_order"] = pair_order
        pair["arm_order"] = arm_order
        pair["schedule_identity_sha256"] = object_sha256(
            {
                key: pair[key]
                for key in (
                    "regime",
                    "warmup_s",
                    "measurement_s",
                    "drain_s",
                    "benign_target_pps",
                    "suspicious_target_pps",
                    "benign_rtt_probe_rate_pps",
                    "traffic_seed",
                )
            }
        )
        for position, arm_id in enumerate(arm_order):
            trials.append(
                {
                    **{key: value for key, value in pair.items() if key != "arm_order"},
                    "arm_id": arm_id,
                    "arm_name": arm_by_id[arm_id],
                    "arm_position_within_pair": position,
                    "trial_id": f"{pair['pair_id']}_{arm_id}",
                }
            )
    plan = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "study_id": config["study_id"],
        "profile": profile,
        "config_sha256": object_sha256(config),
        "pairs": pairs,
        "trials": trials,
    }
    plan["plan_sha256"] = object_sha256(plan)
    return plan


def requested_tc_spec(
    config: dict[str, Any], arm_id: str, reservation_id: str | None = None
) -> dict[str, Any]:
    if arm_id not in ARM_IDS:
        raise ValueError(f"matched study only permits {ARM_IDS}, got {arm_id}")
    service = config["service"]
    if reservation_id is None:
        reservation_id = service["primary_reservation_id"]
    if reservation_id not in service["reservation_profiles"]:
        raise ValueError(f"unknown reservation profile: {reservation_id}")
    reservation = service["reservation_profiles"][reservation_id]
    total = int(service["total_Bps"])
    fast_ceil = int(reservation["fast_reserved_Bps"] if arm_id == "B3" else total)
    suspicious_ceil = int(
        reservation["suspicious_reserved_Bps"] if arm_id == "B3" else total
    )
    return {
        "arm_id": arm_id,
        "arm_name": (
            config["arms"]["comparator"]["name"]
            if arm_id == "B3"
            else config["arms"]["treatment"]["name"]
        ),
        "reservation_id": reservation_id,
        "fast_reservation_fraction": reservation["fast_fraction"],
        "suspicious_reservation_fraction": reservation["suspicious_fraction"],
        "buffer_time_s": service["buffer_time_s"],
        "interface": config["network"]["client_interface"],
        "root": {
            "kind": "htb",
            "handle": "1:",
            "classid": "1:1",
            "parent": "1:",
            "default_class_minor": 20,
            "r2q": int(service["htb_r2q"]),
            "direct_qlen_packets": int(service["root_direct_qlen_packets"]),
            "rate_Bps": total,
            "ceil_Bps": total,
            "burst_bytes": int(service["root_burst_bytes"]),
            "cburst_bytes": int(service["root_cburst_bytes"]),
            "quantum_bytes": int(service["root_quantum_bytes"]),
            "priority": 0,
            "linklayer": "ethernet",
        },
        "classes": {
            "fast": {
                "classid": "1:10",
                "parent": "1:1",
                "rate_Bps": int(reservation["fast_reserved_Bps"]),
                "ceil_Bps": fast_ceil,
                "burst_bytes": int(service["child_burst_bytes"]),
                "cburst_bytes": int(service["child_cburst_bytes"]),
                "quantum_bytes": int(reservation["fast_quantum_bytes"]),
                "priority": 0,
                "linklayer": "ethernet",
                "bfifo_handle": "10:",
                "bfifo_limit_bytes": int(reservation["fast_bfifo_bytes"]),
                "tos": int(service["fast_tos"]),
            },
            "suspicious": {
                "classid": "1:20",
                "parent": "1:1",
                "rate_Bps": int(reservation["suspicious_reserved_Bps"]),
                "ceil_Bps": suspicious_ceil,
                "burst_bytes": int(service["child_burst_bytes"]),
                "cburst_bytes": int(service["child_cburst_bytes"]),
                "quantum_bytes": int(reservation["suspicious_quantum_bytes"]),
                "priority": 0,
                "linklayer": "ethernet",
                "bfifo_handle": "20:",
                "bfifo_limit_bytes": int(reservation["suspicious_bfifo_bytes"]),
                "tos": int(service["suspicious_tos"]),
            },
        },
    }


def tc_command_vectors(spec: dict[str, Any]) -> list[list[str]]:
    iface = spec["interface"]
    root = spec["root"]
    fast = spec["classes"]["fast"]
    suspicious = spec["classes"]["suspicious"]

    def class_command(classid: str, parent: str, values: dict[str, Any]) -> list[str]:
        return [
            "tc", "class", "add", "dev", iface, "parent", parent,
            "classid", classid, "htb",
            "rate", f"{values['rate_Bps']}Bps",
            "ceil", f"{values['ceil_Bps']}Bps",
            "burst", f"{values['burst_bytes']}b",
            "cburst", f"{values['cburst_bytes']}b",
            "quantum", str(values["quantum_bytes"]),
            "prio", str(values["priority"]),
            "linklayer", values["linklayer"],
        ]

    return [
        ["tc", "qdisc", "del", "dev", iface, "root"],
        [
            "tc", "qdisc", "add", "dev", iface, "root", "handle", root["handle"],
            "htb", "default", str(root["default_class_minor"]), "r2q", str(root["r2q"]),
            "direct_qlen", str(root["direct_qlen_packets"]),
        ],
        class_command("1:1", "1:", root),
        class_command(fast["classid"], fast["parent"], fast),
        class_command(suspicious["classid"], suspicious["parent"], suspicious),
        [
            "tc", "qdisc", "add", "dev", iface, "parent", fast["classid"],
            "handle", fast["bfifo_handle"], "bfifo", "limit", str(fast["bfifo_limit_bytes"]),
        ],
        [
            "tc", "qdisc", "add", "dev", iface, "parent", suspicious["classid"],
            "handle", suspicious["bfifo_handle"], "bfifo", "limit", str(suspicious["bfifo_limit_bytes"]),
        ],
        [
            "tc", "filter", "add", "dev", iface, "parent", "1:", "protocol", "ip",
            "prio", "1", "u32", "match", "ip", "tos", f"0x{fast['tos']:02x}", "0xff",
            "flowid", fast["classid"],
        ],
        [
            "tc", "filter", "add", "dev", iface, "parent", "1:", "protocol", "ip",
            "prio", "2", "u32", "match", "ip", "tos", f"0x{suspicious['tos']:02x}", "0xff",
            "flowid", suspicious["classid"],
        ],
    ]


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    if not isinstance(value, dict):
        return {prefix: value}
    result: dict[str, Any] = {}
    for key, item in value.items():
        child = f"{prefix}.{key}" if prefix else key
        result.update(_flatten(item, child))
    return result


def tc_spec_differences(left: dict[str, Any], right: dict[str, Any]) -> set[str]:
    left_flat, right_flat = _flatten(left), _flatten(right)
    return {
        key
        for key in set(left_flat) | set(right_flat)
        if left_flat.get(key) != right_flat.get(key)
    }


def assert_only_frozen_tc_difference(config: dict[str, Any]) -> None:
    for reservation_id in config["service"]["reservation_profiles"]:
        differences = tc_spec_differences(
            requested_tc_spec(config, "B3", reservation_id),
            requested_tc_spec(config, "B5", reservation_id),
        )
        if differences != ALLOWED_TREATMENT_DIFFERENCES:
            raise ValueError(
                "B3/B5 requested configurations differ outside the frozen child ceilings "
                f"for {reservation_id}: {sorted(differences)}"
            )


def make_tree_manifest(root: Path, *, excluded: Iterable[Path] = ()) -> dict[str, Any]:
    excluded_resolved = {path.resolve() for path in excluded}
    files = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.resolve() in excluded_resolved:
            continue
        relative = path.relative_to(root).as_posix()
        files.append(
            {
                "path": relative,
                "size_bytes": path.stat().st_size,
                "sha256": file_sha256(path),
            }
        )
    return {
        "schema_version": FINAL_MANIFEST_SCHEMA_VERSION,
        "root_name": root.name,
        "files": files,
        "file_count": len(files),
        "content_fingerprint_sha256": object_sha256(files),
    }


def verify_manifest_files(root: Path, entries: list[dict[str, Any]]) -> None:
    declared = set()
    for entry in entries:
        relative = entry["path"]
        if relative in declared or Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise ValueError(f"unsafe or duplicate manifest path: {relative}")
        declared.add(relative)
        path = root / relative
        if not path.is_file():
            raise ValueError(f"manifest file missing: {relative}")
        if path.stat().st_size != entry["size_bytes"] or file_sha256(path) != entry["sha256"]:
            raise ValueError(f"manifest mismatch: {relative}")


def available_cpu_assignment(config: dict[str, Any]) -> dict[str, int]:
    available = set(os.sched_getaffinity(0))
    cpu_ids = config["execution"]["cpu_affinity_ids"]
    if not available:
        raise RuntimeError("process has an empty CPU affinity mask")
    missing = sorted(set(cpu_ids.values()) - available)
    if missing:
        raise RuntimeError(
            f"frozen CPU ids are outside the process affinity mask: {missing}"
        )
    return dict(cpu_ids)
