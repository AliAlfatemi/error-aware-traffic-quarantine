from __future__ import annotations

import json
import io
import math
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from experiments.matched_scheduler_analysis import (
    derive_endpoints,
    exact_two_sided_sign_test,
    holm_adjust,
    nearest_rank,
    percentile_interval,
    validate_pair,
)
from testbed.matched_scheduler_lib import (
    ALLOWED_TREATMENT_DIFFERENCES,
    FROZEN_SOURCE_RELATIVE_PATHS,
    PROJECT_ROOT,
    assert_only_frozen_tc_difference,
    build_execution_plan,
    file_sha256,
    load_config,
    protocol_semantic_sha256,
    read_json,
    requested_tc_spec,
    require_testnet_address,
    tc_command_vectors,
    tc_spec_differences,
    write_new_json,
)
from testbed.matched_scheduler_traffic import (
    FLAG_RTT_PROBE,
    HEADER,
    PHASE_MEASUREMENT,
    _make_payload,
    _parse_payload,
    await_shared_start,
    count_selected_indices,
    encode_lateness_samples,
    nearest_rank_percentile,
    planned_packet_count,
    require_testnet,
)
from testbed.run_matched_scheduler import (
    _traffic_common,
    decode_lateness_samples,
    persisted_privacy_violations,
    redact_private_strings,
    summarize_background_cpu,
    validate_live_tc,
    validate_within_pair_fidelity,
)


class MatchedSchedulerConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.path = PROJECT_ROOT / "configs" / "matched_scheduler.json"
        cls.config = load_config(cls.path)

    def test_authoritative_plan_has_frozen_counts_and_pairs(self) -> None:
        plan = build_execution_plan(self.config, "authoritative")
        self.assertEqual(len(plan["pairs"]), 80)
        self.assertEqual(len(plan["trials"]), 160)
        primary = [
            pair
            for pair in plan["pairs"]
            if pair["analysis_family"] == "standard"
            and pair["regime"] == "borrowable_overload"
        ]
        duration = [
            pair
            for pair in plan["pairs"]
            if pair["analysis_family"] == "duration_60s"
        ]
        reservation_sensitivity = [
            pair
            for pair in plan["pairs"]
            if pair["analysis_family"] == "reservation_sensitivity"
        ]
        self.assertEqual(len(primary), 30)
        self.assertEqual(len(duration), 5)
        self.assertEqual(len(reservation_sensitivity), 15)
        self.assertTrue(all(pair["measurement_s"] == 20.0 for pair in primary))
        self.assertTrue(all(pair["measurement_s"] == 60.0 for pair in duration))
        for pair in plan["pairs"]:
            arms = [
                trial
                for trial in plan["trials"]
                if trial["pair_id"] == pair["pair_id"]
            ]
            self.assertEqual({trial["arm_id"] for trial in arms}, {"B3", "B5"})
            self.assertEqual(
                len({trial["schedule_identity_sha256"] for trial in arms}), 1
            )
            self.assertEqual(len({trial["traffic_seed"] for trial in arms}), 1)

    def test_protocol_semantic_design_digest_is_stable(self) -> None:
        self.assertEqual(
            protocol_semantic_sha256(self.config),
            "76b5060c593ecc05878b7e8ab219d2891f83d3935d564a45d0a8c8ac0a673484",
        )

    def test_protocol_lineage_preserves_study_a_attachment(self) -> None:
        self.assertEqual(
            self.config["protocol_file"], "STUDY_C_EXECUTION_PROTOCOL.md"
        )
        amendment = PROJECT_ROOT / self.config["protocol_file"]
        self.assertEqual(
            file_sha256(amendment),
            "84aecccd35a1f42128cd122c3062883166203169401550671c663f58157ee9ae",
        )
        self.assertEqual(self.config["protocol_sha256"], file_sha256(amendment))
        self.assertEqual(
            file_sha256(PROJECT_ROOT / "EXPERIMENTAL_PROTOCOL_FINAL.md"),
            "fc52ec677d93bc2406c1759d42c3d45908d035bddc6f16180d7b9e7d1fd07cf8",
        )
        self.assertIn(
            "fc52ec677d93bc2406c1759d42c3d45908d035bddc6f16180d7b9e7d1fd07cf8",
            amendment.read_text(encoding="utf-8"),
        )
        self.assertEqual(
            FROZEN_SOURCE_RELATIVE_PATHS[:3],
            (
                "configs/matched_scheduler.json",
                "STUDY_C_EXECUTION_PROTOCOL.md",
                "EXPERIMENTAL_PROTOCOL_FINAL.md",
            ),
        )

    def test_protocol_amendment_tamper_fails_full_file_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory_text:
            root = Path(directory_text)
            config_path = root / "configs" / "matched_scheduler.json"
            config_path.parent.mkdir()
            config_path.write_bytes(self.path.read_bytes())
            amendment = root / "STUDY_C_EXECUTION_PROTOCOL.md"
            amendment.write_bytes(
                (PROJECT_ROOT / "STUDY_C_EXECUTION_PROTOCOL.md").read_bytes()
                + b"\ntamper\n"
            )
            with self.assertRaisesRegex(ValueError, "protocol hash mismatch"):
                load_config(config_path, project_root=root)

    def test_protocol_semantic_marker_rejects_stale_config_even_with_matching_file_hash(self) -> None:
        tampered = json.loads(json.dumps(self.config))
        tampered["evidence_boundary"] = "stale-semantic-config"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "semantic design digest"):
                load_config(path)

    def test_reservation_sensitivity_binds_rates_buffers_and_cross_ratio_schedule(self) -> None:
        plan = build_execution_plan(self.config, "authoritative")
        sensitivity = [
            pair for pair in plan["pairs"]
            if pair["analysis_family"] == "reservation_sensitivity"
        ]
        expected = {
            "fast50_suspicious50": (4_000_000, 4_000_000, 80_000, 80_000),
            "fast70_suspicious30": (5_600_000, 2_400_000, 112_000, 48_000),
            "fast85_suspicious15": (6_800_000, 1_200_000, 136_000, 24_000),
        }
        for pair in sensitivity:
            self.assertEqual(
                (
                    pair["fast_reserved_Bps"],
                    pair["suspicious_reserved_Bps"],
                    pair["fast_bfifo_bytes"],
                    pair["suspicious_bfifo_bytes"],
                ),
                expected[pair["reservation_id"]],
            )
        for block in range(5):
            block_pairs = [pair for pair in sensitivity if pair["block"] == block]
            self.assertEqual(len({pair["traffic_seed"] for pair in block_pairs}), 1)
            self.assertEqual(
                len({pair["schedule_identity_sha256"] for pair in block_pairs}), 1
            )

    def test_frozen_cpu_ids_are_distinct_physical_core_selection(self) -> None:
        self.assertEqual(
            self.config["execution"]["cpu_affinity_ids"],
            {"receiver": 4, "benign_sender": 6, "suspicious_sender": 8},
        )
        selection = self.config["execution"]["cpu_affinity_selection"]
        self.assertEqual(
            selection["basis"],
            "pre_authoritative_per_cpu_background_control_not_endpoint_outcomes",
        )
        self.assertTrue(selection["fixed_for_entire_campaign"])
        self.assertEqual(
            selection["expected_linux_topology"],
            {
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
            },
        )

    def test_background_gate_uses_each_assigned_cpu_not_host_aggregate(self) -> None:
        before = {
            "cpu": (100, 1000),
            "cpu4": (10, 100),
            "cpu6": (20, 100),
            "cpu8": (30, 100),
        }
        after = {
            "cpu": (150, 1300),
            "cpu4": (20, 200),
            "cpu6": (45, 200),
            "cpu8": (30, 200),
        }
        summary = summarize_background_cpu(
            before,
            after,
            {"receiver": 4, "benign_sender": 6, "suspicious_sender": 8},
        )
        self.assertEqual(summary["assigned_cpus"]["receiver"]["busy_percent"], 10.0)
        self.assertEqual(summary["assigned_cpus"]["benign_sender"]["busy_percent"], 25.0)
        self.assertEqual(summary["assigned_cpus"]["suspicious_sender"]["busy_percent"], 0.0)
        self.assertEqual(summary["maximum_assigned_cpu_busy_percent"], 25.0)
        host = summary["whole_host_aggregate_descriptive_only"]
        self.assertFalse(host["used_as_invalidation_trigger"])
        self.assertAlmostEqual(host["busy_percent_total_capacity"], 100 / 6)
        self.assertAlmostEqual(host["busy_percent_one_core_equivalent"], 50.0)

    def test_plan_is_byte_deterministic_and_arm_order_is_randomized(self) -> None:
        first = build_execution_plan(self.config, "authoritative")
        second = build_execution_plan(self.config, "authoritative")
        self.assertEqual(first, second)
        orders = {tuple(pair["arm_order"]) for pair in first["pairs"]}
        self.assertEqual(orders, {("B3", "B5"), ("B5", "B3")})

    def test_arm_order_is_constrained_balanced_with_five_pair_alternation(self) -> None:
        plan = build_execution_plan(self.config, "authoritative")
        strata: dict[tuple, list[dict]] = {}
        for pair in plan["pairs"]:
            key = (
                pair["analysis_family"], pair["regime"],
                pair["reservation_id"], pair["measurement_s"],
            )
            strata.setdefault(key, []).append(pair)
        five_pair_splits = []
        for key in sorted(strata, key=repr):
            pairs = strata[key]
            b5_first = sum(pair["arm_order"][0] == "B5" for pair in pairs)
            if len(pairs) == 30:
                self.assertEqual(b5_first, 15)
            elif len(pairs) == 10:
                self.assertEqual(b5_first, 5)
            elif len(pairs) == 5:
                five_pair_splits.append(b5_first)
        self.assertEqual(five_pair_splits, [3, 2, 3, 2])

    def test_smoke_plan_is_tiny_and_non_evidentiary(self) -> None:
        plan = build_execution_plan(self.config, "smoke")
        self.assertFalse(plan["profile"]["evidentiary"])
        self.assertEqual(len(plan["pairs"]), 8)
        self.assertEqual(len(plan["trials"]), 16)
        self.assertLess(max(pair["measurement_s"] for pair in plan["pairs"]), 2.0)
        common = _traffic_common(self.config, plan["trials"][0])
        self.assertNotIn("--start-monotonic-ns", common)

    def test_only_child_ceilings_differ_between_treatment_and_comparator(self) -> None:
        assert_only_frozen_tc_difference(self.config)
        for reservation_id in self.config["service"]["reservation_profiles"]:
            differences = tc_spec_differences(
                requested_tc_spec(self.config, "B3", reservation_id),
                requested_tc_spec(self.config, "B5", reservation_id),
            )
            self.assertEqual(differences, ALLOWED_TREATMENT_DIFFERENCES)
        b3 = requested_tc_spec(self.config, "B3")
        b5 = requested_tc_spec(self.config, "B5")
        self.assertEqual(b3["classes"]["fast"]["bfifo_limit_bytes"], 112000)
        self.assertEqual(b3["classes"]["suspicious"]["bfifo_limit_bytes"], 48000)
        self.assertEqual(
            b3["classes"]["fast"]["bfifo_limit_bytes"],
            b5["classes"]["fast"]["bfifo_limit_bytes"],
        )

    def test_tc_commands_use_one_interface_and_exact_tos_filters(self) -> None:
        for arm_id in ("B3", "B5"):
            commands = tc_command_vectors(requested_tc_spec(self.config, arm_id))
            rendered = [" ".join(command) for command in commands]
            self.assertEqual(len(commands), 9)
            self.assertTrue(all("sbeq0-shrpeer" in line for line in rendered))
            self.assertIn("match ip tos 0x10 0xff flowid 1:10", rendered[-2])
            self.assertIn("match ip tos 0x00 0xff flowid 1:20", rendered[-1])
            self.assertIn("direct_qlen 0", rendered[1])
            self.assertIn("limit 112000", rendered[5])
            self.assertIn("limit 48000", rendered[6])

    def test_primary_offered_load_activates_borrowing_and_qdisc_overload(self) -> None:
        traffic = self.config["traffic"]
        service = self.config["service"]
        rates = traffic["regimes"]["borrowable_overload"]
        payload = traffic["packet_payload_bytes"]
        qdisc_packet = traffic["accounting"][
            "configured_qdisc_accounted_bytes_per_packet"
        ]
        profiles = service["reservation_profiles"].values()
        self.assertGreater(
            (rates["benign_pps"] + rates["suspicious_pps"]) * payload,
            service["total_Bps"],
        )
        self.assertEqual(qdisc_packet, 1242)
        self.assertEqual(
            traffic["accounting"]["veth_qdisc_observed_overhead_bytes"], 42
        )
        self.assertGreater(
            rates["benign_pps"] * payload,
            max(profile["fast_reserved_Bps"] for profile in profiles),
        )
        self.assertLess(
            rates["suspicious_pps"] * payload,
            min(profile["suspicious_reserved_Bps"] for profile in profiles),
        )
        self.assertGreater(
            (rates["benign_pps"] + rates["suspicious_pps"]) * qdisc_packet,
            service["total_Bps"],
        )
        both = traffic["regimes"]["both_saturated"]
        primary = service["reservation_profiles"][service["primary_reservation_id"]]
        self.assertGreater(both["benign_pps"] * payload, primary["fast_reserved_Bps"])
        self.assertGreater(
            both["suspicious_pps"] * payload,
            primary["suspicious_reserved_Bps"],
        )

    def test_fedora_iproute2_json_is_validated_without_schema_guessing(self) -> None:
        spec = requested_tc_spec(self.config, "B5")
        snapshot = {
            "commands": {
                "qdisc": {
                    "records": [
                        {
                            "kind": "htb",
                            "handle": "1:",
                            "root": True,
                            "options": {"default": "0x20", "r2q": 10, "direct_qlen": 0},
                            "packets": 0,
                            "drops": 0,
                        },
                        {"kind": "bfifo", "handle": "10:", "parent": "1:10", "options": {"limit": 112000}},
                        {"kind": "bfifo", "handle": "20:", "parent": "1:20", "options": {"limit": 48000}},
                    ]
                },
                "class": {
                    "records": [
                        {"class": "htb", "handle": "1:1", "root": True, "rate": 8000000, "ceil": 8000000, "burst": 91392, "cburst": 91392, "prio": 0, "linklayer": "ethernet"},
                        {"class": "htb", "handle": "1:10", "parent": "1:1", "rate": 5600000, "ceil": 8000000, "burst": 91392, "cburst": 91392, "quantum": 140000, "prio": 0, "linklayer": "ethernet"},
                        {"class": "htb", "handle": "1:20", "parent": "1:1", "rate": 2400000, "ceil": 8000000, "burst": 91392, "cburst": 91392, "quantum": 60000, "prio": 0, "linklayer": "ethernet"},
                    ]
                },
                "filter": {
                    "records": [
                        {"kind": "u32", "protocol": "ip", "pref": 1, "parent": "1:", "chain": 0},
                        {"kind": "u32", "protocol": "ip", "pref": 1, "parent": "1:", "chain": 0, "options": {"fh": "800:", "ht_divisor": 1}},
                        {"kind": "u32", "protocol": "ip", "pref": 1, "parent": "1:", "chain": 0, "order": 2048, "options": {"fh": "800::800", "bkt": "0", "key_ht": "800", "flowid": "1:10", "match": {"value": "100000", "mask": "ff0000", "off": 0}}},
                        {"kind": "u32", "protocol": "ip", "pref": 2, "parent": "1:", "chain": 0},
                        {"kind": "u32", "protocol": "ip", "pref": 2, "parent": "1:", "chain": 0, "options": {"fh": "801:", "ht_divisor": 1}},
                        {"kind": "u32", "protocol": "ip", "pref": 2, "parent": "1:", "chain": 0, "order": 2048, "options": {"fh": "801::800", "bkt": "0", "key_ht": "801", "flowid": "1:20", "match": {"value": "0", "mask": "ff0000", "off": 0}}},
                    ]
                },
            }
        }
        self.assertEqual(validate_live_tc(snapshot, spec), [])
        snapshot["commands"]["class"]["records"][1]["cburst"] = 91384
        self.assertIn(
            "class 1:10 cburst mismatch: 91384 vs 91392",
            validate_live_tc(snapshot, spec),
        )

    def test_non_testnet_addresses_are_rejected(self) -> None:
        for address in ("127.0.0.1", "10.0.0.1", "8.8.8.8", "::1"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                require_testnet_address(address, self.config)
            with self.assertRaises(ValueError):
                require_testnet(address)
        require_testnet_address("198.51.100.9", self.config)
        require_testnet("198.51.100.10")

    def test_namespace_setup_freezes_ipv6_and_permanent_neighbors(self) -> None:
        setup = (PROJECT_ROOT / "testbed" / "setup_matched_scheduler_netns.sh").read_text()
        validator = (PROJECT_ROOT / "testbed" / "validate_isolation.sh").read_text()
        self.assertIn("net.ipv6.conf.all.disable_ipv6=1", setup)
        self.assertIn("nud permanent", setup)
        self.assertIn("ip -j link show dev sbeq0-shared", setup)
        self.assertIn("ip -j link show dev sbeq0-shrpeer", setup)
        self.assertNotIn("/sys/class/net/", setup)
        self.assertIn("MATCHED_SCHEDULER_PARTIAL_CLEANUP_OK", setup)
        self.assertIn("partial_identity_matches", setup)
        self.assertIn("SERVER_START_TICKS=$(awk", setup)
        self.assertIn("CLIENT_START_TICKS=$(awk", setup)
        self.assertIn("stat -c '%u'", setup)
        self.assertIn("198.51.100.9", setup)
        self.assertIn("198.51.100.10", setup)
        self.assertIn('run_dir=testbed/run_matched_scheduler', setup)
        self.assertNotIn('run_dir=$RUNDIR', setup)
        self.assertIn('${SBEQ_RUN_DIR:-run_matched_scheduler}/client_anchor.pid', validator)
        self.assertNotIn('cat run/client_anchor.pid', validator)

    def test_persisted_private_identifiers_are_redacted_and_scannable(self) -> None:
        import platform

        private = {
            "stderr": f"failure below {PROJECT_ROOT}/testbed",
            "nested": [f"home={Path.home()}", f"host={platform.node()}"],
        }
        redacted = redact_private_strings(private)
        rendered = json.dumps(redacted)
        self.assertNotIn(str(PROJECT_ROOT), rendered)
        self.assertNotIn(str(Path.home()), rendered)
        self.assertNotIn(platform.node(), rendered)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "safe.json").write_text(rendered, encoding="utf-8")
            self.assertEqual(persisted_privacy_violations(root), [])
            (root / "leak.txt").write_text(str(PROJECT_ROOT), encoding="utf-8")
            self.assertEqual(
                persisted_privacy_violations(root),
                ["leak.txt:<PROJECT_ROOT>", "leak.txt:<HOME>"],
            )

    def test_within_pair_fidelity_uses_frozen_count_and_lateness_gates(self) -> None:
        profile = build_execution_plan(self.config, "authoritative")["profile"]
        plan = {"profile": profile, "pairs": [{"pair_id": "p"}]}

        def arm(sent: int, late: int) -> dict:
            phase_counts = {
                "warmup": sent // 4,
                "measurement": sent,
            }
            sender = {
                "sent": {
                    phase: {"packets": count}
                    for phase, count in phase_counts.items()
                },
                "send_lateness_by_phase": {
                    phase: {
                        "sample_count": count,
                        "mean_ns": float(late),
                        "max_ns": late,
                        "p99_ns": late,
                    }
                    for phase, count in phase_counts.items()
                },
                "send_lateness_samples_by_phase": {
                    phase: encode_lateness_samples([late] * count)
                    for phase, count in phase_counts.items()
                },
            }
            return {
                "processes": {
                    "benign_sender": {"final_record": sender},
                    "suspicious_sender": {"final_record": sender},
                }
            }

        arms = {"p_B3": arm(100_000, 100_000), "p_B5": arm(100_100, 200_000)}
        result = validate_within_pair_fidelity(self.config, plan, arms)
        self.assertTrue(result[0]["passed"])
        arms["p_B5"] = arm(99_000, 2_000_000)
        result = validate_within_pair_fidelity(self.config, plan, arms)
        self.assertFalse(result[0]["passed"])
        self.assertIn("benign_measurement_sent_count_difference", result[0]["errors"])


class TrafficRecordTests(unittest.TestCase):
    def test_lossless_lateness_sample_encoding_recomputes_exact_p99(self) -> None:
        samples = [0, 7, 11, 11, 900, 2_000_000]
        block = encode_lateness_samples(samples)
        self.assertEqual(
            decode_lateness_samples(block, expected_count=len(samples)), samples
        )
        self.assertEqual(nearest_rank_percentile(samples, 0.99), 2_000_000)
        tampered = dict(block)
        tampered["uncompressed_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            decode_lateness_samples(tampered, expected_count=len(samples))

    def test_packet_header_round_trip_is_exact_size(self) -> None:
        payload = _make_payload(
            1200,
            class_code=1,
            phase=PHASE_MEASUREMENT,
            sequence=17,
            planned_ns=100,
            actual_send_ns=125,
        )
        self.assertEqual(len(payload), 1200)
        parsed = _parse_payload(payload)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed["class"], "benign")
        self.assertEqual(parsed["phase"], PHASE_MEASUREMENT)
        self.assertEqual(parsed["sequence"], 17)
        self.assertEqual(parsed["planned_ns"], 100)
        self.assertEqual(parsed["sent_ns"], 125)
        self.assertFalse(parsed["rtt_probe"])
        self.assertIsNone(_parse_payload(bytes(HEADER.size - 1)))

    def test_flagged_probe_header_and_even_selection_are_deterministic(self) -> None:
        payload = _make_payload(
            1200,
            class_code=1,
            phase=PHASE_MEASUREMENT,
            sequence=75,
            planned_ns=100,
            actual_send_ns=125,
            rtt_probe=True,
        )
        parsed = _parse_payload(payload)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertTrue(parsed["rtt_probe"])
        self.assertEqual(payload[11] & FLAG_RTT_PROBE, FLAG_RTT_PROBE)
        self.assertEqual(count_selected_indices(0, 150000, 75), 2000)
        self.assertEqual(count_selected_indices(37500, 150000, 75), 2000)

    def test_shared_start_is_consumed_only_from_post_ready_barrier_record(self) -> None:
        future_ns = time.monotonic_ns() + 1_000_000_000
        record = json.dumps(
            {"event": "start", "start_monotonic_ns": future_ns},
            sort_keys=True,
        ) + "\n"
        with mock.patch("sys.stdin", io.StringIO(record)):
            actual, received_ns = await_shared_start(
                SimpleNamespace(start_monotonic_ns=None)
            )
        self.assertEqual(actual, future_ns)
        self.assertIsInstance(received_ns, int)

    def test_expired_probe_slot_has_one_accounting_increment_and_no_catchup_cap(self) -> None:
        source = (
            PROJECT_ROOT / "testbed" / "matched_scheduler_traffic.py"
        ).read_text(encoding="utf-8")
        self.assertEqual(source.count("missed_probe_deadlines[phase_name] += 1"), 2)
        self.assertNotIn("due_count < 256", source)

    def test_planned_counts_are_deterministic(self) -> None:
        self.assertEqual(planned_packet_count(20.0, 5000.0, 0), 100000)
        self.assertEqual(planned_packet_count(20.0, 0.0, 0), 0)
        self.assertEqual(planned_packet_count(0.5, 100.0, 5_000_000), 50)

    def test_nearest_rank_p99_is_not_interpolated(self) -> None:
        values = list(range(1, 101))
        self.assertEqual(nearest_rank_percentile(values, 0.99), 99)
        self.assertEqual(nearest_rank(values, 0.99), 99)


def synthetic_arm(config: dict, arm_id: str, *, valid: bool = True) -> dict:
    reservation_id = config["service"]["primary_reservation_id"]
    reservation = config["service"]["reservation_profiles"][reservation_id]
    trial = {
        "pair_id": "standard_borrowable_overload_000",
        "analysis_family": "standard",
        "regime": "borrowable_overload",
        "block": 0,
        "warmup_s": 5.0,
        "measurement_s": 20.0,
        "drain_s": 2.0,
        "benign_target_pps": 7500.0,
        "suspicious_target_pps": 800.0,
        "traffic_seed": 41031,
        "reservation_id": reservation_id,
        "fast_reservation_fraction": reservation["fast_fraction"],
        "suspicious_reservation_fraction": reservation["suspicious_fraction"],
        "fast_reserved_Bps": reservation["fast_reserved_Bps"],
        "suspicious_reserved_Bps": reservation["suspicious_reserved_Bps"],
        "fast_bfifo_bytes": reservation["fast_bfifo_bytes"],
        "suspicious_bfifo_bytes": reservation["suspicious_bfifo_bytes"],
        "pair_order": 0,
        "schedule_identity_sha256": "0" * 64,
        "arm_id": arm_id,
        "arm_name": config["arms"]["comparator" if arm_id == "B3" else "treatment"]["name"],
        "arm_position_within_pair": 0 if arm_id == "B3" else 1,
        "trial_id": f"standard_borrowable_overload_000_{arm_id}",
    }
    return {
        "schema_version": "matched-scheduler-arm-1.0",
        "trial": trial,
        "valid": valid,
        "invalid_reasons": [] if valid else ["synthetic_failure"],
        "cpu_assignment": {"receiver": 0, "benign_sender": 1, "suspicious_sender": 2},
        "tc_requested_spec": requested_tc_spec(config, arm_id, reservation_id),
        "processes": {
            "receiver": {
                "final_record": {
                    "counts": {
                        "measurement": {
                            "benign_bytes": 112000000 if arm_id == "B3" else 130000000,
                            "suspicious_bytes": 48000000 if arm_id == "B3" else 30000000,
                        }
                    }
                }
            },
            "benign_sender": {
                "final_record": {
                    "measurement_rtt_ns": [1_000_000, 2_000_000, 3_000_000],
                    "measurement_rtt_p99_ns": 3_000_000,
                }
            },
        },
    }


class DeterministicAnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_config(PROJECT_ROOT / "configs" / "matched_scheduler.json")

    def test_endpoint_derivation_recomputes_rtt_from_samples(self) -> None:
        arm = synthetic_arm(self.config, "B3")
        endpoints = derive_endpoints(arm)
        self.assertEqual(endpoints["benign_goodput_Bps"], 5_600_000.0)
        self.assertEqual(endpoints["suspicious_service_Bps"], 2_400_000.0)
        self.assertEqual(endpoints["benign_rtt_p99_ms"], 3.0)
        arm["processes"]["benign_sender"]["final_record"][
            "measurement_rtt_p99_ns"
        ] = 2_000_000
        with self.assertRaises(ValueError):
            derive_endpoints(arm)

    def test_sign_test_and_holm_are_exact(self) -> None:
        sign = exact_two_sided_sign_test([1, 2, 3, 4, 5])
        self.assertEqual(sign["n_nonzero"], 5)
        self.assertEqual(sign["p_value"], 0.0625)
        ties = exact_two_sided_sign_test([0, 0, 0])
        self.assertEqual(ties["p_value"], 1.0)
        self.assertEqual(ties["zeros_excluded"], 3)
        adjusted = holm_adjust({"a": 0.01, "b": 0.03, "c": 0.04}, 0.05)
        self.assertAlmostEqual(adjusted["a"]["holm_adjusted_p_value"], 0.03)
        self.assertAlmostEqual(adjusted["b"]["holm_adjusted_p_value"], 0.06)
        self.assertAlmostEqual(adjusted["c"]["holm_adjusted_p_value"], 0.06)

    def test_paired_bootstrap_is_seed_deterministic(self) -> None:
        values = [1.0, 2.0, 3.0, 4.0]
        first = percentile_interval(
            values, replicates=1000, seed=91, confidence_level=0.95
        )
        second = percentile_interval(
            values, replicates=1000, seed=91, confidence_level=0.95
        )
        self.assertEqual(first, second)
        self.assertTrue(math.isfinite(first[0]) and math.isfinite(first[1]))
        self.assertLessEqual(first[0], first[1])

    def test_pair_validation_rejects_invalid_arm_and_schedule_drift(self) -> None:
        b3 = synthetic_arm(self.config, "B3")
        b5 = synthetic_arm(self.config, "B5")
        self.assertEqual(validate_pair(self.config, b3["trial"]["pair_id"], {"B3": b3, "B5": b5}), [])
        b5["trial"]["traffic_seed"] += 1
        self.assertIn(
            "paired trial factors or offered schedule differ",
            validate_pair(self.config, b3["trial"]["pair_id"], {"B3": b3, "B5": b5}),
        )
        b5["trial"]["traffic_seed"] -= 1
        b5["valid"] = False
        b5["invalid_reasons"] = ["process_failed"]
        self.assertIn(
            "B5:process_failed",
            validate_pair(self.config, b3["trial"]["pair_id"], {"B3": b3, "B5": b5}),
        )

    def test_evidence_json_is_create_only_and_duplicate_keys_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            write_new_json(path, {"x": 1})
            with self.assertRaises(FileExistsError):
                write_new_json(path, {"x": 2})
            duplicate = Path(directory) / "duplicate.json"
            duplicate.write_text('{"x": 1, "x": 2}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                read_json(duplicate)


if __name__ == "__main__":
    unittest.main()
