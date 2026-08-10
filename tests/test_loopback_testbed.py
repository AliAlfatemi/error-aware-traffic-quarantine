from __future__ import annotations

import json
import math
import os
import platform
import subprocess
import tempfile
import unittest
from dataclasses import asdict, replace
from pathlib import Path
from unittest import mock

import prototype.loopback_testbed as loopback_module
from prototype.loopback_testbed import (
    FRAME_HEADER,
    ORACLE_ROUTING_POLICY,
    SCHEMA_VERSION,
    STUDY_CONFIG_SCHEMA_VERSION,
    TCP_MAX_APPLICATION_FRAME_BYTES,
    UDP_MAX_APPLICATION_FRAME_BYTES,
    OfferedPacket,
    PrototypeConfig,
    StudyConfig,
    _condition_identity,
    _decode_frame,
    _encode_frame,
    _probe_macos_architecture,
    _prepare_output_dir,
    aggregate_trials,
    build_configuration_provenance,
    build_execution_plan_payload,
    build_study_trial_plan,
    build_trial_plan,
    file_sha256,
    load_study_config,
    object_sha256,
    offered_schedule,
    runtime_metadata,
    run_trial,
    verify_study_config_unchanged,
    write_json,
)


class ScheduleTests(unittest.TestCase):
    def test_offered_schedule_is_paired_and_deterministic(self) -> None:
        base = PrototypeConfig(
            seed=77,
            protocol="udp",
            mode="shared",
            duration_s=0.05,
            measurement_start_s=0.0,
            benign_offered_pps=80.0,
            suspicious_offered_pps=120.0,
        )
        isolated = replace(base, mode="isolated")
        self.assertEqual(offered_schedule(base), offered_schedule(isolated))
        self.assertEqual(offered_schedule(base), offered_schedule(base))

    def test_default_resource_totals_are_equal(self) -> None:
        config = PrototypeConfig()
        self.assertEqual(
            config.shared_capacity_pps,
            config.fast_capacity_pps + config.quarantine_capacity_pps,
        )
        self.assertEqual(
            config.shared_buffer_packets,
            config.fast_buffer_packets + config.quarantine_buffer_packets,
        )
        self.assertEqual(config.routing_policy, ORACLE_ROUTING_POLICY)

    def test_non_loopback_configuration_is_not_exposed(self) -> None:
        self.assertGreaterEqual(PrototypeConfig().packet_size_bytes, FRAME_HEADER.size)
        self.assertNotIn("host", PrototypeConfig.__dataclass_fields__)


class ValidationTests(unittest.TestCase):
    def test_invalid_finite_numeric_inputs_are_rejected(self) -> None:
        invalid = (
            ("duration_s", math.inf),
            ("measurement_start_s", math.nan),
            ("benign_offered_pps", -1.0),
            ("suspicious_offered_pps", math.inf),
            ("shared_capacity_pps", 0.0),
            ("fast_capacity_pps", math.nan),
            ("quarantine_capacity_pps", -2.0),
            ("quarantine_dwell_s", -0.01),
            ("drain_timeout_s", 0.0),
        )
        for field, value in invalid:
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    replace(PrototypeConfig(), **{field: value}).validate()

    def test_invalid_discrete_and_policy_inputs_are_rejected(self) -> None:
        invalid = (
            {"protocol": "sctp"},
            {"mode": "magic"},
            {"routing_policy": "learned"},
            {"shared_buffer_packets": 0},
            {"fast_buffer_packets": 1.5},
            {"packet_size_bytes": FRAME_HEADER.size - 1},
            {"seed": True},
        )
        for update in invalid:
            with self.subTest(update=update):
                with self.assertRaises(ValueError):
                    replace(PrototypeConfig(), **update).validate()

    def test_protocol_frame_size_limits_are_enforced(self) -> None:
        PrototypeConfig(
            protocol="udp", packet_size_bytes=UDP_MAX_APPLICATION_FRAME_BYTES
        ).validate()
        PrototypeConfig(
            protocol="tcp", packet_size_bytes=TCP_MAX_APPLICATION_FRAME_BYTES
        ).validate()
        with self.assertRaises(ValueError):
            PrototypeConfig(
                protocol="udp",
                packet_size_bytes=UDP_MAX_APPLICATION_FRAME_BYTES + 1,
            ).validate()
        with self.assertRaises(ValueError):
            PrototypeConfig(
                protocol="tcp",
                packet_size_bytes=TCP_MAX_APPLICATION_FRAME_BYTES + 1,
            ).validate()

    def test_runtime_distinguishes_kernel_and_python_process_architecture(self) -> None:
        metadata = runtime_metadata()
        self.assertEqual(metadata["kernel_machine"], os.uname().machine)
        self.assertEqual(metadata["python_process_machine"], platform.machine())
        self.assertEqual(
            metadata["architecture_mismatch_or_translation_possible"],
            os.uname().machine != platform.machine(),
        )
        self.assertIn("macos_process_translated", metadata)
        self.assertIn("macos_arm64_capable", metadata)
        self.assertIn("macos_sysctl_probe_error", metadata)

    def test_direct_macos_architecture_probe_parses_boolean_sysctls(self) -> None:
        values = {
            "sysctl.proc_translated": "1\n",
            "hw.optional.arm64": "1\n",
        }

        def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess:
            return subprocess.CompletedProcess(
                command, 0, stdout=values[command[-1]], stderr=""
            )

        with mock.patch.object(loopback_module.platform, "system", return_value="Darwin"):
            with mock.patch.object(
                loopback_module.subprocess, "run", side_effect=fake_run
            ) as run_mock:
                probe = _probe_macos_architecture()
        self.assertTrue(probe["macos_process_translated"])
        self.assertTrue(probe["macos_arm64_capable"])
        self.assertIsNone(probe["macos_sysctl_probe_error"])
        self.assertEqual(run_mock.call_count, 2)

    def test_macos_architecture_probe_preserves_partial_failure(self) -> None:
        def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess:
            if command[-1] == "sysctl.proc_translated":
                return subprocess.CompletedProcess(
                    command, 1, stdout="", stderr="permission denied\n"
                )
            return subprocess.CompletedProcess(command, 0, stdout="1\n", stderr="")

        with mock.patch.object(loopback_module.platform, "system", return_value="Darwin"):
            with mock.patch.object(
                loopback_module.subprocess, "run", side_effect=fake_run
            ):
                probe = _probe_macos_architecture()
        self.assertIsNone(probe["macos_process_translated"])
        self.assertTrue(probe["macos_arm64_capable"])
        self.assertIn("permission denied", probe["macos_sysctl_probe_error"])

    def test_output_directory_must_be_empty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            empty = root / "empty"
            empty.mkdir()
            _prepare_output_dir(empty)

            new = root / "new" / "nested"
            _prepare_output_dir(new)
            self.assertTrue(new.is_dir())

            stale = root / "stale"
            stale.mkdir()
            (stale / "old-result.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                _prepare_output_dir(stale)

            ordinary_file = root / "not-a-directory"
            ordinary_file.write_text("data\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                _prepare_output_dir(ordinary_file)


class FrameIntegrityTests(unittest.TestCase):
    def test_frame_round_trip_preserves_exact_metadata(self) -> None:
        packet = OfferedPacket(
            sequence=123,
            label="attack",
            planned_offset_s=0.1,
            target_ns=1_000,
            ingress_ns=1_010,
            size_bytes=128,
        )
        decoded = _decode_frame(
            _encode_frame(packet, "quarantine", service_ns=1_100, due_ns=1_400),
            receive_ns=1_500,
        )
        self.assertEqual(decoded["sequence"], packet.sequence)
        self.assertEqual(decoded["label"], packet.label)
        self.assertEqual(decoded["route"], "quarantine")
        self.assertEqual(decoded["size_bytes"], packet.size_bytes)
        self.assertEqual(decoded["ingress_ns"], packet.ingress_ns)
        self.assertEqual(decoded["service_ns"], 1_100)
        self.assertEqual(decoded["due_ns"], 1_400)
        self.assertEqual(decoded["receive_ns"], 1_500)

    def test_frame_rejects_invalid_sequence_and_route(self) -> None:
        packet = OfferedPacket(
            sequence=-1,
            label="benign",
            planned_offset_s=0.0,
            target_ns=1,
            ingress_ns=1,
            size_bytes=128,
        )
        with self.assertRaises(ValueError):
            _encode_frame(packet, "fast", 2, 3)
        with self.assertRaises(ValueError):
            _encode_frame(replace(packet, sequence=1), "unknown", 2, 3)


def _synthetic_summary(seed: int, value: float = 10.0) -> dict:
    config = PrototypeConfig(seed=seed, protocol="udp", mode="shared")
    identity = _condition_identity(config)
    by_label = {}
    for label in ("benign", "attack"):
        by_label[label] = {
            "ingress_cohort": {
                "admission_drop_fraction": 0.1,
                "delivery_failure_fraction_of_admitted": 0.0,
                "end_to_end_loss_fraction": 0.1,
                "latency_ms": {"p50": value, "p95": value + 1, "p99": value + 2},
            },
            "departure_window": {
                "application_frame_rate_fps": value,
                "application_payload_Bps": value * 128,
            },
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "valid_for_publication_aggregation": True,
        "condition_identity": identity,
        "condition_identity_sha256": object_sha256(identity),
        "config": asdict(config),
        "claim_boundary": "user-space oracle; not XDP",
        "measurement": {"by_label": by_label},
    }


class AggregationTests(unittest.TestCase):
    def test_aggregation_reports_counts_condition_and_bootstrap_ci(self) -> None:
        aggregate = aggregate_trials(
            [_synthetic_summary(1, 10.0), _synthetic_summary(2, 12.0)]
        )
        self.assertEqual(aggregate["trial_count"], 2)
        self.assertEqual(aggregate["seed_sample_count"], 2)
        self.assertEqual(aggregate["seed_ids"], [1, 2])
        metric = aggregate["metrics"]["benign"]["application_frame_rate_fps"]
        self.assertEqual(metric["sample_count"], 2)
        self.assertEqual(metric["mean"], 11.0)
        self.assertEqual(metric["bootstrap_95_ci"]["confidence_level"], 0.95)
        self.assertLessEqual(
            metric["bootstrap_95_ci"]["lower"],
            metric["bootstrap_95_ci"]["upper"],
        )

    def test_aggregation_rejects_mixed_conditions_duplicate_seeds_and_invalid(self) -> None:
        first = _synthetic_summary(1)
        different = _synthetic_summary(2)
        different_config = PrototypeConfig(seed=2, protocol="tcp", mode="shared")
        different["config"] = asdict(different_config)
        different["condition_identity"] = _condition_identity(different_config)
        different["condition_identity_sha256"] = object_sha256(
            different["condition_identity"]
        )
        with self.assertRaises(ValueError):
            aggregate_trials([first, different])
        with self.assertRaises(ValueError):
            aggregate_trials([first, _synthetic_summary(1)])
        invalid = _synthetic_summary(2)
        invalid["valid_for_publication_aggregation"] = False
        with self.assertRaises(ValueError):
            aggregate_trials([first, invalid])


class ExecutionPlanTests(unittest.TestCase):
    def test_plan_is_deterministic_randomized_and_pair_interleaved(self) -> None:
        arguments = dict(
            protocols=["udp", "tcp"],
            modes=["shared", "isolated"],
            loads=[0.0, 400.0],
            seeds=3,
            seed_start=100,
            duration_s=0.1,
            measurement_start_s=0.01,
            dwell_s=0.005,
            order_seed=77,
        )
        first = build_trial_plan(**arguments)
        second = build_trial_plan(**arguments)
        comparable = lambda plan: [
            (
                item["execution_ordinal"],
                item["paired_block_id"],
                item["within_block_order"],
                item["config_sha256"],
            )
            for item in plan
        ]
        self.assertEqual(comparable(first), comparable(second))
        self.assertEqual(len(first), 24)
        for index in range(0, len(first), 2):
            pair = first[index : index + 2]
            self.assertEqual(pair[0]["paired_block_id"], pair[1]["paired_block_id"])
            self.assertEqual(
                {item["config"].mode for item in pair}, {"shared", "isolated"}
            )
            self.assertEqual(
                offered_schedule(pair[0]["config"]),
                offered_schedule(pair[1]["config"]),
            )

    def test_plan_rejects_invalid_or_duplicate_design_values(self) -> None:
        base = dict(
            protocols=["udp"],
            modes=["shared", "isolated"],
            loads=[400.0],
            seeds=1,
            seed_start=1,
            duration_s=0.1,
            measurement_start_s=0.0,
            dwell_s=0.0,
            order_seed=1,
        )
        with self.assertRaises(ValueError):
            build_trial_plan(**{**base, "seeds": 0})
        with self.assertRaises(ValueError):
            build_trial_plan(**{**base, "modes": ["shared", "shared"]})
        with self.assertRaises(ValueError):
            build_trial_plan(**{**base, "loads": [math.inf]})
        with self.assertRaises(ValueError):
            build_trial_plan(**{**base, "seed_start": True})
        with self.assertRaises(ValueError):
            build_trial_plan(**{**base, "order_seed": 1.5})


class CommittedStudyConfigTests(unittest.TestCase):
    @staticmethod
    def committed_path() -> Path:
        return Path(__file__).resolve().parents[1] / "configs" / "loopback_testbed.json"

    def test_authoritative_config_exactly_matches_frozen_design(self) -> None:
        study, provenance = load_study_config(self.committed_path())
        self.assertEqual(study.schema_version, STUDY_CONFIG_SCHEMA_VERSION)
        self.assertEqual(study.study_role, "authoritative")
        self.assertEqual(study.seeds, 30)
        self.assertEqual(study.seed_start, 1009)
        self.assertEqual(study.protocols, ("udp", "tcp"))
        self.assertEqual(study.modes, ("shared", "isolated"))
        self.assertEqual(study.suspicious_offered_pps, (0, 160, 400, 800))
        self.assertEqual(study.execution_order_seed, 1729)
        self.assertEqual(study.duration_s, 1.2)
        self.assertEqual(study.measurement_start_s, 0.2)
        self.assertEqual(study.quarantine_dwell_s, 0.025)
        self.assertEqual(
            study.shared_capacity_pps,
            study.fast_capacity_pps + study.quarantine_capacity_pps,
        )
        self.assertEqual(
            study.shared_buffer_packets,
            study.fast_buffer_packets + study.quarantine_buffer_packets,
        )
        self.assertEqual(provenance["path"], "configs/loopback_testbed.json")
        self.assertEqual(provenance["file_sha256"], file_sha256(self.committed_path()))

        plan = build_study_trial_plan(study)
        self.assertEqual(len(plan), 480)
        condition_seed_sets: dict[tuple[str, str, float], set[int]] = {}
        for item in plan:
            trial = item["config"]
            condition_seed_sets.setdefault(
                (trial.protocol, trial.mode, trial.suspicious_offered_pps), set()
            ).add(trial.seed)
            self.assertEqual(trial.routing_policy, study.routing_policy)
            self.assertEqual(trial.duration_s, study.duration_s)
            self.assertEqual(trial.measurement_start_s, study.measurement_start_s)
            self.assertEqual(trial.benign_offered_pps, study.benign_offered_pps)
            self.assertEqual(trial.shared_capacity_pps, study.shared_capacity_pps)
            self.assertEqual(trial.fast_capacity_pps, study.fast_capacity_pps)
            self.assertEqual(
                trial.quarantine_capacity_pps, study.quarantine_capacity_pps
            )
            self.assertEqual(trial.shared_buffer_packets, study.shared_buffer_packets)
            self.assertEqual(trial.fast_buffer_packets, study.fast_buffer_packets)
            self.assertEqual(
                trial.quarantine_buffer_packets, study.quarantine_buffer_packets
            )
            self.assertEqual(trial.quarantine_dwell_s, study.quarantine_dwell_s)
            self.assertEqual(trial.packet_size_bytes, study.packet_size_bytes)
            self.assertEqual(trial.drain_timeout_s, study.drain_timeout_s)
        self.assertEqual(len(condition_seed_sets), 16)
        self.assertTrue(
            all(len(seed_ids) == 30 for seed_ids in condition_seed_sets.values())
        )

    def test_strict_config_rejects_missing_unknown_and_nonfrozen_inputs(self) -> None:
        payload = json.loads(self.committed_path().read_text(encoding="utf-8"))
        missing = dict(payload)
        missing.pop("duration_s")
        with self.assertRaisesRegex(ValueError, "missing keys: duration_s"):
            StudyConfig.from_mapping(missing)

        unknown = dict(payload)
        unknown["undocumented_override"] = 1
        with self.assertRaisesRegex(ValueError, "unknown keys: undocumented_override"):
            StudyConfig.from_mapping(unknown)

        study = StudyConfig.from_mapping(payload)
        with self.assertRaisesRegex(ValueError, "at least 30 seeds"):
            replace(study, seeds=29).validate()
        with self.assertRaisesRegex(ValueError, "authoritative design is frozen"):
            replace(study, duration_s=1.1).validate()
        with self.assertRaisesRegex(ValueError, "authoritative design is frozen"):
            replace(study, suspicious_offered_pps=(0, 400)).validate()

    def test_loader_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text(
                '{"schema_version":"loopback-study-config-1.0",'
                '"schema_version":"loopback-study-config-1.0"}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON keys"):
                load_study_config(path)

    def test_manifest_and_plan_bind_the_exact_input_hash(self) -> None:
        study, input_provenance = load_study_config(self.committed_path())
        plan = build_study_trial_plan(study)
        payload = build_execution_plan_payload(study, plan, input_provenance)
        self.assertEqual(
            payload["input_configuration"]["file_sha256"],
            file_sha256(self.committed_path()),
        )
        self.assertEqual(
            payload["study_config_sha256"],
            input_provenance["parsed_config_sha256"],
        )
        with tempfile.TemporaryDirectory() as directory:
            plan_path = Path(directory) / "execution_plan.json"
            write_json(plan_path, payload)
            manifest_provenance = build_configuration_provenance(
                plan_path, payload, plan, input_provenance
            )
        self.assertTrue(
            manifest_provenance["input_config_hash_matches_execution_plan"]
        )
        self.assertEqual(
            manifest_provenance["input_configuration"]["file_sha256"],
            input_provenance["file_sha256"],
        )
        self.assertEqual(
            manifest_provenance["execution_plan_study_config_sha256"],
            input_provenance["parsed_config_sha256"],
        )

        tampered_provenance = dict(input_provenance)
        tampered_provenance["parsed_config_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "does not match"):
            build_execution_plan_payload(study, plan, tampered_provenance)

    def test_file_backed_config_must_remain_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "study.json"
            copied.write_bytes(self.committed_path().read_bytes())
            _, provenance = load_study_config(copied)
            verify_study_config_unchanged(copied, provenance)
            copied.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "changed during the run"):
                verify_study_config_unchanged(copied, provenance)


class _MemoryTransport:
    """Socket-free transport double for the threaded integration test."""

    instances: list["_MemoryTransport"] = []

    def __init__(self, protocol: str, channel: str) -> None:
        self.protocol = protocol
        self.channel = channel
        self.records: list[dict] = []
        self.errors: list[str] = []
        self.__class__.instances.append(self)

    def start(self) -> None:
        return None

    def send(self, frame: bytes) -> None:
        record = _decode_frame(frame, loopback_module.time.monotonic_ns())
        record["transport_channel"] = self.channel
        self.records.append(record)

    def record_count(self) -> int:
        return len(self.records)

    def snapshot(self) -> list[dict]:
        return [dict(record) for record in self.records]

    def error_snapshot(self) -> list[str]:
        return list(self.errors)

    def close(self) -> None:
        return None


class InMemoryIntegrationTests(unittest.TestCase):
    def test_v2_pipeline_invariants_without_opening_sockets(self) -> None:
        _MemoryTransport.instances = []
        config = PrototypeConfig(
            seed=211,
            protocol="udp",
            mode="isolated",
            duration_s=0.05,
            measurement_start_s=0.005,
            benign_offered_pps=240.0,
            suspicious_offered_pps=280.0,
            shared_capacity_pps=2_000.0,
            fast_capacity_pps=1_200.0,
            quarantine_capacity_pps=800.0,
            shared_buffer_packets=32,
            fast_buffer_packets=16,
            quarantine_buffer_packets=16,
            quarantine_dwell_s=0.001,
            packet_size_bytes=128,
            drain_timeout_s=1.0,
        )
        with tempfile.TemporaryDirectory() as directory:
            raw_path = Path(directory) / "memory.jsonl"
            with mock.patch.object(
                loopback_module, "LoopbackTransport", _MemoryTransport
            ):
                summary = run_trial(config, raw_path)
            raw_records = [
                json.loads(line)
                for line in raw_path.read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(
            {transport.channel for transport in _MemoryTransport.instances},
            {"fast", "quarantine"},
        )
        self.assertTrue(summary["valid_for_publication_aggregation"])
        self.assertTrue(summary["integrity"]["exact_sequence_integrity_valid"])
        self.assertTrue(summary["integrity"]["exact_received_metadata_valid"])
        self.assertFalse(summary["integrity"]["delivery_failure_sequences"])
        self.assertEqual(
            [record["sequence"] for record in raw_records],
            list(range(len(raw_records))),
        )
        self.assertTrue(all(record["received"] for record in raw_records))
        self.assertTrue(
            all(
                record["service_ns"]
                <= record["due_ns"]
                <= record["send_start_ns"]
                <= record["receive_ns"]
                for record in raw_records
            )
        )
        all_metrics = summary["measurement"]["all"]
        self.assertIn("ingress_cohort", all_metrics)
        self.assertIn("departure_window", all_metrics)
        self.assertNotIn("packet_goodput_pps", all_metrics)
        for route in ("fast", "quarantine"):
            service = summary["measurement"]["service_domains"][route]
            self.assertLessEqual(
                service["peak_waiting_frames"],
                service["waiting_buffer_capacity_frames"],
            )
            self.assertLessEqual(
                service["peak_resident_frames_waiting_plus_in_service"],
                service["waiting_buffer_capacity_frames"] + 1,
            )
            self.assertGreaterEqual(
                summary["measurement"]["delay_dispatchers"][route][
                    "peak_dwell_heap_frames"
                ],
                1,
            )


@unittest.skipUnless(
    os.environ.get("RUN_LIVE_LOOPBACK_TESTS") == "1",
    "set RUN_LIVE_LOOPBACK_TESTS=1 to open localhost sockets",
)
class LiveLoopbackTests(unittest.TestCase):
    def _run(self, protocol: str) -> tuple[dict, list[dict]]:
        config = PrototypeConfig(
            seed=101,
            protocol=protocol,
            mode="isolated",
            duration_s=0.08,
            measurement_start_s=0.0,
            benign_offered_pps=85.0,
            suspicious_offered_pps=110.0,
            shared_capacity_pps=900.0,
            fast_capacity_pps=500.0,
            quarantine_capacity_pps=400.0,
            shared_buffer_packets=32,
            fast_buffer_packets=16,
            quarantine_buffer_packets=16,
            quarantine_dwell_s=0.005,
            packet_size_bytes=128,
            drain_timeout_s=1.5,
        )
        with tempfile.TemporaryDirectory() as directory:
            raw_path = Path(directory) / f"{protocol}.jsonl"
            summary = run_trial(config, raw_path)
            records = [
                json.loads(line)
                for line in raw_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(len(summary["raw_event_log_sha256"]), 64)
        return summary, records

    def _assert_live_invariants(self, summary: dict, records: list[dict]) -> None:
        self.assertEqual(
            summary["expected_received_application_frames"],
            summary["actual_received_application_frames"],
        )
        self.assertTrue(summary["valid_for_publication_aggregation"])
        self.assertTrue(summary["integrity"]["sequence_partition_valid"])
        self.assertTrue(summary["integrity"]["exact_sequence_integrity_valid"])
        self.assertTrue(summary["integrity"]["exact_received_metadata_valid"])
        self.assertFalse(summary["integrity"]["delivery_failure_sequences"])
        self.assertEqual(
            summary["transport_topology"]["channels"], ["fast", "quarantine"]
        )
        self.assertTrue(
            summary["transport_topology"][
                "isolated_routes_use_distinct_transport_and_dispatcher"
            ]
        )
        self.assertIn("not XDP/eBPF", summary["claim_boundary"])
        self.assertEqual(
            [record["sequence"] for record in records], list(range(len(records)))
        )
        self.assertTrue(all(record["routing_policy"] == ORACLE_ROUTING_POLICY for record in records))
        self.assertTrue(
            all(
                record["admission_drop"] != record["admitted"]
                for record in records
            )
        )

    def test_live_udp_loopback(self) -> None:
        summary, records = self._run("udp")
        self._assert_live_invariants(summary, records)

    def test_live_tcp_loopback(self) -> None:
        summary, records = self._run("tcp")
        self._assert_live_invariants(summary, records)
        self.assertGreater(
            summary["measurement"]["all"]["departure_window"][
                "application_frame_rate_fps"
            ],
            0.0,
        )


if __name__ == "__main__":
    unittest.main()
