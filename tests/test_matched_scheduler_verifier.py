from __future__ import annotations

import base64
import hashlib
import json
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest import mock

from experiments import matched_scheduler_analysis as analysis
from testbed.matched_scheduler_lib import (
    PROJECT_ROOT,
    build_execution_plan,
    effective_profile,
    load_config,
    make_tree_manifest,
    object_sha256,
    requested_tc_spec,
)
from testbed.run_matched_scheduler import validate_within_pair_fidelity


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def _encoded_lateness(values: list[int]) -> dict:
    raw = b"".join(struct.pack("<Q", value) for value in values)
    return {
        "encoding": analysis.LATENESS_SAMPLE_ENCODING,
        "sample_count": len(values),
        "uncompressed_sha256": hashlib.sha256(raw).hexdigest(),
        "data_base64": base64.b64encode(zlib.compress(raw, level=9)).decode(
            "ascii"
        ),
    }


def _threshold_regression_pair(
    config: dict, profile_name: str
) -> tuple[dict, str, dict[str, dict]]:
    plan = build_execution_plan(config, profile_name)
    pair_id = "standard_borrowable_overload_000"
    trials = {
        trial["arm_id"]: trial
        for trial in plan["trials"]
        if trial["pair_id"] == pair_id
    }

    def sender(
        arm_id: str, label: str
    ) -> dict:
        counts = (
            {"warmup": 30, "measurement": 75 if arm_id == "B3" else 74}
            if label == "benign"
            else {"warmup": 3, "measurement": 8}
        )
        samples = {
            phase: [
                2_000_000
                if label == "benign"
                and phase == "measurement"
                and arm_id == "B5"
                else 0
            ]
            * count
            for phase, count in counts.items()
        }
        return {
            "final_record": {
                "sent": {
                    phase: {"packets": count}
                    for phase, count in counts.items()
                },
                "send_lateness_samples_by_phase": {
                    phase: _encoded_lateness(values)
                    for phase, values in samples.items()
                },
            }
        }

    arms = {}
    for arm_id, trial in trials.items():
        arms[arm_id] = {
            "schema_version": analysis.ARM_SCHEMA_VERSION,
            "profile": profile_name,
            "evidentiary": plan["profile"]["evidentiary"],
            "trial": trial,
            "valid": True,
            "invalid_reasons": [],
            "cpu_assignment": config["execution"]["cpu_affinity_ids"],
            "tc_requested_spec": requested_tc_spec(
                config, arm_id, trial["reservation_id"]
            ),
            "tc_snapshots": {
                name: {} for name in analysis.TC_SNAPSHOT_NAMES
            },
            "processes": {
                "receiver": {"final_record": {}},
                "benign_sender": sender(arm_id, "benign"),
                "suspicious_sender": sender(arm_id, "suspicious"),
            },
        }
    return plan["profile"], pair_id, arms


def _tc_snapshot(spec: dict, arm_id: str) -> dict:
    classes = []
    for classid, values in (
        ("1:1", spec["root"]),
        (spec["classes"]["fast"]["classid"], spec["classes"]["fast"]),
        (
            spec["classes"]["suspicious"]["classid"],
            spec["classes"]["suspicious"],
        ),
    ):
        record = {
            "class": "htb",
            "handle": classid,
            "rate": values["rate_Bps"],
            "ceil": values["ceil_Bps"],
            "burst": values["burst_bytes"],
            "cburst": values["cburst_bytes"],
            "prio": values["priority"],
            "linklayer": values["linklayer"],
        }
        if classid == "1:1":
            record["root"] = True
        else:
            record["parent"] = values["parent"]
            record["quantum"] = values["quantum_bytes"]
        classes.append(record)
    return {
        "capture_started_monotonic_ns": 1,
        "capture_finished_monotonic_ns": 2,
        "commands": {
            "qdisc": {
                "argv": [
                    "tc", "-s", "-d", "-j", "qdisc", "show", "dev",
                    spec["interface"],
                ],
                "records": [
                    {
                        "kind": "htb",
                        "handle": "1:",
                        "root": True,
                        "options": {
                            "default": "0x20",
                            "r2q": spec["root"]["r2q"],
                            "direct_qlen": spec["root"]["direct_qlen_packets"],
                        },
                    },
                    {
                        "kind": "bfifo",
                        "handle": "10:",
                        "parent": "1:10",
                        "options": {
                            "limit": spec["classes"]["fast"][
                                "bfifo_limit_bytes"
                            ]
                        },
                    },
                    {
                        "kind": "bfifo",
                        "handle": "20:",
                        "parent": "1:20",
                        "options": {
                            "limit": spec["classes"]["suspicious"][
                                "bfifo_limit_bytes"
                            ]
                        },
                    },
                ]
            },
            "class": {
                "argv": [
                    "tc", "-s", "-d", "-j", "class", "show", "dev",
                    spec["interface"],
                ],
                "records": classes,
            },
            "filter": {
                "argv": [
                    "tc", "-s", "-d", "-j", "filter", "show", "dev",
                    spec["interface"],
                ],
                "records": [
                    {
                        "kind": "u32",
                        "parent": "1:",
                        "protocol": "ip",
                        "pref": 1,
                        "chain": 0,
                    },
                    {
                        "kind": "u32",
                        "parent": "1:",
                        "protocol": "ip",
                        "pref": 1,
                        "chain": 0,
                        "options": {"fh": "800:", "ht_divisor": 1},
                    },
                    {
                        "kind": "u32",
                        "parent": "1:",
                        "protocol": "ip",
                        "pref": 1,
                        "chain": 0,
                        "order": 2048,
                        "options": {
                            "fh": "800::800",
                            "bkt": "0",
                            "key_ht": "800",
                            "flowid": "1:10",
                            "match": {
                                "value": "100000",
                                "mask": "ff0000",
                                "off": 0,
                            },
                        },
                    },
                    {
                        "kind": "u32",
                        "parent": "1:",
                        "protocol": "ip",
                        "pref": 2,
                        "chain": 0,
                    },
                    {
                        "kind": "u32",
                        "parent": "1:",
                        "protocol": "ip",
                        "pref": 2,
                        "chain": 0,
                        "options": {"fh": "801:", "ht_divisor": 1},
                    },
                    {
                        "kind": "u32",
                        "parent": "1:",
                        "protocol": "ip",
                        "pref": 2,
                        "chain": 0,
                        "order": 2048,
                        "options": {
                            "fh": "801::800",
                            "bkt": "0",
                            "key_ht": "801",
                            "flowid": "1:20",
                            "match": {"value": "0", "mask": "ff0000", "off": 0},
                        },
                    },
                ]
            },
        },
    }


class TcNormalizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_config(PROJECT_ROOT / "configs" / "matched_scheduler.json")

    def test_normalized_live_pair_diff_is_only_the_two_child_ceils(self) -> None:
        normalized = {}
        for arm_id in ("B3", "B5"):
            spec = requested_tc_spec(self.config, arm_id)
            snapshot = _tc_snapshot(spec, arm_id)
            # Fedora may omit the root class's inoperative prio/quantum while
            # retaining both on the child classes.
            snapshot["commands"]["class"]["records"][0].pop("prio", None)
            snapshot["commands"]["class"]["records"][0].pop("quantum", None)
            normalized[arm_id], errors = analysis.validate_normalized_live_tc(
                snapshot, spec
            )
            self.assertEqual(errors, [])
        self.assertEqual(
            analysis.normalized_tc_pair_differences(
                normalized["B3"], normalized["B5"]
            ),
            {"classes.1:10.ceil_Bps", "classes.1:20.ceil_Bps"},
        )


class RawValidityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_config(PROJECT_ROOT / "configs" / "matched_scheduler.json")
        cls.trial = build_execution_plan(cls.config, "smoke")["trials"][0]
        cls.profile = effective_profile(cls.config, "smoke")

    def test_any_phase_send_error_is_independently_invalid(self) -> None:
        label = "benign"
        rate = self.trial["benign_target_pps"]
        offset = analysis._schedule_offset_ns(
            self.trial["traffic_seed"], label, rate
        )
        warmup = analysis._planned_packet_count(
            self.trial["warmup_s"], rate, offset
        )
        total = analysis._planned_packet_count(
            self.trial["warmup_s"] + self.trial["measurement_s"], rate, offset
        )
        planned = {"warmup": warmup, "measurement": total - warmup, "total": total}
        sent_counts = {
            "warmup": planned["warmup"] - 1,
            "measurement": planned["measurement"],
        }
        packet_size = self.config["traffic"]["packet_payload_bytes"]
        sender = {
            "traffic_class": label,
            "role": "sender",
            "final": True,
            "tos": self.config["service"]["fast_tos"],
            "source_port": self.config["network"]["benign_source_port"],
            "target_port": self.config["network"]["receiver_port"],
            "seed": self.trial["traffic_seed"],
            "target_rate_pps": rate,
            "packet_size_bytes": packet_size,
            "schedule_offset_ns": offset,
            "planned_packets": planned,
            "missed_deadline_policy": "skip_expired_slot_never_catch_up",
            "missed_deadlines": {
                "warmup": 0,
                "measurement": 0,
                "total": 0,
                "rtt_probes": {"warmup": 0, "measurement": 0},
            },
            "sent": {
                phase: {
                    "packets": count,
                    "bytes": count * packet_size,
                    "rtt_probe_packets": 0,
                }
                for phase, count in sent_counts.items()
            },
            "send_errors": 1,
            "send_errors_by_phase": {"warmup": 1, "measurement": 0},
            "send_lateness_by_phase": {
                phase: {
                    "sample_count": count,
                    "mean_ns": 0.0,
                    "max_ns": 0,
                    "p99_ns": 0,
                }
                for phase, count in sent_counts.items()
            },
            "send_lateness_sample_count": sum(sent_counts.values()),
            "send_lateness_mean_ns": 0.0,
            "send_lateness_max_ns": 0,
            "send_lateness_p99_ns": 0,
            "socket_rxq_overflow_drops": 0,
            "udp_snmp_delta": {"InErrors": 0, "RcvbufErrors": 0},
            "rtt_probe_policy": "fixed_rate_flagged_subset_echo_only",
            "rtt_probes": {},
        }
        errors = analysis._sender_raw_errors(
            self.config, self.profile, self.trial, label, sender
        )
        self.assertIn("benign_sender_send_errors_nonzero:warmup", errors)

    def test_tc_counters_must_be_nonnegative_integers(self) -> None:
        snapshot = {
            "commands": {
                "qdisc": {"records": [{"handle": "1:", "packets": 1.0}]}
            }
        }
        self.assertIsNone(
            analysis._tc_record_counter(snapshot, "qdisc", "1:", "packets")
        )
        snapshot["commands"]["qdisc"]["records"][0]["packets"] = 1
        self.assertEqual(
            analysis._tc_record_counter(snapshot, "qdisc", "1:", "packets"),
            1,
        )

    def test_lossless_lateness_encoding_is_exact_and_tamper_evident(self) -> None:
        samples = [0, 3, 7, 11, 10_000_000]
        raw = b"".join(struct.pack("<Q", value) for value in samples)
        evidence = {
            "encoding": analysis.LATENESS_SAMPLE_ENCODING,
            "sample_count": len(samples),
            "uncompressed_sha256": hashlib.sha256(raw).hexdigest(),
            "data_base64": base64.b64encode(zlib.compress(raw, level=9)).decode(
                "ascii"
            ),
        }
        decoded, errors = analysis._decode_lateness_samples(
            evidence,
            expected_sample_count=len(samples),
            label="test",
        )
        self.assertEqual(errors, [])
        self.assertEqual(decoded, samples)
        self.assertEqual(
            analysis._lateness_summary(decoded or []),
            {
                "sample_count": 5,
                "mean_ns": 2_000_004.2,
                "max_ns": 10_000_000,
                "p99_ns": 10_000_000,
            },
        )

        forged = {**evidence, "uncompressed_sha256": "0" * 64}
        decoded, errors = analysis._decode_lateness_samples(
            forged,
            expected_sample_count=len(samples),
            label="test",
        )
        self.assertIsNone(decoded)
        self.assertEqual(errors, ["test:encoded_sample_sha256_mismatch"])

        trailing_stream = zlib.compress(raw, level=9) + zlib.compress(b"trailing")
        forged = {
            **evidence,
            "data_base64": base64.b64encode(trailing_stream).decode("ascii"),
        }
        decoded, errors = analysis._decode_lateness_samples(
            forged,
            expected_sample_count=len(samples),
            label="test",
        )
        self.assertIsNone(decoded)
        self.assertEqual(
            errors, ["test:encoded_sample_stream_or_length_invalid"]
        )

        decoded, errors = analysis._decode_lateness_samples(
            {**evidence, "sample_count": 1_000_000},
            expected_sample_count=1_000_000,
            maximum_sample_count=len(samples),
            label="test",
        )
        self.assertIsNone(decoded)
        self.assertEqual(
            errors, ["test:expected_sample_count_exceeds_schedule"]
        )

        oversized = {
            "encoding": analysis.LATENESS_SAMPLE_ENCODING,
            "sample_count": 0,
            "uncompressed_sha256": hashlib.sha256(b"").hexdigest(),
            "data_base64": base64.b64encode(b"x" * 1025).decode("ascii"),
        }
        decoded, errors = analysis._decode_lateness_samples(
            oversized,
            expected_sample_count=0,
            maximum_sample_count=0,
            label="test",
        )
        self.assertIsNone(decoded)
        self.assertEqual(
            errors, ["test:encoded_sample_compressed_size_exceeded"]
        )

    def test_pair_fidelity_recomputation_matches_runner_lossless_schema(self) -> None:
        plan = {
            "profile": self.profile,
            "pairs": [
                {
                    "pair_id": "p",
                    "warmup_s": self.trial["warmup_s"],
                    "measurement_s": self.trial["measurement_s"],
                    "traffic_seed": self.trial["traffic_seed"],
                    "benign_target_pps": self.trial["benign_target_pps"],
                    "suspicious_target_pps": self.trial[
                        "suspicious_target_pps"
                    ],
                }
            ],
        }

        def encoded(values: list[int]) -> dict:
            raw = b"".join(struct.pack("<Q", value) for value in values)
            return {
                "encoding": analysis.LATENESS_SAMPLE_ENCODING,
                "sample_count": len(values),
                "uncompressed_sha256": hashlib.sha256(raw).hexdigest(),
                "data_base64": base64.b64encode(
                    zlib.compress(raw, level=9)
                ).decode("ascii"),
            }

        def arm(arm_id: str, shift: int) -> dict:
            processes = {}
            for role in ("benign_sender", "suspicious_sender"):
                by_phase = {
                    "warmup": [1 + shift, 2 + shift],
                    "measurement": [3 + shift, 4 + shift, 5 + shift],
                }
                processes[role] = {
                    "final_record": {
                        "sent": {
                            phase: {"packets": len(values)}
                            for phase, values in by_phase.items()
                        },
                        "send_lateness_by_phase": {
                            phase: analysis._lateness_summary(values)
                            for phase, values in by_phase.items()
                        },
                        "send_lateness_samples_by_phase": {
                            phase: encoded(values)
                            for phase, values in by_phase.items()
                        },
                    }
                }
            return {
                "trial": {"trial_id": f"p_{arm_id}"},
                "processes": processes,
            }

        arms_by_id = {"p_B3": arm("B3", 0), "p_B5": arm("B5", 1)}
        runner = validate_within_pair_fidelity(
            self.config, plan, arms_by_id
        )
        verifier = analysis.recompute_pair_fidelity(
            plan, list(arms_by_id.values())
        )
        self.assertEqual(verifier, runner)

    def _threshold_reasons(self, profile_name: str) -> list[str]:
        profile, pair_id, arms = _threshold_regression_pair(
            self.config, profile_name
        )
        with (
            mock.patch.object(
                analysis, "recompute_arm_invalid_reasons", return_value=[]
            ),
            mock.patch.object(analysis, "normalize_live_tc", return_value={}),
            mock.patch.object(
                analysis,
                "normalized_tc_pair_differences",
                return_value={
                    "classes.1:10.ceil_Bps",
                    "classes.1:20.ceil_Bps",
                },
            ),
        ):
            return analysis.validate_pair(
                self.config,
                pair_id,
                arms,
                independently_validate_raw=True,
                authenticated_profile=profile,
            )

    def test_pair_validation_uses_smoke_profile_thresholds(self) -> None:
        self.assertEqual(self._threshold_reasons("smoke"), [])

    def test_pair_validation_uses_authoritative_profile_thresholds(self) -> None:
        reasons = self._threshold_reasons("authoritative")
        self.assertIn(
            "within_pair_sent_count_gate:benign:measurement", reasons
        )
        self.assertIn(
            "within_pair_lateness_p99_gate:benign:measurement", reasons
        )

    def test_pair_validation_rejects_missing_or_tampered_plan_profile(self) -> None:
        profile, pair_id, arms = _threshold_regression_pair(
            self.config, "smoke"
        )
        with self.assertRaisesRegex(ValueError, "requires authenticated"):
            analysis.validate_pair(
                self.config,
                pair_id,
                arms,
                independently_validate_raw=True,
            )
        tampered = json.loads(json.dumps(profile))
        tampered["validity"][
            "maximum_within_pair_lateness_p99_difference_ns"
        ] = 20_000_000
        with self.assertRaisesRegex(ValueError, "differs from frozen config"):
            analysis.validate_pair(
                self.config,
                pair_id,
                arms,
                independently_validate_raw=True,
                authenticated_profile=tampered,
            )


class TransactionAndVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config_path = PROJECT_ROOT / "configs" / "matched_scheduler.json"
        cls.config = load_config(cls.config_path)
        cls.plan = build_execution_plan(cls.config, "smoke")

    def _campaign(self) -> dict:
        return {
            "profile": "smoke",
            "evidentiary": False,
            "campaign_manifest_payload_sha256": "a" * 64,
            "setup_success": True,
            "teardown_success": True,
            "planned_arm_count": len(self.plan["trials"]),
            "recorded_arm_count": len(self.plan["trials"]),
        }

    def _summary(self, campaign: dict) -> dict:
        return {
            "schema_version": analysis.ANALYSIS_SCHEMA_VERSION,
            "config_sha256": object_sha256(self.config),
            "protocol_sha256": self.config["protocol_sha256"],
            "campaign_manifest_payload_sha256": campaign[
                "campaign_manifest_payload_sha256"
            ],
            "valid_pair_count": len(self.plan["pairs"]),
            "invalid_pair_count": 0,
            "mechanical_gate": {"study_B_pass": True},
            "claim_permitted": False,
        }

    def test_analysis_failure_leaves_no_partial_analysis_or_staging_tree(self) -> None:
        with tempfile.TemporaryDirectory() as parent_text:
            parent = Path(parent_text)
            result = parent / "result"
            result.mkdir()
            _write_json(
                result / "campaign_manifest.json",
                {"profile": "smoke", "evidentiary": False},
            )
            campaign = self._campaign()
            with (
                mock.patch.object(
                    analysis, "_verify_campaign", return_value=(campaign, [])
                ),
                mock.patch.object(
                    analysis,
                    "_recompute_analysis",
                    return_value=([], [], self._summary(campaign)),
                ),
                mock.patch.object(
                    analysis, "_write_pairs_csv", side_effect=RuntimeError("boom")
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "boom"):
                    analysis.analyze(result, config_path=self.config_path)
            self.assertFalse((result / "analysis").exists())
            self.assertFalse((result / "manifest.json").exists())
            self.assertEqual(list(parent.glob(".result.analysis-*")), [])

    def test_completed_verifier_is_read_only_and_exactly_recomputes_csv(self) -> None:
        with tempfile.TemporaryDirectory() as parent_text:
            result = Path(parent_text) / "result"
            result.mkdir()
            _write_json(
                result / "campaign_manifest.json",
                {"profile": "smoke", "evidentiary": False},
            )
            campaign = self._campaign()
            summary = self._summary(campaign)
            recomputed = ([], [], summary)
            with (
                mock.patch.object(
                    analysis, "_verify_campaign", return_value=(campaign, [])
                ),
                mock.patch.object(
                    analysis, "_recompute_analysis", return_value=recomputed
                ),
            ):
                analysis.analyze(result, config_path=self.config_path)
                before = {
                    path.relative_to(result).as_posix(): (
                        path.read_bytes(),
                        path.stat().st_mtime_ns,
                    )
                    for path in result.rglob("*")
                    if path.is_file()
                }
                verified = analysis.verify_completed_result_tree(
                    result, config_path=self.config_path
                )
                after = {
                    path.relative_to(result).as_posix(): (
                        path.read_bytes(),
                        path.stat().st_mtime_ns,
                    )
                    for path in result.rglob("*")
                    if path.is_file()
                }
            self.assertTrue(verified["verified"])
            self.assertTrue(verified["read_only"])
            self.assertEqual(before, after)

            # Reseal a semantically forged CSV so the nested hashes all pass;
            # deterministic recomputation must still reject it.
            csv_path = result / "analysis" / "paired_effects.csv"
            csv_path.write_bytes(csv_path.read_bytes() + b"forged\n")
            _write_json(
                result / "analysis" / "manifest.json",
                {
                    **make_tree_manifest(
                        result / "analysis",
                        excluded=[result / "analysis" / "manifest.json"],
                    ),
                    "schema_version": analysis.ANALYSIS_MANIFEST_SCHEMA_VERSION,
                },
            )
            _write_json(
                result / "manifest.json",
                make_tree_manifest(result, excluded=[result / "manifest.json"]),
            )
            with (
                mock.patch.object(
                    analysis, "_verify_campaign", return_value=(campaign, [])
                ),
                mock.patch.object(
                    analysis, "_recompute_analysis", return_value=recomputed
                ),
                self.assertRaisesRegex(ValueError, "paired-effects CSV"),
            ):
                analysis.verify_completed_result_tree(
                    result, config_path=self.config_path
                )

            csv_path.write_bytes(analysis._pairs_csv_bytes([]))
            forged_summary = {**summary, "claim_permitted": True}
            _write_json(result / "analysis" / "summary.json", forged_summary)
            _write_json(
                result / "analysis" / "manifest.json",
                {
                    **make_tree_manifest(
                        result / "analysis",
                        excluded=[result / "analysis" / "manifest.json"],
                    ),
                    "schema_version": analysis.ANALYSIS_MANIFEST_SCHEMA_VERSION,
                },
            )
            _write_json(
                result / "manifest.json",
                make_tree_manifest(result, excluded=[result / "manifest.json"]),
            )
            with (
                mock.patch.object(
                    analysis, "_verify_campaign", return_value=(campaign, [])
                ),
                mock.patch.object(
                    analysis, "_recompute_analysis", return_value=recomputed
                ),
                self.assertRaisesRegex(ValueError, "summary/statistics/gates"),
            ):
                analysis.verify_completed_result_tree(
                    result, config_path=self.config_path
                )

    def test_completed_verifier_rejects_noncanonical_config_path_first(self) -> None:
        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text)
            copied_config = directory / "config.json"
            copied_config.write_bytes(self.config_path.read_bytes())
            with self.assertRaisesRegex(ValueError, "canonical config"):
                analysis.verify_completed_result_tree(
                    directory, config_path=copied_config
                )

    def test_inventory_rejects_duplicate_paths_even_when_resealed(self) -> None:
        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text)
            (directory / "payload.txt").write_text("payload\n", encoding="utf-8")
            inventory = make_tree_manifest(directory)
            inventory["files"].append(dict(inventory["files"][0]))
            inventory["file_count"] = len(inventory["files"])
            inventory["content_fingerprint_sha256"] = object_sha256(
                inventory["files"]
            )
            with self.assertRaisesRegex(ValueError, "duplicate paths"):
                analysis._verify_inventory_exact(
                    directory, inventory, excluded_relative_paths=set()
                )


if __name__ == "__main__":
    unittest.main()
