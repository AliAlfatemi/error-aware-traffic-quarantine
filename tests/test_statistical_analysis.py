"""Fast fixture tests for the pre-specified paired statistical stage."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import tempfile
import unittest

from experiments.statistical_analysis import (
    AnalysisError,
    BootstrapSpec,
    MetricSpec,
    bootstrap_paired_effects,
    exact_two_sided_sign_test,
    holm_adjust,
    load_config,
    load_json_strict,
    run_analysis,
    sha256_file,
    summarize_paired_comparison,
    verify_output_manifest,
    verify_upstream_manifest,
    write_json_strict,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BASE_CONFIG = PROJECT_ROOT / "configs" / "statistical_analysis.json"


def _write_manifest(root: Path, schema: str, files: list[Path]) -> None:
    mapping = {
        str(path.relative_to(root)): sha256_file(path)
        for path in sorted(files)
    }
    write_json_strict(
        root / "manifest.json",
        {"schema_version": schema, "files": mapping},
    )


def _coupled_run(defense: str, selector: str | None, goodput: float) -> dict:
    return {
        "defense": defense,
        "selector": selector,
        "sweep": {
            "name": "attack_scale_1",
            "attack_scale": 1.0,
            "quarantine_capacity_Bps": 28000.0,
            "quarantine_buffer_bytes": 24000,
            "quarantine_delay_s": 0.1,
        },
        "resource_equivalence": {
            "capacity_equal": True,
            "buffer_equal": True,
        },
        "metrics": {
            "benign_goodput_Bps": goodput,
            "offered_packets": 100,
            "offered_bytes": 100000,
            "offered_arrival_Bps": 10000.0,
            "offered_load_to_matched_capacity": 1.2,
            "matched_total_capacity_Bps": 138000.0,
        },
    }


def _loopback_summary(seed: int, mode: str, frame_rate: float) -> dict:
    return {
        "schema_version": "loopback-2.0",
        "valid_for_publication_aggregation": True,
        "config": {
            "seed": seed,
            "protocol": "udp",
            "mode": mode,
            "suspicious_offered_pps": 10.0,
            "benign_offered_pps": 160.0,
            "duration_s": 1.0,
            "measurement_start_s": 0.2,
            "routing_policy": "oracle_ground_truth_label",
        },
        "execution": {
            "paired_block_id": f"udp_load_10_seed_{seed}",
            "within_block_order": 0 if mode == "shared" else 1,
        },
        "offered_schedule_sha256": f"{seed:064x}",
        "integrity": {
            "exact_received_metadata_valid": True,
            "exact_sequence_integrity_valid": True,
            "sequence_partition_valid": True,
        },
        "resource_accounting": {
            "capacity_pps": {
                "equal_total": True,
                "shared": 320.0,
                "isolated_fast_plus_quarantine": 320.0,
            },
            "waiting_buffer_frames": {
                "equal_total": True,
                "shared": 96,
                "isolated_fast_plus_quarantine": 96,
            },
        },
        "measurement": {
            "by_label": {
                "benign": {
                    "departure_window": {
                        "application_frame_rate_fps": frame_rate,
                    },
                    "ingress_cohort": {
                        "end_to_end_loss_fraction": 0.1 if mode == "shared" else 0.02,
                        "latency_ms": {"p99": 30.0 if mode == "shared" else 10.0},
                    },
                },
                "attack": {
                    "departure_window": {
                        "application_frame_rate_fps": 9.0 if mode == "shared" else 5.0,
                    }
                },
            }
        },
    }


class StatisticalPrimitiveTests(unittest.TestCase):
    def test_exact_sign_test_and_holm(self) -> None:
        self.assertEqual(exact_two_sided_sign_test(0, 0), 1.0)
        self.assertEqual(exact_two_sided_sign_test(3, 0), 0.25)
        adjusted = holm_adjust([0.01, 0.04, 0.03])
        self.assertEqual(adjusted, [0.03, 0.06, 0.06])

    def test_bootstrap_is_deterministic_and_paired(self) -> None:
        first = bootstrap_paired_effects([1.0, 2.0, 3.0], 500, 0.95, 91)
        second = bootstrap_paired_effects([1.0, 2.0, 3.0], 500, 0.95, 91)
        self.assertEqual(first, second)
        self.assertEqual(first["mean"]["estimate"], 2.0)
        self.assertEqual(first["median"]["estimate"], 2.0)

    def test_relative_effect_is_withheld_for_zero_denominator(self) -> None:
        metric = MetricSpec(
            id="loss",
            path="loss",
            unit="fraction",
            better="lower",
            practical_threshold=0.02,
            relative_denominator_min_abs=0.005,
            tie_tolerance=1e-12,
        )
        result = summarize_paired_comparison(
            treatment=[0.0, 0.0, 0.0],
            comparator=[0.0, 0.1, 0.2],
            seeds=[1, 2, 3],
            metric=metric,
            maximum_denominator_cv=1.0,
            bootstrap=BootstrapSpec(200, 7, 0.95),
            stable_seed=11,
        )
        self.assertFalse(result["relative_effect"]["available"])
        self.assertEqual(result["pair_count"], 3)
        self.assertEqual(result["paired_outcomes_oriented_by_better_direction"]["wins"], 2)

    def test_config_is_frozen_and_rejects_unknown_keys(self) -> None:
        config = load_config(BASE_CONFIG)
        with self.assertRaises(FrozenInstanceError):
            config.bootstrap.seed = 4  # type: ignore[misc]
        with tempfile.TemporaryDirectory() as directory:
            mapping = load_json_strict(BASE_CONFIG)
            mapping["unknown"] = 1
            path = Path(directory) / "bad.json"
            write_json_strict(path, mapping)
            with self.assertRaises(AnalysisError):
                load_config(path)

    def test_strict_json_rejects_nonfinite_and_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            nonfinite = Path(directory) / "nonfinite.json"
            nonfinite.write_text('{"x": NaN}\n', encoding="utf-8")
            with self.assertRaises(AnalysisError):
                load_json_strict(nonfinite)
            duplicate = Path(directory) / "duplicate.json"
            duplicate.write_text('{"x": 1, "x": 2}\n', encoding="utf-8")
            with self.assertRaises(AnalysisError):
                load_json_strict(duplicate)


class EndToEndFixtureTests(unittest.TestCase):
    def _build_fixture(self, root: Path) -> Path:
        coupled = root / "coupled"
        coupled_raw = coupled / "raw"
        coupled_raw.mkdir(parents=True)
        coupled_files: list[Path] = []
        for offset, seed in enumerate((101, 103, 107)):
            path = coupled_raw / f"heldout_seed_{seed}.json"
            write_json_strict(
                path,
                {
                    "seed": seed,
                    "split": "heldout",
                    "runs": [
                        _coupled_run("shared_fifo", None, 10000.0 + offset),
                        _coupled_run(
                            "capacity_isolated_quarantine",
                            "multifeature",
                            18000.0 + offset,
                        ),
                    ],
                },
            )
            coupled_files.append(path)
        _write_manifest(coupled, "coupled-1.1", coupled_files)

        loopback = root / "loopback"
        loopback_raw = loopback / "raw"
        loopback_raw.mkdir(parents=True)
        loopback_files: list[Path] = []
        for offset, seed in enumerate((101, 103, 107)):
            for mode in ("shared", "isolated"):
                path = loopback_raw / f"udp_{mode}_load_10_seed_{seed}.summary.json"
                rate = (100.0 + offset) if mode == "shared" else (130.0 + offset)
                write_json_strict(path, _loopback_summary(seed, mode, rate))
                loopback_files.append(path)
        _write_manifest(loopback, "loopback-2.0", loopback_files)

        mapping = load_json_strict(BASE_CONFIG)
        mapping["bootstrap"]["replicates"] = 200
        mapping["coupled"]["input_dir"] = str(coupled)
        mapping["coupled"]["expected_seed_count"] = 3
        mapping["coupled"]["attack_load_points"] = [1.0]
        mapping["coupled"]["metrics"] = [mapping["coupled"]["metrics"][0]]
        mapping["coupled"]["families"] = [mapping["coupled"]["families"][0]]
        mapping["coupled"]["families"][0]["metric_ids"] = ["benign_goodput_Bps"]
        mapping["loopback"]["input_dir"] = str(loopback)
        mapping["loopback"]["expected_seed_count"] = 3
        mapping["loopback"]["protocols"] = ["udp"]
        mapping["loopback"]["suspicious_offered_pps"] = [10.0]
        config_path = root / "fixture_config.json"
        write_json_strict(config_path, mapping)
        return config_path

    def test_full_fixture_run_is_deterministic_and_manifest_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = self._build_fixture(root)
            config = load_config(config_path)
            first_output = root / "analysis_one"
            second_output = root / "analysis_two"
            first = run_analysis(first_output, config, config_path)
            second = run_analysis(second_output, config, config_path)
            self.assertEqual(first, second)
            self.assertEqual(sha256_file(first_output / "summary.json"), sha256_file(second_output / "summary.json"))
            self.assertEqual(set(verify_output_manifest(first_output)), {"config.json", "summary.json"})
            self.assertEqual(len(first["comparison_families"]), 3)
            self.assertEqual(
                first["public_dataset_scope"]["included_in_paired_hypothesis_tests"],
                False,
            )
            for family in first["comparison_families"]:
                for result in family["results"]:
                    self.assertEqual(result["pair_count"], 3)
                    self.assertIsNotNone(result["nonparametric_test"]["p_value_holm"])

    def test_refuses_nonempty_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = self._build_fixture(root)
            output = root / "occupied"
            output.mkdir()
            (output / "keep.txt").write_text("do not overwrite\n", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                run_analysis(output, load_config(config_path), config_path)
            self.assertEqual((output / "keep.txt").read_text(encoding="utf-8"), "do not overwrite\n")

    def test_upstream_manifest_tampering_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "data.json"
            write_json_strict(data, {"value": 1})
            _write_manifest(root, "fixture-1", [data])
            write_json_strict(data, {"value": 2})
            with self.assertRaises(AnalysisError):
                verify_upstream_manifest(root, "fixture-1")


if __name__ == "__main__":
    unittest.main()
