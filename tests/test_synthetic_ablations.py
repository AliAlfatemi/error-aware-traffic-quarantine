from __future__ import annotations

import json
import math
import tempfile
import unittest
from dataclasses import FrozenInstanceError, asdict, replace
from pathlib import Path

import numpy as np

from experiments.coupled_simulation import FlowTrace, SelectorModel, canonical_json_sha256
from experiments.synthetic_ablations import (
    DEFAULT_CONFIG,
    FAILURE_SCENARIOS,
    _bootstrap_mean_ci,
    _wilson_interval,
    aggregate_boundary_rows,
    aggregate_cardinality_rows,
    aggregate_failure_rows,
    aggregate_observation_rows,
    build_provenance,
    detector_failure_row,
    fit_window_models,
    load_ablation_config,
    load_coupled_config,
    observation_window_rows,
    run_synthetic_ablations,
    state_cardinality_row,
    threshold_boundary_rows,
    write_json,
)


def constant_iat_flow(mean_iat_s: float, window: int = 20) -> FlowTrace:
    iats = tuple(mean_iat_s for _ in range(window + 2))
    offsets = tuple(float(value) for value in np.concatenate(([0.0], np.cumsum(iats))))
    return FlowTrace(
        flow_id="boundary-unit",
        split="unit",
        seed=1,
        family="attack_jitter",
        true_label="attack",
        protocol="UDP-like",
        start_time_s=0.0,
        iats_s=iats,
        arrival_offsets_s=offsets,
        packet_sizes_bytes=tuple(800 for _ in range(len(iats) + 1)),
    )


class ConfigAndProvenanceTests(unittest.TestCase):
    def test_committed_config_is_frozen_dense_and_has_disjoint_thirty_seed_holdout(self) -> None:
        config = load_ablation_config()
        self.assertEqual(len(config.heldout_seeds), 30)
        self.assertFalse(set(config.train_seeds) & set(config.calibration_seeds))
        self.assertFalse(set(config.train_seeds) & set(config.heldout_seeds))
        self.assertFalse(set(config.calibration_seeds) & set(config.heldout_seeds))
        self.assertGreaterEqual(config.boundary_points, 41)
        self.assertEqual(config.boundary_points % 2, 1)
        self.assertIn(config.reference_window_iats, config.observation_windows_iats)
        self.assertLess(min(config.state_cardinalities), config.state_map_capacity_entries)
        self.assertGreater(max(config.state_cardinalities), config.state_map_capacity_entries)
        self.assertTrue({4095, 4096, 4097}.issubset(config.state_cardinalities))
        with self.assertRaises(FrozenInstanceError):
            config.reference_window_iats = 8  # type: ignore[misc]
        with self.assertRaises(ValueError):
            replace(config, heldout_seeds=config.heldout_seeds[:29])
        with self.assertRaises(ValueError):
            replace(config, boundary_points=40)
        with self.assertRaises(ValueError):
            replace(config, boundary_jitter_cvs=(math.nan,))

    def test_input_source_dependency_and_runtime_fingerprints_are_stable_and_finite(self) -> None:
        config = load_ablation_config()
        coupled = load_coupled_config()
        first = build_provenance(config, DEFAULT_CONFIG.resolve(), coupled, Path("configs/coupled_simulation.json").resolve())
        second = build_provenance(config, DEFAULT_CONFIG.resolve(), coupled, Path("configs/coupled_simulation.json").resolve())
        self.assertEqual(first, second)
        self.assertEqual(first["ablation_config_canonical_sha256"], canonical_json_sha256(asdict(config)))
        for key in (
            "input_file_fingerprint_sha256", "source_fingerprint_sha256",
            "dependency_fingerprint_sha256", "runtime_fingerprint_sha256",
            "combined_input_fingerprint_sha256",
        ):
            self.assertEqual(len(first[key]), 64)
        json.dumps(first, allow_nan=False)

    def test_nonempty_output_is_rejected_before_any_experiment_runs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "sentinel.txt").write_text("preserve", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                run_synthetic_ablations(output)
            self.assertEqual((output / "sentinel.txt").read_text(encoding="utf-8"), "preserve")

    def test_strict_json_writer_rejects_nan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                write_json(Path(directory) / "bad.json", {"value": math.nan})


class BoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_ablation_config()
        cls.coupled = load_coupled_config()
        cls.models, _ = fit_window_models(cls.config, cls.coupled)

    def test_rate_comparator_includes_equality_and_excludes_value_above(self) -> None:
        flow_at_boundary = constant_iat_flow(0.01)
        threshold = float(np.mean(flow_at_boundary.iats_s[:20]))
        selector = SelectorModel("rate_only", 20, rate_threshold_s=threshold)
        self.assertTrue(selector.decide(flow_at_boundary).predicted_attack)
        self.assertTrue(selector.decide(constant_iat_flow(threshold - 1e-6)).predicted_attack)
        self.assertFalse(selector.decide(constant_iat_flow(threshold + 1e-6)).predicted_attack)

    def test_reduced_dense_boundary_rows_retain_center_and_window_aware_tail(self) -> None:
        config = replace(
            self.config,
            boundary_points=41,
            boundary_jitter_cvs=(0.0, 0.1),
            boundary_phase_fractions=(0.0,),
            boundary_selectors=("rate_only",),
            boundary_tail_iats=2,
        )
        rows = threshold_boundary_rows(1009, config, self.models[config.boundary_window_iats])
        self.assertEqual(len(rows), 41 * 2 * 3)
        center = [
            row for row in rows
            if row["grid_index"] == 20
            and row["scenario"] == "attack_stationary"
            and row["jitter_cv_target"] == 0.0
        ][0]
        self.assertAlmostEqual(center["target_mean_iat_s"], center["frozen_rate_threshold_s"])
        self.assertEqual(center["predicted_attack"], 1)
        adaptive = [
            row for row in rows
            if row["scenario"] == "attack_window_aware_tail_acceleration"
        ]
        self.assertTrue(all(float(row["tail_rate_multiplier_vs_prefix"]) > 4.0 for row in adaptive))
        paired_prefixes: dict[tuple[int, float, float], set[float]] = {}
        for row in rows:
            key = (
                int(row["grid_index"]),
                float(row["jitter_cv_target"]),
                float(row["phase_fraction"]),
            )
            paired_prefixes.setdefault(key, set()).add(float(row["effective_mean_iat_s"]))
        self.assertTrue(all(len(values) == 1 for values in paired_prefixes.values()))
        json.dumps(rows, allow_nan=False)

    def test_wilson_and_bootstrap_intervals_are_finite_and_deterministic(self) -> None:
        self.assertEqual(_wilson_interval(0, 0), [None, None])
        interval = _wilson_interval(10, 30)
        self.assertTrue(0.0 <= float(interval[0]) < float(interval[1]) <= 1.0)
        first = _bootstrap_mean_ci([1.0, 2.0, 4.0], 50, 123)
        second = _bootstrap_mean_ci([1.0, 2.0, 4.0], 50, 123)
        self.assertEqual(first, second)
        json.dumps(first, allow_nan=False)


class StateAndFailureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_ablation_config()
        cls.coupled = load_coupled_config()

    def test_bounded_lru_conserves_operations_and_reports_eviction_progress_loss(self) -> None:
        config = replace(
            self.config,
            state_cardinalities=(4, 7, 8, 9, 16),
            state_map_capacity_entries=8,
            state_long_flow_fraction=1.0,
        )
        first = state_cardinality_row(1009, 16, config)
        second = state_cardinality_row(1009, 16, config)
        self.assertEqual(first, second)
        self.assertLessEqual(first["peak_occupancy_entries"], 8)
        self.assertGreater(first["state_evictions"], 0)
        self.assertEqual(first["state_lookups"], first["state_hits"] + first["state_misses"])
        self.assertEqual(
            first["state_insertions"],
            first["target_concurrent_flows"] + first["state_reinsertions_after_eviction"],
        )
        self.assertEqual(first["map_allocation_failures"], 0)
        self.assertIn("not measured CPU", first["operation_count_note"])

    def test_detector_restart_policies_conserve_packets_and_expose_tradeoff(self) -> None:
        rows = {
            scenario: detector_failure_row(1009, scenario, self.config, self.coupled)
            for scenario in FAILURE_SCENARIOS
        }
        for row in rows.values():
            self.assertEqual(
                row["offered_packets"], row["accepted_packets"] + row["dropped_packets"]
            )
            self.assertEqual(
                row["offered_bytes"], row["accepted_bytes"] + row["dropped_bytes"]
            )
            self.assertEqual(
                row["offered_packets"],
                row["fast_routed_packets"] + row["quarantine_routed_packets"],
            )
            self.assertLessEqual(
                row["peak_state_occupancy_entries"], self.config.failure_map_capacity_entries
            )
            json.dumps(row, allow_nan=False)
        self.assertGreater(rows["restart_fail_open"]["failure_window_attack_fast_packets"], 0)
        self.assertEqual(rows["restart_fail_closed"]["failure_window_attack_fast_packets"], 0)
        self.assertGreater(rows["restart_fail_closed"]["failure_window_benign_quarantine_packets"], 0)
        self.assertEqual(rows["restart_fail_open"]["failure_window_benign_quarantine_packets"], 0)
        self.assertGreater(rows["restart_fail_open"]["state_entries_lost_at_restart"], 0)

    def test_reduced_trial_aggregates_are_strict_json(self) -> None:
        # Exercise every aggregate path without invoking the authoritative run.
        config = replace(
            self.config,
            observation_windows_iats=(20,),
            selectors=("rate_only", "oracle"),
            boundary_selectors=("rate_only",),
            boundary_points=41,
            boundary_jitter_cvs=(0.0,),
            boundary_phase_fractions=(0.0,),
            boundary_tail_iats=2,
            state_cardinalities=(4, 7, 8, 9, 16),
            state_map_capacity_entries=8,
            bootstrap_replicates=40,
        )
        models, _ = fit_window_models(config, self.coupled)
        seeds = config.heldout_seeds[:2]
        observation = [
            row
            for seed in seeds
            for row in observation_window_rows(seed, config, self.coupled, models)
        ]
        boundary = [
            row
            for seed in seeds
            for row in threshold_boundary_rows(seed, config, models[20])
        ]
        cardinality = [
            state_cardinality_row(seed, cardinality, config)
            for seed in seeds for cardinality in config.state_cardinalities
        ]
        failure = [
            detector_failure_row(seed, scenario, config, self.coupled)
            for seed in seeds for scenario in FAILURE_SCENARIOS
        ]
        cardinality_aggregate = aggregate_cardinality_rows(cardinality, config)
        self.assertEqual(len(cardinality_aggregate["paired_capacity_boundary_effects"]), 2)
        self.assertTrue(all(
            item["paired_seed_count"] == len(seeds)
            for item in cardinality_aggregate["paired_capacity_boundary_effects"]
        ))
        payload = {
            "window": aggregate_observation_rows(observation, config),
            "boundary": aggregate_boundary_rows(boundary, config),
            "cardinality": cardinality_aggregate,
            "failure": aggregate_failure_rows(failure, config),
        }
        encoded = json.dumps(payload, sort_keys=True, allow_nan=False)
        self.assertNotIn("NaN", encoded)
        self.assertNotIn("Infinity", encoded)


if __name__ == "__main__":
    unittest.main()
