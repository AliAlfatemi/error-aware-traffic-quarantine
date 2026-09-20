from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

import numpy as np

import experiments.timing_baseline as baseline


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ImmutableConfigTests(unittest.TestCase):
    def test_committed_config_is_complete_and_matches_frozen_defaults(self) -> None:
        config = baseline.load_config()
        self.assertEqual(config, baseline.ExperimentConfig())
        self.assertEqual(len(config.calibration_seeds), 5)
        self.assertEqual(len(config.test_seeds), 20)
        self.assertFalse(set(config.calibration_seeds) & set(config.test_seeds))

    def test_unknown_missing_and_nonfinite_config_values_are_rejected(self) -> None:
        source = asdict(baseline.ExperimentConfig())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            unknown = {**source, "surprise": 1}
            unknown_path = root / "unknown.json"
            unknown_path.write_text(json.dumps(unknown), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unknown"):
                baseline.load_config(unknown_path)

            missing = dict(source)
            missing.pop("window_iats")
            missing_path = root / "missing.json"
            missing_path.write_text(json.dumps(missing), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "missing"):
                baseline.load_config(missing_path)

            nonfinite_path = root / "nonfinite.json"
            nonfinite_path.write_text(
                json.dumps(source).replace(
                    '"fast_capacity_pps": 2000.0',
                    '"fast_capacity_pps": NaN',
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "non-finite"):
                baseline.load_config(nonfinite_path)

    def test_json_writer_refuses_nonfinite_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid.json"
            with self.assertRaises(ValueError):
                baseline.write_json(path, {"invalid": float("nan")})
            self.assertFalse(path.exists())


class HistoricalClassifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = baseline.load_config()
        calibration_flows = []
        for seed in cls.config.calibration_seeds:
            calibration_flows.extend(
                baseline.generate_flow_observations(
                    seed,
                    cls.config.calibration_flows_per_type_per_seed,
                    cls.config.window_iats,
                )
            )
        cls.classifier, cls.calibration = baseline.calibrate_classifier(
            calibration_flows, cls.config
        )
        cls.test_records = []
        for seed in cls.config.test_seeds:
            flows = baseline.generate_flow_observations(
                seed,
                cls.config.test_flows_per_type_per_seed,
                cls.config.window_iats,
            )
            cls.test_records.extend(
                baseline.prediction_records(flows, cls.classifier)
            )

    def test_exact_original_negative_result_is_preserved(self) -> None:
        confusion = baseline._confusion_from_predictions(self.test_records)
        self.assertEqual(
            confusion,
            {"tp": 2043, "fp": 51, "tn": 5949, "fn": 3957},
        )
        metrics = baseline.metrics_from_confusion(confusion)
        self.assertEqual(metrics["recall_tpr"], 0.3405)
        self.assertAlmostEqual(metrics["f1"], 0.5048183839881394)
        self.assertLess(metrics["recall_tpr"], 0.35)

    def test_frozen_threshold_and_decision_maturity_are_preserved(self) -> None:
        self.assertAlmostEqual(
            self.classifier.variance_threshold_s2,
            4.325269569488584e-06,
            delta=1e-18,
        )
        self.assertEqual(self.classifier.window_iats + 1, 21)
        self.assertLessEqual(
            self.calibration["metrics"]["false_positive_rate"],
            self.config.calibration_target_fpr,
        )

    def test_serialized_classification_is_byte_deterministic(self) -> None:
        payload = {
            "classifier": asdict(self.classifier),
            "confusion": baseline._confusion_from_predictions(self.test_records),
            "records": self.test_records,
        }
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first.json"
            second = Path(temporary) / "second.json"
            baseline.write_json(first, payload)
            baseline.write_json(second, payload)
            self.assertEqual(first.read_bytes(), second.read_bytes())


class PreservedQueueAndTcpTests(unittest.TestCase):
    def test_dwell_does_not_change_queue_service_or_acceptance(self) -> None:
        arrivals = baseline.poisson_arrivals(
            np.random.default_rng(77), 100.0, 10.0
        )
        no_dwell = baseline.simulate_finite_queue(
            arrivals, 150.0, 100, 0.0, 2.0, 10.0
        )
        long_dwell = baseline.simulate_finite_queue(
            arrivals, 150.0, 100, 3.0, 2.0, 10.0
        )
        self.assertEqual(
            no_dwell["measurement_accepted_packet_count"],
            long_dwell["measurement_accepted_packet_count"],
        )
        self.assertEqual(
            no_dwell["service_departure_rate_pps"],
            long_dwell["service_departure_rate_pps"],
        )
        self.assertAlmostEqual(
            long_dwell["latency_mean_s"] - no_dwell["latency_mean_s"],
            3.0,
            places=10,
        )

    def test_three_second_tcp_point_remains_a_narrow_transient(self) -> None:
        config = baseline.load_config()
        result = baseline.simulate_tcp_timeout_transient(3.0, config)
        self.assertEqual(result["timeout_retransmissions_before_first_ack"], 2)
        self.assertAlmostEqual(result["first_ack_time_s"], 3.04)
        self.assertEqual(
            result["adequate_window_rate_pps"], config.quarantine_capacity_pps
        )


class OutputSafetyTests(unittest.TestCase):
    def test_nonempty_output_directory_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "occupied"
            output.mkdir()
            sentinel = output / "user-data.txt"
            sentinel.write_text("preserve me", encoding="utf-8")
            with self.assertRaisesRegex(FileExistsError, "refusing to overwrite"):
                baseline.run_pipeline(output)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me")
            self.assertEqual(list(output.iterdir()), [sentinel])

    def test_preservation_module_is_self_contained_and_has_no_dashboard_path(self) -> None:
        source = (PROJECT_ROOT / "experiments" / "timing_baseline.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("from experiments.reproducible_pipeline", source)
        self.assertNotIn("DEFAULT_DASHBOARD_PATH", source)
        self.assertNotIn('PROJECT_ROOT / "dashboard"', source)


if __name__ == "__main__":
    unittest.main()
