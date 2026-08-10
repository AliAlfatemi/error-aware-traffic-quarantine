from __future__ import annotations

import unittest

import numpy as np
import pandas as pd

from experiments.public_rt_iot2022 import (
    COMPACT_FEATURES,
    DEFAULT_CONFIG,
    EXPECTED_ARCHIVE_SHA256,
    EXPECTED_CSV_SHA256,
    EXPORTED_INDEX_COLUMN,
    GENERATOR_PATH,
    REFERENCE_FEATURES,
    REQUIREMENTS_PATH,
    STRICT_COMPARATOR,
    _family_rates,
    apply_or_rule,
    apply_score_rule,
    calibrate_or_rule,
    calibrate_score_threshold,
    file_sha256,
    load_and_split,
    load_config,
    metric_summary,
    reproducibility_inputs,
)


class PublicSourceAndSplitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.frame, cls.audit = load_and_split()

    def test_immutable_source_hashes_shape_and_retention(self) -> None:
        source = self.audit["source"]
        self.assertEqual(source["archive_sha256"], EXPECTED_ARCHIVE_SHA256)
        self.assertEqual(source["csv_sha256"], EXPECTED_CSV_SHA256)
        self.assertEqual(self.audit["shape"], {"rows": 123117, "source_columns": 85})
        self.assertEqual(self.audit["rows_retained"], 123117)
        self.assertEqual(len(self.frame), 123117)

    def test_distributed_index_is_candidly_renamed(self) -> None:
        self.assertIn(EXPORTED_INDEX_COLUMN, self.frame.columns)
        self.assertNotIn("Unnamed: 0", self.frame.columns)
        self.assertEqual(
            self.audit["renamed_source_index"]["interpretation"],
            "class-local row identifier; not a capture or time identifier",
        )

    def test_identical_inputs_for_both_learned_models_never_cross_splits(self) -> None:
        audits = self.audit["learned_input_overlap_audits"]
        self.assertEqual(
            set(audits),
            {
                "compact_5_feature_learned_input",
                "reference_12_feature_learned_input",
            },
        )
        for record in audits.values():
            self.assertEqual(
                record["cross_split_overlap_counts"],
                {
                    "train_calibration": 0,
                    "train_test": 0,
                    "calibration_test": 0,
                },
            )
        for hash_column in ("compact_input_hash_u64", "reference_input_hash_u64"):
            split_count = self.frame.groupby(hash_column)["split"].nunique()
            self.assertEqual(int(split_count.max()), 1)
        self.assertTrue(set(COMPACT_FEATURES).issubset(REFERENCE_FEATURES))

    def test_all_partitions_contain_benign_and_attack_rows(self) -> None:
        for split, counts in self.audit["split_label_counts"].items():
            self.assertGreater(counts["benign"], 0, split)
            self.assertGreater(counts["attack"], 0, split)
        self.assertEqual(
            self.audit["split_distinct_family_counts"],
            {"train": 12, "calibration": 11, "test": 12},
        )

    def test_large_compact_groups_and_partition_dominance_are_reported(self) -> None:
        grouping = self.audit["global_grouping"]
        self.assertEqual(grouping["maximum_global_group_rows"], 25894)
        expected = {
            "train": (25894, 0.2748452973581141),
            "calibration": (9690, 0.6022748461681895),
            "test": (5200, 0.4057744830277019),
        }
        for split, (rows, fraction) in expected.items():
            record = grouping["largest_group_by_split"][split]
            self.assertEqual(record["rows"], rows)
            self.assertAlmostEqual(record["fraction_of_split_rows"], fraction)
            self.assertTrue(record["exceeds_10_percent_of_split_rows"])
        self.assertIn("not row-balanced", grouping["concentration_warning"])

    def test_conflicting_labels_are_counted_not_removed(self) -> None:
        conflicts = self.audit["conflicting_label_audits"]
        full = conflicts["full_83_minus_index_and_label_feature_vector"]
        reference = conflicts["reference_12_feature_learned_input"]
        compact = conflicts["compact_5_feature_learned_input"]
        self.assertEqual(full["duplicate_rows_after_first_within_exact_input"], 5202)
        self.assertEqual(
            full["family_label_conflicts"],
            {"group_count": 6, "rows_in_conflicting_groups": 128},
        )
        self.assertEqual(
            full["binary_label_conflicts"],
            {"group_count": 4, "rows_in_conflicting_groups": 107},
        )
        self.assertEqual(
            reference["family_label_conflicts"],
            {"group_count": 84, "rows_in_conflicting_groups": 8023},
        )
        self.assertEqual(
            reference["binary_label_conflicts"],
            {"group_count": 9, "rows_in_conflicting_groups": 2136},
        )
        self.assertEqual(
            compact["family_label_conflicts"],
            {"group_count": 85, "rows_in_conflicting_groups": 8250},
        )
        self.assertEqual(
            compact["binary_label_conflicts"],
            {"group_count": 9, "rows_in_conflicting_groups": 2154},
        )

    def test_dispersion_degeneracy_is_quantified(self) -> None:
        record = self.audit["dispersion_feature_degeneracy"]
        self.assertEqual(record["zero_flow_iat_std_rows"], 105520)
        self.assertEqual(
            record["zero_std_rows_by_total_packets"], {"1": 14809, "2": 90711}
        )
        self.assertTrue(record["all_zero_std_rows_have_one_or_two_total_packets"])
        self.assertEqual(record["nonzero_std_rows_with_at_most_two_total_packets"], 0)

    def test_split_fingerprint_is_stable_for_bound_source_and_runtime(self) -> None:
        # This exact value deliberately binds the pandas hash implementation.
        self.assertEqual(
            self.audit["global_grouping"]["split_assignment_sha256"],
            "e9ba54f179cddb5f07a9ccc4294095a42960df8c3ef5c152b96f0d1427d89d34",
        )


class CalibrationTests(unittest.TestCase):
    def test_single_score_threshold_respects_fpr_cap(self) -> None:
        labels = np.array([0] * 100 + [1] * 50)
        scores = np.concatenate([np.linspace(0, 1, 100), np.linspace(0.5, 1.5, 50)])
        result = calibrate_score_threshold(scores, labels, 0.01)
        prediction = apply_score_rule(scores, result)
        self.assertEqual(result["comparator"], STRICT_COMPARATOR)
        self.assertLessEqual(prediction[labels == 0].mean(), 0.01)

    def test_zero_boundary_and_ties_need_no_subnormal_sentinel(self) -> None:
        labels = np.array([0] * 100 + [1] * 4)
        scores = np.array([0.0] * 100 + [1.0] * 4)
        result = calibrate_score_threshold(scores, labels, 0.01)
        prediction = apply_score_rule(scores, result)
        self.assertEqual(result["threshold"], 0.0)
        self.assertEqual(result["benign_rows_tied_at_threshold"], 100)
        self.assertEqual(int(prediction[labels == 0].sum()), 0)
        self.assertEqual(int(prediction[labels == 1].sum()), 4)
        self.assertIn("ties are not flagged", result["decision_rule"])

    def test_or_threshold_respects_joint_fpr_cap(self) -> None:
        labels = np.array([0] * 200 + [1] * 80)
        rate = np.concatenate([np.linspace(0, 1, 200), np.linspace(0.4, 1.4, 80)])
        dispersion = np.concatenate(
            [np.linspace(1, 0, 200), np.linspace(0.2, 1.2, 80)]
        )
        result = calibrate_or_rule(rate, dispersion, labels, 0.01)
        prediction = apply_or_rule(rate, dispersion, result)
        self.assertLessEqual(prediction[labels == 0].mean(), 0.01)
        self.assertEqual(result["rate_comparator"], STRICT_COMPARATOR)
        self.assertEqual(result["dispersion_comparator"], STRICT_COMPARATOR)


class MetricSemanticsTests(unittest.TestCase):
    def test_metrics_and_retrospective_mass_names(self) -> None:
        labels = np.array([0, 0, 1, 1])
        prediction = np.array([False, True, True, False])
        scores = np.array([0.1, 0.9, 0.8, 0.2])
        record = metric_summary(
            labels,
            prediction,
            scores,
            packet_weights=np.array([1.0, 3.0, 2.0, 8.0]),
            byte_weights=np.array([10.0, 30.0, 20.0, 80.0]),
        )
        self.assertEqual(record["confusion"], {"tp": 1, "fp": 1, "tn": 1, "fn": 1})
        self.assertNotIn("traffic_weighted", record)
        mass = record["retrospective_whole_flow_mass_association"]
        self.assertAlmostEqual(mass["attack_packet_mass_on_flagged_rows_fraction"], 0.2)
        self.assertAlmostEqual(mass["benign_packet_mass_on_flagged_rows_fraction"], 0.75)
        self.assertIn("not operational packet diversion", mass["interpretation"])
        self.assertIn(
            "descriptive_conditional_row_wilson95",
            record["metrics"]["recall_tpr"],
        )

    def test_macro_family_averages_are_unweighted(self) -> None:
        families = pd.Series(
            ["MQTT_Publish", "MQTT_Publish", "Thing_Speak", "DOS_SYN_Hping", "ARP", "ARP"]
        )
        prediction = np.array([False, True, False, True, False, True])
        _, macro = _family_rates(families, prediction)
        self.assertAlmostEqual(macro["attack_family_macro_recall"], 0.75)
        self.assertAlmostEqual(macro["benign_family_macro_false_positive_rate"], 0.25)
        self.assertEqual(macro["attack_family_count"], 2)
        self.assertEqual(macro["benign_family_count"], 2)


class ReproducibilityBindingTests(unittest.TestCase):
    def test_config_and_input_hashes_are_bound(self) -> None:
        config = load_config(DEFAULT_CONFIG)
        config.validate()
        record = reproducibility_inputs(DEFAULT_CONFIG)
        self.assertEqual(record["generator"]["sha256"], file_sha256(GENERATOR_PATH))
        self.assertEqual(record["immutable_config"]["sha256"], file_sha256(DEFAULT_CONFIG))
        self.assertEqual(record["requirements"]["sha256"], file_sha256(REQUIREMENTS_PATH))
        self.assertIn("same host", record["determinism_scope"])
        self.assertIn("scikit_learn", record["runtime"])


if __name__ == "__main__":
    unittest.main()
