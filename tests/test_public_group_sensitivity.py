from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

import numpy as np
import pandas as pd

from experiments.public_group_sensitivity import (
    ANALYSIS_SPLIT,
    CLAIM_BOUNDARY,
    DEFAULT_CONFIG,
    DEFAULT_OUTPUT_DIR,
    DOMINANT_GROUP_RULE,
    EXACT_GROUP_ID,
    EXACT_GROUP_TUPLE_SHA256,
    EXPECTED_PROTOCOL_SHA256,
    EXPECTED_SENSITIVITY_CONFIG_SHA256,
    GENERATOR_PATH,
    GROUP_BOOTSTRAP_METRICS,
    PROJECT_ROOT,
    SCHEMA_VERSION,
    SUPPORTED_SELECTORS,
    SensitivityError,
    SEED_METRIC_VALUE_COLUMNS,
    _write_artifact_set,
    canonical_json_sha256,
    _input_record,
    _prepare_output_directory,
    aggregate_seed_metrics,
    assign_groups,
    define_exact_groups,
    descriptive_binary_metrics,
    dominant_test_group,
    equal_group_weighted_metrics,
    family_metrics,
    file_sha256,
    fit_and_predict_selectors,
    group_bootstrap_sensitivity,
    load_config,
    load_json_strict,
    materialize_split,
    projection_overlap_audit,
    run_public_group_sensitivity,
    split_assignment_sha256,
    validate_split,
    verify_frozen_public_stage,
    verify_manifest,
    write_json_strict,
)
from experiments.public_rt_iot2022 import (
    COMPACT_FEATURES,
    DEFAULT_ARCHIVE,
    DEFAULT_CSV,
    EXPECTED_ARCHIVE_SHA256,
    EXPECTED_CSV_SHA256,
    REFERENCE_FEATURES,
    PublicExperimentConfig,
)


def feature_frame(rows: int) -> pd.DataFrame:
    data: dict[str, np.ndarray] = {}
    for index, feature in enumerate(REFERENCE_FEATURES):
        data[feature] = np.arange(rows, dtype=float) + index / 10.0 + 1.0
    data["source_file_row_position_zero_based"] = np.arange(rows, dtype=np.int64)
    data["Attack_type"] = np.where(
        np.arange(rows) % 2 == 0, "DOS_SYN_Hping", "MQTT_Publish"
    )
    data["true_label"] = (np.arange(rows) % 2 == 0).astype(int)
    return pd.DataFrame(data)


def model_fixture() -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    partitions = (("train", 80), ("calibration", 200), ("test", 80))
    source_position = 0
    for split, count in partitions:
        for local in range(count):
            label = local % 2
            base = float(label * 20 + (local % 17) / 20.0 + 1.0)
            record: dict[str, object] = {
                feature: base + feature_index / 100.0
                for feature_index, feature in enumerate(REFERENCE_FEATURES)
            }
            record.update(
                {
                    "source_file_row_position_zero_based": source_position,
                    "Attack_type": "DOS_SYN_Hping" if label else "MQTT_Publish",
                    "true_label": label,
                    EXACT_GROUP_ID: source_position,
                    ANALYSIS_SPLIT: split,
                }
            )
            rows.append(record)
            source_position += 1
    return pd.DataFrame(rows)


class ConfigAndExecutionGuardTests(unittest.TestCase):
    def test_committed_config_is_complete_and_fixed(self) -> None:
        config = load_config(DEFAULT_CONFIG)
        self.assertEqual(config.schema_version, SCHEMA_VERSION)
        self.assertEqual(tuple(config.exact_group_columns), tuple(COMPACT_FEATURES))
        self.assertEqual(config.selectors, SUPPORTED_SELECTORS)
        self.assertEqual(len(config.group_split_seeds), 30)
        self.assertEqual(len(set(config.group_split_seeds)), 30)
        self.assertEqual(
            config.dominant_group_rule,
            "largest_test_exact_group_by_rows_then_lowest_group_id",
        )
        self.assertEqual(config.protocol_path, "EXPERIMENTAL_PROTOCOL_FINAL.md")
        self.assertEqual(config.protocol_sha256, EXPECTED_PROTOCOL_SHA256)
        self.assertEqual(file_sha256(DEFAULT_CONFIG), EXPECTED_SENSITIVITY_CONFIG_SHA256)
        self.assertEqual(
            file_sha256(PROJECT_ROOT / config.protocol_path),
            EXPECTED_PROTOCOL_SHA256,
        )
        self.assertEqual(config.group_bootstrap_replicates, 2000)
        self.assertEqual(config.group_bootstrap_seed, 40787)
        self.assertEqual(config.group_bootstrap_macro_min_groups_per_family, 10)

    def test_strict_config_rejects_duplicate_keys_and_nan(self) -> None:
        original = DEFAULT_CONFIG.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT) as raw:
            root = Path(raw)
            duplicate = root / "duplicate.json"
            duplicate.write_text(
                original.replace(
                    "{\n", '{\n  "schema_version": "duplicate",\n', 1
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(SensitivityError, "duplicate JSON object key"):
                load_json_strict(duplicate)
            nonfinite = root / "nonfinite.json"
            nonfinite.write_text('{"value": NaN}\n', encoding="utf-8")
            with self.assertRaisesRegex(SensitivityError, "non-finite JSON"):
                load_json_strict(nonfinite)

    def test_full_run_is_blocked_before_protocol_acknowledgement(self) -> None:
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT) as raw:
            target = Path(raw) / "must_not_be_created"
            with self.assertRaisesRegex(SensitivityError, "protocol"):
                run_public_group_sensitivity(target)
            self.assertFalse(target.exists())

    def test_authoritative_run_rejects_a_copied_config_before_analysis(self) -> None:
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT) as raw:
            copied = Path(raw) / "copied.json"
            copied.write_bytes(DEFAULT_CONFIG.read_bytes())
            with self.assertRaisesRegex(SensitivityError, "committed frozen config"):
                run_public_group_sensitivity(
                    config_path=copied,
                    acknowledge_final_protocol_frozen=True,
                )

    def test_default_output_is_additional_and_v1_tree_is_forbidden(self) -> None:
        self.assertEqual(
            DEFAULT_OUTPUT_DIR.relative_to(PROJECT_ROOT).as_posix(),
            "results_additional/public_group_sensitivity",
        )
        with self.assertRaisesRegex(SensitivityError, "immutable v1"):
            _prepare_output_directory(PROJECT_ROOT / "results" / "forbidden")


class ExactGroupingAndSplitTests(unittest.TestCase):
    def test_exact_value_equality_not_hash_equality_defines_groups(self) -> None:
        frame = feature_frame(6)
        frame.loc[1, list(COMPACT_FEATURES)] = frame.loc[0, list(COMPACT_FEATURES)].to_numpy()
        frame.loc[4, list(COMPACT_FEATURES)] = frame.loc[3, list(COMPACT_FEATURES)].to_numpy()
        grouped, catalog, families = define_exact_groups(frame)
        self.assertEqual(grouped.loc[0, EXACT_GROUP_ID], grouped.loc[1, EXACT_GROUP_ID])
        self.assertEqual(grouped.loc[3, EXACT_GROUP_ID], grouped.loc[4, EXACT_GROUP_ID])
        self.assertNotEqual(grouped.loc[0, EXACT_GROUP_ID], grouped.loc[2, EXACT_GROUP_ID])
        self.assertEqual(len(catalog), 4)
        self.assertEqual(int(catalog["row_count"].sum()), 6)
        self.assertFalse(catalog[EXACT_GROUP_TUPLE_SHA256].duplicated().any())
        self.assertEqual(set(families), {"DOS_SYN_Hping", "MQTT_Publish"})

        shuffled, shuffled_catalog, _ = define_exact_groups(
            frame.sample(frac=1.0, random_state=17)
        )
        mapping = grouped.set_index("source_file_row_position_zero_based")[EXACT_GROUP_ID]
        shuffled_mapping = shuffled.set_index("source_file_row_position_zero_based")[
            EXACT_GROUP_ID
        ]
        pd.testing.assert_series_equal(mapping.sort_index(), shuffled_mapping.sort_index())
        self.assertEqual(
            set(catalog[EXACT_GROUP_TUPLE_SHA256]),
            set(shuffled_catalog[EXACT_GROUP_TUPLE_SHA256]),
        )

    def test_salted_assignment_is_atomic_deterministic_and_seed_sensitive(self) -> None:
        frame = feature_frame(100)
        grouped, catalog, _ = define_exact_groups(frame)
        config = load_config(DEFAULT_CONFIG)
        first = assign_groups(catalog, config.group_split_seeds[0], config)
        repeat = assign_groups(catalog, config.group_split_seeds[0], config)
        second = assign_groups(catalog, config.group_split_seeds[1], config)
        pd.testing.assert_frame_equal(first, repeat)
        self.assertEqual(split_assignment_sha256(first), split_assignment_sha256(repeat))
        self.assertTrue((first[ANALYSIS_SPLIT] != second[ANALYSIS_SPLIT]).any())

        split = materialize_split(grouped, first)
        self.assertEqual(
            int(split.groupby(EXACT_GROUP_ID)[ANALYSIS_SPLIT].nunique().max()), 1
        )
        self.assertEqual(len(split), len(frame))
        self.assertEqual(int(split[ANALYSIS_SPLIT].isna().sum()), 0)

    def test_missing_test_family_is_retained_without_seed_replacement(self) -> None:
        frame = feature_frame(12)
        frame[EXACT_GROUP_ID] = np.arange(len(frame), dtype=np.int64)
        frame[ANALYSIS_SPLIT] = ["train"] * 4 + ["calibration"] * 4 + ["test"] * 4
        # Keep both binary classes in every partition but require one family that
        # is deliberately absent from test.
        reasons = validate_split(
            frame, ["DOS_SYN_Hping", "MQTT_Publish", "Thing_Speak"]
        )
        self.assertEqual(reasons, [])

    def test_timing_projection_overlap_is_reported_not_called_learned_leakage(self) -> None:
        frame = feature_frame(6)
        # Rows 0 and 1 share the rate scalar but differ on another compact input.
        frame.loc[1, "flow_pkts_per_sec"] = frame.loc[0, "flow_pkts_per_sec"]
        grouped, _, _ = define_exact_groups(frame)
        grouped[ANALYSIS_SPLIT] = [
            "train",
            "test",
            "train",
            "calibration",
            "test",
            "calibration",
        ]
        audit = {row["projection"]: row for row in projection_overlap_audit(grouped, 7)}
        self.assertEqual(
            audit["compact_logistic_input"][
                "crossing_any_partition_pair_tuple_count"
            ],
            0,
        )
        rate = audit["rate_only_projection"]
        self.assertGreater(rate["crossing_any_partition_pair_tuple_count"], 0)
        self.assertFalse(rate["exact_cross_split_separation_required"])
        self.assertIn("no cross-partition separation claim", rate["interpretation"])


class DescriptiveMetricTests(unittest.TestCase):
    def test_exact_group_bootstrap_is_deterministic_shared_and_bounded(self) -> None:
        rows: list[dict[str, object]] = []
        for group_id in range(40):
            label = int(group_id < 20)
            family = "DOS_SYN_Hping" if label else "MQTT_Publish"
            for _ in range(1 + group_id % 3):
                rows.append(
                    {
                        EXACT_GROUP_ID: group_id,
                        "true_label": label,
                        "Attack_type": family,
                    }
                )
        test = pd.DataFrame(rows)
        group_ids = test[EXACT_GROUP_ID].to_numpy(dtype=int)
        labels = test["true_label"].to_numpy(dtype=int)
        predictions = {
            selector: np.asarray(
                (labels == 1) ^ ((group_ids + index) % 7 == 0),
                dtype=bool,
            )
            for index, selector in enumerate(SUPPORTED_SELECTORS)
        }
        config = load_config(DEFAULT_CONFIG)
        first_raw, first_intervals = group_bootstrap_sensitivity(
            test,
            predictions,
            ("DOS_SYN_Hping", "MQTT_Publish"),
            30139,
            2,
            config,
        )
        second_raw, second_intervals = group_bootstrap_sensitivity(
            test,
            predictions,
            ("DOS_SYN_Hping", "MQTT_Publish"),
            30139,
            2,
            config,
        )
        self.assertEqual(first_raw, second_raw)
        self.assertEqual(first_intervals, second_intervals)
        self.assertEqual(len(first_raw), 2 * config.group_bootstrap_replicates)
        self.assertEqual(
            len(first_intervals),
            2 * len(SUPPORTED_SELECTORS) * len(GROUP_BOOTSTRAP_METRICS),
        )
        full_intervals = [
            row for row in first_intervals if row["variant"] == "full_test"
        ]
        self.assertTrue(all(row["interval_available"] for row in full_intervals))
        self.assertTrue(
            all(
                row["defined_replicate_count"]
                + row["undefined_replicate_count"]
                == config.group_bootstrap_replicates
                for row in first_intervals
            )
        )
        self.assertTrue(
            all("not a capture" in row["interpretation"] for row in first_intervals)
        )
        for row in first_raw:
            self.assertEqual(
                row["sampled_group_draw_count"],
                40 if row["variant"] == "full_test" else 39,
            )
            for selector in SUPPORTED_SELECTORS:
                for metric in GROUP_BOOTSTRAP_METRICS:
                    defined = row[f"{selector}::{metric}::defined"]
                    value = row[f"{selector}::{metric}::value"]
                    self.assertEqual(defined, value is not None)
                    if value is not None:
                        self.assertGreaterEqual(value, 0.0)
                        self.assertLessEqual(value, 1.0)

    def test_exact_group_bootstrap_macro_interval_obeys_support_gate(self) -> None:
        test = pd.DataFrame(
            {
                EXACT_GROUP_ID: np.arange(18, dtype=np.int64),
                "true_label": np.array([1] * 9 + [0] * 9),
                "Attack_type": ["DOS_SYN_Hping"] * 9 + ["MQTT_Publish"] * 9,
            }
        )
        labels = test["true_label"].to_numpy(dtype=int)
        predictions = {
            selector: labels.astype(bool) for selector in SUPPORTED_SELECTORS
        }
        _, intervals = group_bootstrap_sensitivity(
            test,
            predictions,
            ("DOS_SYN_Hping", "MQTT_Publish"),
            30139,
            17,
            load_config(DEFAULT_CONFIG),
        )
        macro = [
            row
            for row in intervals
            if "present_family_macro" in str(row["metric"])
        ]
        row_metrics = [
            row
            for row in intervals
            if row["metric"] in {"recall_tpr", "false_positive_rate"}
        ]
        self.assertTrue(macro)
        self.assertTrue(all(not row["interval_available"] for row in macro))
        self.assertTrue(
            all("below frozen minimum 10" in row["unavailable_reason"] for row in macro)
        )
        self.assertTrue(all(row["interval_available"] for row in row_metrics))

    def test_equal_group_weighting_exposes_dominant_group_dependence(self) -> None:
        labels = np.array([1] * 101 + [0] * 51)
        prediction = np.array([True] * 100 + [False] + [False] * 50 + [True])
        groups = np.array([10] * 100 + [20] + [30] * 50 + [40])
        row = descriptive_binary_metrics(labels, prediction)
        grouped = equal_group_weighted_metrics(groups, labels, prediction)
        self.assertAlmostEqual(row["recall_tpr"], 100 / 101)
        self.assertAlmostEqual(row["false_positive_rate"], 1 / 51)
        self.assertAlmostEqual(
            grouped["equal_exact_group_weighted_recall_tpr"], 0.5
        )
        self.assertAlmostEqual(
            grouped["equal_exact_group_weighted_false_positive_rate"], 0.5
        )
        self.assertAlmostEqual(
            grouped["equal_exact_group_weighted_accuracy"], 0.5
        )

    def test_mixed_label_group_contributes_to_both_group_estimands(self) -> None:
        labels = np.array([1, 0, 1, 0])
        prediction = np.array([True, True, False, False])
        groups = np.array([7, 7, 9, 11])
        record = equal_group_weighted_metrics(groups, labels, prediction)
        self.assertAlmostEqual(record["equal_exact_group_weighted_recall_tpr"], 0.5)
        self.assertAlmostEqual(
            record["equal_exact_group_weighted_false_positive_rate"], 0.5
        )
        self.assertEqual(record["attack_group_count"], 2)
        self.assertEqual(record["benign_group_count"], 2)

    def test_family_metrics_use_null_and_defined_flag_for_absent_family(self) -> None:
        frame = pd.DataFrame(
            {
                "Attack_type": ["DOS_SYN_Hping", "MQTT_Publish"],
                EXACT_GROUP_ID: [1, 2],
            }
        )
        rows, macro = family_metrics(
            frame,
            np.array([True, False]),
            ["DOS_SYN_Hping", "MQTT_Publish", "Thing_Speak"],
            seed=1,
            selector="rate_only",
            variant="full_test",
        )
        absent = next(row for row in rows if row["family"] == "Thing_Speak")
        self.assertFalse(absent["flagged_row_rate_defined"])
        self.assertIsNone(absent["flagged_row_rate"])
        self.assertEqual(macro["benign_families_included"], 1)
        self.assertAlmostEqual(
            macro["benign_present_family_macro_false_positive_rate"], 0.0
        )
        self.assertTrue(math_is_finite_or_none(macro))

    def test_dominant_group_selection_is_outcome_blind_and_tie_deterministic(self) -> None:
        test = pd.DataFrame(
            {
                EXACT_GROUP_ID: [9, 2, 9, 2],
                "true_label": [1, 0, 1, 0],
                "Attack_type": ["DOS_SYN_Hping", "MQTT_Publish"] * 2,
            }
        )
        catalog = pd.DataFrame(
            {
                EXACT_GROUP_ID: [2, 9],
                EXACT_GROUP_TUPLE_SHA256: ["2" * 64, "9" * 64],
            }
        )
        first = dominant_test_group(
            test, catalog, ["DOS_SYN_Hping", "MQTT_Publish"], 101
        )
        second = dominant_test_group(
            test.sample(frac=1.0, random_state=8),
            catalog,
            ["DOS_SYN_Hping", "MQTT_Publish"],
            101,
        )
        self.assertEqual(first[EXACT_GROUP_ID], 2)
        self.assertEqual(first[EXACT_GROUP_ID], second[EXACT_GROUP_ID])
        self.assertEqual(first["selection_rule"], DOMINANT_GROUP_RULE)


class RefitAndCalibrationTests(unittest.TestCase):
    def test_every_selector_is_refit_and_recalibrated_on_supplied_split(self) -> None:
        base = PublicExperimentConfig(forest_estimators=5, forest_max_depth=4)
        base.validate()
        frame = model_fixture()
        test, predictions, rules, metadata = fit_and_predict_selectors(frame, base)
        self.assertEqual(tuple(predictions), SUPPORTED_SELECTORS)
        self.assertEqual(tuple(rules), SUPPORTED_SELECTORS)
        self.assertEqual(len(test), 80)
        for prediction in predictions.values():
            self.assertEqual(len(prediction), len(test))
        self.assertEqual(rules["rate_only"]["comparator"], "score_strictly_greater_than_threshold")
        self.assertEqual(metadata["random_forest_reference"]["workers"], 1)
        self.assertEqual(metadata["random_forest_reference"]["estimators"], 5)

        shifted = frame.copy()
        mask = (shifted[ANALYSIS_SPLIT] == "calibration") & shifted["true_label"].eq(0)
        shifted.loc[mask, "flow_pkts_per_sec"] += 1000.0
        _, _, shifted_rules, _ = fit_and_predict_selectors(shifted, base)
        self.assertNotEqual(
            rules["rate_only"]["threshold"], shifted_rules["rate_only"]["threshold"]
        )


class StrictArtifactTests(unittest.TestCase):
    def _manifest_fixture(self, root: Path) -> Path:
        config = load_config(DEFAULT_CONFIG)
        family = "DOS_SYN_Hping"
        tuple_hash = "b" * 64
        provenance = {
            "input_files": {
                "sensitivity_generator": _input_record(GENERATOR_PATH),
                "frozen_public_generator_reused": _input_record(
                    PROJECT_ROOT / "experiments" / "public_rt_iot2022.py"
                ),
                "sensitivity_config": _input_record(DEFAULT_CONFIG),
                "frozen_public_config": _input_record(
                    PROJECT_ROOT / "configs" / "public_rt_iot2022.json"
                ),
                "frozen_public_result_manifest": _input_record(
                    PROJECT_ROOT / "results" / "public_rt_iot2022" / "manifest.json"
                ),
                "frozen_protocol": _input_record(
                    PROJECT_ROOT / "EXPERIMENTAL_PROTOCOL_FINAL.md"
                ),
                "official_downloader": _input_record(
                    PROJECT_ROOT / "data" / "public" / "rt_iot2022" / "download.py"
                ),
                "dataset_provenance_record": _input_record(
                    PROJECT_ROOT
                    / "data"
                    / "public"
                    / "rt_iot2022"
                    / "PROVENANCE.md"
                ),
                "requirements": _input_record(PROJECT_ROOT / "requirements.txt"),
            },
            "source_files": {
                "archive": _input_record(DEFAULT_ARCHIVE),
                "extracted_table": _input_record(DEFAULT_CSV),
            },
            "frozen_public_stage_binding": verify_frozen_public_stage(),
        }
        catalog_row = {
            EXACT_GROUP_ID: 0,
            EXACT_GROUP_TUPLE_SHA256: tuple_hash,
            "first_source_row_position_zero_based": 0,
            "row_count": 1,
            "benign_rows": 0,
            "attack_rows": 1,
            "distinct_binary_labels": 1,
            "distinct_families": 1,
            **{feature: float(index + 1) for index, feature in enumerate(COMPACT_FEATURES)},
            f"family_rows::{family}": 1,
        }
        catalog = pd.DataFrame([catalog_row])
        assignment_rows = [
            {
                "split_seed": seed,
                EXACT_GROUP_ID: 0,
                EXACT_GROUP_TUPLE_SHA256: tuple_hash,
                "split_bucket": 0,
                ANALYSIS_SPLIT: "train",
            }
            for seed in config.group_split_seeds
        ]
        split_count_rows = []
        for seed in config.group_split_seeds:
            for split in ("train", "calibration", "test"):
                for category_type, category in (
                    ("all", "__ALL__"),
                    ("binary_label", "__BENIGN__"),
                    ("binary_label", "__ATTACK__"),
                    ("family", family),
                ):
                    split_count_rows.append(
                        {
                            "split_seed": seed,
                            "split": split,
                            "category_type": category_type,
                            "category": category,
                            "row_count": 0,
                            "exact_group_count": 0,
                        }
                    )
        seed_status_rows = [
            {
                "split_seed": seed,
                "status": "failed",
                "failure_reason_count": 1,
                "failure_reasons": "fixture_failure",
                "absent_test_family_count": 1,
                "absent_test_families": family,
                "split_assignment_sha256": "c" * 64,
                "train_rows": 1,
                "calibration_rows": 0,
                "test_rows": 0,
                "train_exact_groups": 1,
                "calibration_exact_groups": 0,
                "test_exact_groups": 0,
                "maximum_splits_per_exact_group": 1,
                "maximum_splits_per_reference_input_tuple": 1,
            }
            for seed in config.group_split_seeds
        ]
        projection_rows = []
        for seed in config.group_split_seeds:
            for projection in (
                "compact_logistic_input",
                "random_forest_reference_input",
                "rate_only_projection",
                "dispersion_only_projection",
                "timing_or_projection",
            ):
                projection_rows.append(
                    {
                        "split_seed": seed,
                        "projection": projection,
                        "projection_role": "fixture",
                        "columns_in_order": "fixture",
                        "exact_cross_split_separation_required": False,
                        "train_distinct_tuple_count": 1,
                        "calibration_distinct_tuple_count": 0,
                        "test_distinct_tuple_count": 0,
                        "train_calibration_overlap_tuple_count": 0,
                        "train_test_overlap_tuple_count": 0,
                        "calibration_test_overlap_tuple_count": 0,
                        "crossing_any_partition_pair_tuple_count": 0,
                        "rows_in_crossing_tuples": 0,
                        "interpretation": "fixture",
                    }
                )
        summary_without_hash = {
            "schema_version": SCHEMA_VERSION,
            "run_status": "failed",
            "source_validation": {"family_counts": {family: 1}},
            "exact_group_definition": {"distinct_exact_groups": 1},
            "split_execution": {
                "configured_seed_count": 30,
                "executed_seed_count": 30,
                "successful_seed_count": 0,
            },
            "provenance": provenance,
            "value": 1.0,
        }
        result_hash = canonical_json_sha256(summary_without_hash)
        summary = {
            **summary_without_hash,
            "result_payload_sha256": result_hash,
        }
        generated = _write_artifact_set(
            root,
            catalog=catalog,
            assignment_rows=assignment_rows,
            split_count_rows=split_count_rows,
            seed_status_rows=seed_status_rows,
            metric_rows=[],
            family_rows=[],
            calibration_rows=[],
            projection_overlap_rows=projection_rows,
            group_bootstrap_rows=[],
            group_bootstrap_interval_rows=[],
            dominant_rows=[],
            model_metadata={"schema_version": SCHEMA_VERSION},
            summary=summary,
        )
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "run_status": "failed",
            "result_payload_sha256": result_hash,
            "provenance": provenance,
            "generated_files": generated,
        }
        manifest_path = root / "manifest.json"
        write_json_strict(manifest_path, manifest)
        return manifest_path

    def test_manifest_verifies_hashes_schemas_inputs_and_closed_file_set(self) -> None:
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT) as raw:
            root = Path(raw)
            manifest = self._manifest_fixture(root)
            verify_manifest(manifest)
            (root / "seed_status.csv").write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(SensitivityError, "hash mismatch"):
                verify_manifest(manifest)

    def test_release_verification_rejects_a_hash_valid_failed_stage(self) -> None:
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT) as raw:
            manifest = self._manifest_fixture(Path(raw))
            with self.assertRaisesRegex(
                SensitivityError, "study did not pass"
            ):
                verify_manifest(manifest, require_success=True)

    def test_manifest_rejects_undeclared_files(self) -> None:
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT) as raw:
            root = Path(raw)
            manifest = self._manifest_fixture(root)
            (root / "extra.txt").write_text("undeclared\n", encoding="utf-8")
            with self.assertRaisesRegex(SensitivityError, "undeclared"):
                verify_manifest(manifest)

    def test_manifest_recomputes_result_payload_hash(self) -> None:
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT) as raw:
            root = Path(raw)
            manifest_path = self._manifest_fixture(root)
            summary_path = root / "summary.json"
            summary = load_json_strict(summary_path)
            summary["value"] = 2.0
            write_json_strict(summary_path, summary)
            manifest = load_json_strict(manifest_path)
            manifest["generated_files"]["summary.json"]["sha256"] = file_sha256(
                summary_path
            )
            write_json_strict(manifest_path, manifest)
            with self.assertRaisesRegex(SensitivityError, "payload SHA-256"):
                verify_manifest(manifest_path)

    def test_no_inferential_claim_is_encoded_in_scope_or_aggregate(self) -> None:
        config = load_config(DEFAULT_CONFIG)
        rows = []
        for selector in SUPPORTED_SELECTORS:
            for variant in ("full_test", "dominant_group_removed"):
                row = {"split_seed": 1, "selector": selector, "variant": variant}
                row.update({metric: 0.5 for metric in SEED_METRIC_VALUE_COLUMNS})
                row.update(
                    {
                        "attack_families_included": 2,
                        "benign_families_included": 2,
                        "attack_family_set_sha256": "a" * 64,
                        "benign_family_set_sha256": "b" * 64,
                    }
                )
                rows.append(row)
        aggregate = aggregate_seed_metrics(rows, config)
        encoded = json.dumps(aggregate).lower()
        self.assertNotIn("wilson", encoded)
        self.assertNotIn("p_value", encoded)
        self.assertIn("not a confidence", encoded)
        self.assertIn("not capture, device, session", CLAIM_BOUNDARY)

    def test_macro_removal_delta_is_undefined_when_family_set_changes(self) -> None:
        config = load_config(DEFAULT_CONFIG)
        rows = []
        for variant, family_hash in (
            ("full_test", "a" * 64),
            ("dominant_group_removed", "b" * 64),
        ):
            row = {
                "split_seed": 1,
                "selector": "rate_only",
                "variant": variant,
                "attack_families_included": 2 if variant == "full_test" else 1,
                "benign_families_included": 1,
                "attack_family_set_sha256": family_hash,
                "benign_family_set_sha256": "c" * 64,
            }
            row.update({metric: 0.5 for metric in SEED_METRIC_VALUE_COLUMNS})
            rows.append(row)
        aggregate = aggregate_seed_metrics(rows, config)
        delta = aggregate["dominant_group_removal_delta_removed_minus_full"][
            "rate_only"
        ]["attack_present_family_macro_recall"]
        self.assertFalse(delta["defined"])


class DownloaderBindingTests(unittest.TestCase):
    def test_frozen_public_stage_manifest_is_bound_and_valid(self) -> None:
        binding = verify_frozen_public_stage()
        self.assertEqual(binding["schema_version"], "public-rt-iot2022-2.0")
        self.assertEqual(binding["generated_file_count"], 4)

    def test_analysis_and_verified_downloader_hashes_are_identical(self) -> None:
        downloader_path = (
            PROJECT_ROOT / "data" / "public" / "rt_iot2022" / "download.py"
        )
        spec = importlib.util.spec_from_file_location(
            "rt_iot2022_download_for_sensitivity_test", downloader_path
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.ARCHIVE_SHA256, EXPECTED_ARCHIVE_SHA256)
        self.assertEqual(module.EXTRACTED_SHA256, EXPECTED_CSV_SHA256)


def math_is_finite_or_none(value: object) -> bool:
    if isinstance(value, dict):
        return all(math_is_finite_or_none(item) for item in value.values())
    if value is None or isinstance(value, (str, bool, int)):
        return True
    if isinstance(value, float):
        return bool(np.isfinite(value))
    return False


if __name__ == "__main__":
    unittest.main()
