#!/usr/bin/env python3
"""Repeated exact-input-group sensitivity for the public RT-IoT2022 table.

This is a bounded, descriptive companion to :mod:`public_rt_iot2022`.  It
reuses that frozen stage's verified official-source loader, features, model
settings, and calibration rules without changing the frozen stage or its
stored results.  Equality of the configured learned-input tuple defines the
only group relation used here.  Those deduplication groups are explicitly not
capture, device, session, source, time, or independent-sampling identities.

The command executes all 30 configured group splits or none; it intentionally
has no seed-subset or resume mode.  An explicit protocol-freeze acknowledgement
is required.  Outputs contain descriptive fixed-release and split-sensitivity
summaries only: no row-level p-values, row-IID confidence intervals,
population intervals, or deployment-generalization claims are computed.  The
only resampling intervals are explicitly bounded within-release exact-group
sensitivity summaries.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import asdict, dataclass, fields
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
import warnings

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from experiments.public_rt_iot2022 import (
    COMPACT_FEATURES,
    DEFAULT_ARCHIVE,
    DEFAULT_CONFIG as BASE_DEFAULT_CONFIG,
    DEFAULT_CSV,
    EXPECTED_ARCHIVE_SHA256,
    EXPECTED_CSV_SHA256,
    NORMAL_FAMILIES,
    REFERENCE_FEATURES,
    SPLIT_NAMES,
    PublicExperimentConfig,
    apply_or_rule,
    apply_score_rule,
    calibrate_or_rule,
    calibrate_score_threshold,
    load_and_split,
    load_config as load_base_config,
    runtime_record,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = Path(__file__).resolve()
BASE_GENERATOR_PATH = PROJECT_ROOT / "experiments" / "public_rt_iot2022.py"
DOWNLOADER_PATH = PROJECT_ROOT / "data" / "public" / "rt_iot2022" / "download.py"
DATA_PROVENANCE_PATH = (
    PROJECT_ROOT / "data" / "public" / "rt_iot2022" / "PROVENANCE.md"
)
REQUIREMENTS_PATH = PROJECT_ROOT / "requirements.txt"
FROZEN_PUBLIC_MANIFEST_PATH = (
    PROJECT_ROOT / "results" / "public_rt_iot2022" / "manifest.json"
)
FROZEN_PUBLIC_MANIFEST_SHA256 = (
    "d4a7c3850f607b97c737576efb5d5a986c424474dbd22f3f1529feaf34a4ad04"
)
EXPECTED_PROTOCOL_SHA256 = (
    "fc52ec677d93bc2406c1759d42c3d45908d035bddc6f16180d7b9e7d1fd07cf8"
)
EXPECTED_SENSITIVITY_CONFIG_SHA256 = (
    "44800a93a64eba8c1dab9abeaf53f72304670731a76d908d4231835fe343ab68"
)
DEFAULT_CONFIG = PROJECT_ROOT / "configs" / "public_group_sensitivity.json"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "results_additional" / "public_group_sensitivity"
SCHEMA_VERSION = "public-group-sensitivity-1.0"
EXACT_GROUP_ID = "exact_learned_input_group_id"
EXACT_GROUP_TUPLE_SHA256 = "exact_learned_input_tuple_sha256"
ANALYSIS_SPLIT = "sensitivity_split"

SUPPORTED_SELECTORS = (
    "rate_only",
    "dispersion_only",
    "timing_or",
    "compact_logistic",
    "random_forest_reference",
)
LEARNED_MODEL_SELECTORS = ("compact_logistic", "random_forest_reference")
CALIBRATED_HAND_BUILT_COMPARATORS = (
    "rate_only",
    "dispersion_only",
    "timing_or",
)
METRIC_VARIANTS = ("full_test", "dominant_group_removed")
GROUP_BOOTSTRAP_METRICS = (
    "recall_tpr",
    "false_positive_rate",
    "attack_present_family_macro_recall",
    "benign_present_family_macro_false_positive_rate",
)
DOMINANT_GROUP_RULE = "largest_test_exact_group_by_rows_then_lowest_group_id"
CLAIM_BOUNDARY = (
    "Descriptive sensitivity within the one hash-verified, completed-flow "
    "RT-IoT2022 release. Exact compact learned-model input tuples are "
    "deduplication groups only, not capture, device, session, source, time, or "
    "independent-sampling identities. Timing-comparator projection overlaps are "
    "reported separately and are not claimed group-disjoint. Results do not "
    "establish packet-ordered online behavior, "
    "population performance, deployment generalization, kernel execution, or XDP."
)
NO_INFERENCE_STATEMENT = (
    "No row-level p-values or row-IID confidence intervals are computed. "
    "Across-split percentiles summarize only the 30 fixed exact-group splits. "
    "Exact-group bootstrap percentiles are within-release sensitivity "
    "intervals. Neither is a capture, device, session, time, deployment, or "
    "population confidence interval."
)
EXPECTED_GENERATED_FILES = frozenset(
    {
        "group_catalog.csv",
        "group_assignments.csv",
        "split_counts.csv",
        "seed_status.csv",
        "seed_metrics.csv",
        "family_metrics.csv",
        "calibration_rules.csv",
        "projection_overlap_audit.csv",
        "group_bootstrap_replicates.csv",
        "group_bootstrap_intervals.csv",
        "dominant_groups.csv",
        "model_metadata.json",
        "summary.json",
    }
)


class SensitivityError(RuntimeError):
    """Raised when configuration, execution, or artifact integrity fails."""


@dataclass(frozen=True)
class SensitivityConfig:
    schema_version: str
    base_public_config_path: str
    protocol_path: str
    protocol_sha256: str
    exact_group_columns: tuple[str, ...]
    split_hash_namespace: str
    split_modulus: int
    train_bucket_end: int
    calibration_bucket_end: int
    group_bootstrap_method: str
    group_bootstrap_replicates: int
    group_bootstrap_seed: int
    group_bootstrap_macro_min_groups_per_family: int
    group_split_seeds: tuple[int, ...]
    selectors: tuple[str, ...]
    dominant_group_rule: str
    percentile_interval_percent: tuple[float, float]

    def validate(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise SensitivityError(
                f"unsupported sensitivity schema {self.schema_version!r}"
            )
        if self.base_public_config_path != "configs/public_rt_iot2022.json":
            raise SensitivityError("base_public_config_path must bind the frozen stage")
        if self.protocol_path != "EXPERIMENTAL_PROTOCOL_FINAL.md":
            raise SensitivityError("protocol_path must bind EXPERIMENTAL_PROTOCOL_FINAL.md")
        if self.protocol_sha256 != EXPECTED_PROTOCOL_SHA256:
            raise SensitivityError("protocol_sha256 differs from the frozen protocol")
        if tuple(self.exact_group_columns) != tuple(COMPACT_FEATURES):
            raise SensitivityError(
                "exact_group_columns must equal the frozen compact learned-input tuple"
            )
        if self.split_hash_namespace != "rt-iot2022-exact-compact-input-v1":
            raise SensitivityError("unexpected split_hash_namespace")
        if (
            self.group_bootstrap_method
            != "iid_exact_group_cluster_percentile_numpy_linear"
        ):
            raise SensitivityError("unexpected group_bootstrap_method")
        for name in ("split_modulus", "train_bucket_end", "calibration_bucket_end"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise SensitivityError(f"{name} must be an integer")
        if not (
            0
            < self.train_bucket_end
            < self.calibration_bucket_end
            < self.split_modulus
        ):
            raise SensitivityError("split bucket boundaries must be increasing")
        if len(self.group_split_seeds) != 30:
            raise SensitivityError("exactly 30 group_split_seeds are required")
        if len(set(self.group_split_seeds)) != len(self.group_split_seeds):
            raise SensitivityError("group_split_seeds must be unique")
        for seed in self.group_split_seeds:
            if (
                not isinstance(seed, int)
                or isinstance(seed, bool)
                or not 0 <= seed < 2**64
            ):
                raise SensitivityError(
                    "group_split_seeds must be unsigned 64-bit integers"
                )
        if (
            not isinstance(self.group_bootstrap_replicates, int)
            or isinstance(self.group_bootstrap_replicates, bool)
            or self.group_bootstrap_replicates != 2000
        ):
            raise SensitivityError("group_bootstrap_replicates must equal 2000")
        if (
            not isinstance(self.group_bootstrap_seed, int)
            or isinstance(self.group_bootstrap_seed, bool)
            or self.group_bootstrap_seed != 40787
        ):
            raise SensitivityError("group_bootstrap_seed must equal 40787")
        if (
            not isinstance(self.group_bootstrap_macro_min_groups_per_family, int)
            or isinstance(self.group_bootstrap_macro_min_groups_per_family, bool)
            or self.group_bootstrap_macro_min_groups_per_family != 10
        ):
            raise SensitivityError(
                "group_bootstrap_macro_min_groups_per_family must equal 10"
            )
        if tuple(self.selectors) != SUPPORTED_SELECTORS:
            raise SensitivityError(
                f"selectors must be the fixed ordered list {SUPPORTED_SELECTORS!r}"
            )
        if self.dominant_group_rule != DOMINANT_GROUP_RULE:
            raise SensitivityError("unexpected dominant_group_rule")
        if len(self.percentile_interval_percent) != 2:
            raise SensitivityError("percentile interval needs two endpoints")
        lower, upper = self.percentile_interval_percent
        if not (0.0 <= lower < upper <= 100.0):
            raise SensitivityError("invalid percentile_interval_percent")


def _reject_json_constant(token: str) -> None:
    raise ValueError(f"non-finite JSON constant is forbidden: {token}")


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _assert_finite_json(value: Any, location: str = "root") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, (float, np.floating)):
        if not math.isfinite(float(value)):
            raise SensitivityError(f"non-finite JSON number at {location}")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise SensitivityError(f"non-string JSON key at {location}")
            _assert_finite_json(item, f"{location}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _assert_finite_json(item, f"{location}[{index}]")
        return
    if isinstance(value, np.integer):
        return
    raise SensitivityError(
        f"non-JSON value {type(value).__name__} at {location}"
    )


def load_json_strict(path: Path) -> Any:
    try:
        payload = json.loads(
            Path(path).read_text(encoding="utf-8"),
            parse_constant=_reject_json_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise SensitivityError(f"invalid strict JSON at {path}: {exc}") from exc
    _assert_finite_json(payload, str(path))
    return payload


def _json_ready(value: Any) -> Any:
    if isinstance(value, np.integer):
        return int(value)
    if isinstance(value, np.floating):
        return float(value)
    if isinstance(value, Mapping):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    return value


def _encoded_json(value: Any, *, pretty: bool) -> bytes:
    ready = _json_ready(value)
    _assert_finite_json(ready)
    if pretty:
        text = json.dumps(ready, indent=2, sort_keys=True, allow_nan=False) + "\n"
    else:
        text = json.dumps(
            ready, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
    return text.encode("utf-8")


def canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(_encoded_json(value, pretty=False)).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json_strict(path: Path, value: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_bytes(_encoded_json(value, pretty=True))
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _csv_scalar(value: Any, location: str) -> str | int | float:
    if value is None:
        return ""
    if isinstance(value, (bool, np.bool_)):
        return "true" if bool(value) else "false"
    if isinstance(value, (int, np.integer)):
        return int(value)
    if isinstance(value, (float, np.floating)):
        numeric = float(value)
        if not math.isfinite(numeric):
            raise SensitivityError(f"non-finite CSV number at {location}")
        return numeric
    if isinstance(value, str):
        return value
    raise SensitivityError(f"non-scalar CSV value at {location}: {type(value).__name__}")


def write_csv_strict(
    path: Path, rows: Iterable[Mapping[str, Any]], columns: Sequence[str]
) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    expected = tuple(columns)
    if len(set(expected)) != len(expected) or not expected:
        raise SensitivityError("CSV columns must be nonempty and unique")
    temporary = path.with_name(f".{path.name}.tmp")
    count = 0
    try:
        with temporary.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=list(expected),
                extrasaction="raise",
                lineterminator="\n",
            )
            writer.writeheader()
            for count, row in enumerate(rows, start=1):
                if set(row) != set(expected):
                    raise SensitivityError(
                        f"CSV row {count} fields differ: "
                        f"missing={sorted(set(expected) - set(row))}, "
                        f"unknown={sorted(set(row) - set(expected))}"
                    )
                writer.writerow(
                    {
                        column: _csv_scalar(row[column], f"{path.name}[{count}].{column}")
                        for column in expected
                    }
                )
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return count


def _project_path(relative_name: str, label: str) -> Path:
    candidate = Path(relative_name)
    if candidate.is_absolute():
        raise SensitivityError(f"{label} must be project-relative")
    resolved = (PROJECT_ROOT / candidate).resolve()
    try:
        resolved.relative_to(PROJECT_ROOT.resolve())
    except ValueError as exc:
        raise SensitivityError(f"{label} escapes the project root") from exc
    return resolved


def _display_path(path: Path) -> str:
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(PROJECT_ROOT.resolve()).as_posix()
    except ValueError:
        return resolved.name


def load_config(path: Path = DEFAULT_CONFIG) -> SensitivityConfig:
    payload = load_json_strict(path)
    if not isinstance(payload, Mapping):
        raise SensitivityError("sensitivity config must be a JSON object")
    expected = {item.name for item in fields(SensitivityConfig)}
    observed = set(payload)
    if observed != expected:
        raise SensitivityError(
            "config fields differ: "
            f"missing={sorted(expected - observed)}, unknown={sorted(observed - expected)}"
        )
    converted = dict(payload)
    for key in ("exact_group_columns", "group_split_seeds", "selectors"):
        if not isinstance(converted[key], list):
            raise SensitivityError(f"config.{key} must be a JSON array")
        converted[key] = tuple(converted[key])
    percentile = converted["percentile_interval_percent"]
    if not isinstance(percentile, list):
        raise SensitivityError("config.percentile_interval_percent must be an array")
    converted["percentile_interval_percent"] = tuple(percentile)
    config = SensitivityConfig(**converted)
    config.validate()
    _project_path(config.base_public_config_path, "base_public_config_path")
    _project_path(config.protocol_path, "protocol_path")
    return config


def _python_scalar(value: Any) -> Any:
    return value.item() if isinstance(value, np.generic) else value


def define_exact_groups(
    frame: pd.DataFrame, columns: Sequence[str] = COMPACT_FEATURES
) -> tuple[pd.DataFrame, pd.DataFrame, tuple[str, ...]]:
    """Assign collision-free IDs by exact tuple equality, never by hash equality."""

    columns = tuple(columns)
    missing = sorted(
        {
            *columns,
            "source_file_row_position_zero_based",
            "Attack_type",
            "true_label",
        }
        - set(frame.columns)
    )
    if missing:
        raise SensitivityError(f"group input frame lacks columns: {missing}")
    if frame[list(columns)].isna().any().any():
        raise SensitivityError("exact learned-input tuples contain missing values")
    numeric = frame[list(columns)].to_numpy(dtype=float)
    if not np.isfinite(numeric).all():
        raise SensitivityError("exact learned-input tuples contain non-finite values")

    tuple_index = pd.MultiIndex.from_frame(frame[list(columns)])
    codes, _ = pd.factorize(tuple_index, sort=False)
    if (codes < 0).any():
        raise SensitivityError("exact tuple factorization produced an invalid code")
    source_positions = frame["source_file_row_position_zero_based"].to_numpy(
        dtype=np.int64
    )
    code_count = int(codes.max()) + 1 if len(codes) else 0
    first_positions = np.full(code_count, np.iinfo(np.int64).max, dtype=np.int64)
    np.minimum.at(first_positions, codes, source_positions)
    group_ids = first_positions[codes]

    grouped_frame = frame.copy()
    grouped_frame[EXACT_GROUP_ID] = group_ids
    if int(grouped_frame[EXACT_GROUP_ID].nunique()) != code_count:
        raise SensitivityError("exact group IDs are not one-to-one with exact tuples")
    reverse_count = int(
        grouped_frame.groupby(list(columns), sort=False, dropna=False).ngroups
    )
    if reverse_count != code_count:
        raise SensitivityError("one exact tuple maps to more than one exact group")

    families = tuple(sorted(str(value) for value in grouped_frame["Attack_type"].unique()))
    grouped = grouped_frame.groupby(EXACT_GROUP_ID, sort=True, observed=False)
    catalog = grouped.agg(
        first_source_row_position_zero_based=(
            "source_file_row_position_zero_based",
            "min",
        ),
        row_count=(EXACT_GROUP_ID, "size"),
        benign_rows=("true_label", lambda values: int((values == 0).sum())),
        attack_rows=("true_label", lambda values: int((values == 1).sum())),
        distinct_binary_labels=("true_label", "nunique"),
        distinct_families=("Attack_type", "nunique"),
    )
    feature_first = grouped[list(columns)].first()
    catalog = catalog.join(feature_first)
    family_counts = pd.crosstab(
        grouped_frame[EXACT_GROUP_ID], grouped_frame["Attack_type"]
    ).reindex(columns=families, fill_value=0)
    family_counts.columns = [f"family_rows::{name}" for name in family_counts.columns]
    catalog = catalog.join(family_counts).reset_index()

    tuple_hashes: list[str] = []
    for _, row in catalog.iterrows():
        tuple_hashes.append(
            canonical_json_sha256(
                {
                    "columns": list(columns),
                    "values": [_python_scalar(row[column]) for column in columns],
                }
            )
        )
    catalog.insert(1, EXACT_GROUP_TUPLE_SHA256, tuple_hashes)
    if catalog[EXACT_GROUP_TUPLE_SHA256].duplicated().any():
        raise SensitivityError("exact tuple SHA-256 collision in the bound table")
    if int(catalog["row_count"].sum()) != len(grouped_frame):
        raise SensitivityError("exact group catalog does not retain every source row")
    return grouped_frame, catalog, families


def _seeded_bucket(
    group_id: int, seed: int, namespace: str, modulus: int
) -> int:
    if not 0 <= seed < 2**64 or not 0 <= group_id < 2**64:
        raise SensitivityError("split seed and exact group ID must fit uint64")
    payload = (
        namespace.encode("utf-8")
        + b"\0"
        + seed.to_bytes(8, "big", signed=False)
        + group_id.to_bytes(8, "big", signed=False)
    )
    value = int.from_bytes(hashlib.sha256(payload).digest()[:8], "big")
    return value % modulus


def assign_groups(
    catalog: pd.DataFrame, seed: int, config: SensitivityConfig
) -> pd.DataFrame:
    """Atomically assign each exact group using a seeded cryptographic bucket."""

    config.validate()
    if not isinstance(seed, int) or isinstance(seed, bool) or seed < 0:
        raise SensitivityError("seed must be a nonnegative integer")
    if catalog[EXACT_GROUP_ID].duplicated().any():
        raise SensitivityError("group catalog contains duplicate group IDs")
    identifiers = catalog[EXACT_GROUP_ID].to_numpy(dtype=np.int64)
    buckets = np.fromiter(
        (
            _seeded_bucket(
                int(group_id), seed, config.split_hash_namespace, config.split_modulus
            )
            for group_id in identifiers
        ),
        dtype=np.int64,
        count=len(identifiers),
    )
    splits = np.where(
        buckets < config.train_bucket_end,
        "train",
        np.where(buckets < config.calibration_bucket_end, "calibration", "test"),
    )
    assignment = pd.DataFrame(
        {
            "split_seed": seed,
            EXACT_GROUP_ID: identifiers,
            EXACT_GROUP_TUPLE_SHA256: catalog[
                EXACT_GROUP_TUPLE_SHA256
            ].astype(str).to_numpy(),
            "split_bucket": buckets,
            ANALYSIS_SPLIT: splits,
        }
    ).sort_values(EXACT_GROUP_ID, kind="stable")
    if assignment[EXACT_GROUP_ID].duplicated().any():
        raise SensitivityError("one exact group received multiple split assignments")
    return assignment.reset_index(drop=True)


def split_assignment_sha256(assignment: pd.DataFrame) -> str:
    required = {
        "split_seed",
        EXACT_GROUP_ID,
        "split_bucket",
        ANALYSIS_SPLIT,
    }
    if required - set(assignment.columns):
        raise SensitivityError("assignment fingerprint input is incomplete")
    digest = hashlib.sha256()
    split_codes = {"train": 0, "calibration": 1, "test": 2}
    ordered = assignment.sort_values(EXACT_GROUP_ID, kind="stable")
    for row in ordered.itertuples(index=False):
        record = row._asdict()
        split = str(record[ANALYSIS_SPLIT])
        if split not in split_codes:
            raise SensitivityError(f"unknown split in assignment: {split!r}")
        digest.update(int(record["split_seed"]).to_bytes(8, "big", signed=False))
        digest.update(int(record[EXACT_GROUP_ID]).to_bytes(8, "big", signed=False))
        digest.update(int(record["split_bucket"]).to_bytes(8, "big", signed=False))
        digest.update(bytes([split_codes[split]]))
    return digest.hexdigest()


def materialize_split(
    frame: pd.DataFrame, assignment: pd.DataFrame
) -> pd.DataFrame:
    mapping = assignment.set_index(EXACT_GROUP_ID)[ANALYSIS_SPLIT]
    split_frame = frame.copy()
    split_frame[ANALYSIS_SPLIT] = split_frame[EXACT_GROUP_ID].map(mapping)
    if split_frame[ANALYSIS_SPLIT].isna().any():
        raise SensitivityError("at least one source row lacks a group assignment")
    if set(split_frame[ANALYSIS_SPLIT].unique()) - set(SPLIT_NAMES):
        raise SensitivityError("unexpected split label after materialization")
    crossings = split_frame.groupby(EXACT_GROUP_ID, sort=False)[
        ANALYSIS_SPLIT
    ].nunique()
    if len(crossings) and int(crossings.max()) != 1:
        raise SensitivityError("exact learned-input group crosses partitions")
    # Reference-input equality is nested inside compact-input equality because
    # COMPACT_FEATURES is a strict subset of REFERENCE_FEATURES.  The explicit
    # check keeps that proof executable if either frozen feature list changes.
    if not set(COMPACT_FEATURES).issubset(REFERENCE_FEATURES):
        raise SensitivityError("frozen compact/reference nesting no longer holds")
    reference_crossings = split_frame.groupby(
        list(REFERENCE_FEATURES), sort=False, dropna=False
    )[ANALYSIS_SPLIT].nunique()
    if len(reference_crossings) and int(reference_crossings.max()) != 1:
        raise SensitivityError("exact reference learned-input tuple crosses partitions")
    return split_frame


def projection_overlap_audit(
    frame: pd.DataFrame, seed: int
) -> list[dict[str, Any]]:
    """Audit exact projection equality without redefining deduplication groups.

    Compact and reference tuples are the learned-model inputs and must never
    cross. The one-/two-field timing projections belong to deterministic,
    hand-built comparators; equal scalar values are expected across partitions
    and are reported rather than mislabeled as capture/entity duplicates.
    """

    definitions = (
        ("compact_logistic_input", "learned_model_input", COMPACT_FEATURES, True),
        (
            "random_forest_reference_input",
            "learned_model_input",
            REFERENCE_FEATURES,
            True,
        ),
        (
            "rate_only_projection",
            "calibrated_hand_built_comparator_projection",
            ("flow_pkts_per_sec",),
            False,
        ),
        (
            "dispersion_only_projection",
            "calibrated_hand_built_comparator_projection",
            ("flow_iat.std",),
            False,
        ),
        (
            "timing_or_projection",
            "calibrated_hand_built_comparator_projection",
            ("flow_pkts_per_sec", "flow_iat.std"),
            False,
        ),
    )
    result: list[dict[str, Any]] = []
    for name, role, columns, separation_required in definitions:
        columns = tuple(columns)
        sets = {
            split: set(
                frame.loc[frame[ANALYSIS_SPLIT] == split, list(columns)].itertuples(
                    index=False, name=None
                )
            )
            for split in SPLIT_NAMES
        }
        train_calibration = sets["train"] & sets["calibration"]
        train_test = sets["train"] & sets["test"]
        calibration_test = sets["calibration"] & sets["test"]
        crossing = train_calibration | train_test | calibration_test
        if crossing:
            tuple_values = pd.MultiIndex.from_frame(frame[list(columns)])
            crossing_index = pd.MultiIndex.from_tuples(crossing, names=list(columns))
            rows_in_crossing = int(tuple_values.isin(crossing_index).sum())
        else:
            rows_in_crossing = 0
        if separation_required and crossing:
            raise SensitivityError(
                f"exact learned-model input crosses partitions for {name}"
            )
        result.append(
            {
                "split_seed": seed,
                "projection": name,
                "projection_role": role,
                "columns_in_order": " | ".join(columns),
                "exact_cross_split_separation_required": separation_required,
                "train_distinct_tuple_count": len(sets["train"]),
                "calibration_distinct_tuple_count": len(sets["calibration"]),
                "test_distinct_tuple_count": len(sets["test"]),
                "train_calibration_overlap_tuple_count": len(train_calibration),
                "train_test_overlap_tuple_count": len(train_test),
                "calibration_test_overlap_tuple_count": len(calibration_test),
                "crossing_any_partition_pair_tuple_count": len(crossing),
                "rows_in_crossing_tuples": rows_in_crossing,
                "interpretation": (
                    "zero overlap required for exact learned-model input tuples"
                    if separation_required
                    else (
                        "descriptive equality audit for a hand-built comparator "
                        "projection; scalar equality is not a capture/device/session "
                        "identity and no cross-partition separation claim is made"
                    )
                ),
            }
        )
    return result


def _split_count_rows(
    frame: pd.DataFrame, seed: int, families: Sequence[str]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    categories: list[tuple[str, str, np.ndarray]] = [
        ("all", "__ALL__", np.ones(len(frame), dtype=bool)),
        ("binary_label", "__BENIGN__", frame["true_label"].eq(0).to_numpy()),
        ("binary_label", "__ATTACK__", frame["true_label"].eq(1).to_numpy()),
    ]
    categories.extend(
        (
            "family",
            str(family),
            frame["Attack_type"].astype(str).eq(str(family)).to_numpy(),
        )
        for family in families
    )
    split_values = frame[ANALYSIS_SPLIT].astype(str).to_numpy()
    group_values = frame[EXACT_GROUP_ID].to_numpy(dtype=np.int64)
    for split in SPLIT_NAMES:
        split_mask = split_values == split
        for category_type, category, category_mask in categories:
            mask = split_mask & category_mask
            rows.append(
                {
                    "split_seed": seed,
                    "split": split,
                    "category_type": category_type,
                    "category": category,
                    "row_count": int(mask.sum()),
                    "exact_group_count": int(np.unique(group_values[mask]).size),
                }
            )
    return rows


def validate_split(
    frame: pd.DataFrame, families: Sequence[str]
) -> list[str]:
    """Return all mechanical invalidity reasons without choosing replacement seeds."""

    reasons: list[str] = []
    for split in SPLIT_NAMES:
        partition = frame[frame[ANALYSIS_SPLIT] == split]
        if partition.empty:
            reasons.append(f"empty_partition:{split}")
            continue
        present_labels = set(int(value) for value in partition["true_label"].unique())
        if present_labels != {0, 1}:
            reasons.append(f"empty_binary_class:{split}")
    # Rare families can be absent when exact groups are assigned atomically.
    # Their zero counts and undefined per-family metrics are retained; seeds are
    # never replaced. Only missing binary classes make fit/calibration impossible.
    del families
    crossings = frame.groupby(EXACT_GROUP_ID, sort=False)[ANALYSIS_SPLIT].nunique()
    if len(crossings) and int(crossings.max()) > 1:
        reasons.append("exact_group_cross_split_leakage")
    return reasons


def _safe_rate(numerator: float, denominator: float) -> float | None:
    return float(numerator / denominator) if denominator else None


def descriptive_binary_metrics(
    labels: np.ndarray, prediction: np.ndarray
) -> dict[str, Any]:
    labels = np.asarray(labels, dtype=int)
    prediction = np.asarray(prediction, dtype=bool)
    if len(labels) != len(prediction):
        raise SensitivityError("metric label and prediction lengths differ")
    if set(np.unique(labels)) - {0, 1}:
        raise SensitivityError("binary metrics require labels in {0, 1}")
    tp = int(((labels == 1) & prediction).sum())
    fp = int(((labels == 0) & prediction).sum())
    tn = int(((labels == 0) & ~prediction).sum())
    fn = int(((labels == 1) & ~prediction).sum())
    precision = _safe_rate(tp, tp + fp)
    recall = _safe_rate(tp, tp + fn)
    specificity = _safe_rate(tn, tn + fp)
    fpr = _safe_rate(fp, fp + tn)
    fnr = _safe_rate(fn, fn + tp)
    accuracy = _safe_rate(tp + tn, len(labels))
    f1 = _safe_rate(2 * tp, 2 * tp + fp + fn)
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall_tpr": recall,
        "specificity_tnr": specificity,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "f1": f1,
        "predicted_positive_rate": _safe_rate(int(prediction.sum()), len(labels)),
    }


def equal_group_weighted_metrics(
    group_ids: np.ndarray, labels: np.ndarray, prediction: np.ndarray
) -> dict[str, Any]:
    group_ids = np.asarray(group_ids, dtype=np.int64)
    labels = np.asarray(labels, dtype=int)
    prediction = np.asarray(prediction, dtype=bool)
    if len({len(group_ids), len(labels), len(prediction)}) != 1:
        raise SensitivityError("group-balanced metric arrays differ in length")
    work = pd.DataFrame(
        {
            EXACT_GROUP_ID: group_ids,
            "label": labels,
            "prediction": prediction.astype(float),
            "correct": (prediction == labels).astype(float),
        }
    )
    group_accuracy = work.groupby(EXACT_GROUP_ID, sort=False)["correct"].mean()
    attack = work[work["label"] == 1].groupby(EXACT_GROUP_ID, sort=False)[
        "prediction"
    ].mean()
    benign = work[work["label"] == 0].groupby(EXACT_GROUP_ID, sort=False)[
        "prediction"
    ].mean()
    return {
        "equal_exact_group_weighted_accuracy": (
            float(group_accuracy.mean()) if len(group_accuracy) else None
        ),
        "equal_exact_group_weighted_recall_tpr": (
            float(attack.mean()) if len(attack) else None
        ),
        "equal_exact_group_weighted_false_positive_rate": (
            float(benign.mean()) if len(benign) else None
        ),
        "accuracy_group_count": int(len(group_accuracy)),
        "attack_group_count": int(len(attack)),
        "benign_group_count": int(len(benign)),
    }


def family_metrics(
    frame: pd.DataFrame,
    prediction: np.ndarray,
    families: Sequence[str],
    *,
    seed: int,
    selector: str,
    variant: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    prediction = np.asarray(prediction, dtype=bool)
    if len(frame) != len(prediction):
        raise SensitivityError("family metric prediction length differs")
    names = frame["Attack_type"].astype(str).to_numpy()
    group_ids = frame[EXACT_GROUP_ID].to_numpy(dtype=np.int64)
    result: list[dict[str, Any]] = []
    attack_row_rates: list[float] = []
    benign_row_rates: list[float] = []
    attack_group_rates: list[float] = []
    benign_group_rates: list[float] = []
    attack_family_names: list[str] = []
    benign_family_names: list[str] = []
    for family in families:
        mask = names == str(family)
        total = int(mask.sum())
        flagged = int(prediction[mask].sum())
        row_rate = _safe_rate(flagged, total)
        if total:
            work = pd.DataFrame(
                {
                    EXACT_GROUP_ID: group_ids[mask],
                    "prediction": prediction[mask].astype(float),
                }
            )
            per_group = work.groupby(EXACT_GROUP_ID, sort=False)["prediction"].mean()
            group_rate: float | None = float(per_group.mean())
            group_count = int(len(per_group))
        else:
            group_rate = None
            group_count = 0
        kind = "benign" if family in NORMAL_FAMILIES else "attack"
        interpretation = (
            "benign-family false-positive flow-row rate"
            if kind == "benign"
            else "attack-family recall over completed-flow rows"
        )
        result.append(
            {
                "split_seed": seed,
                "selector": selector,
                "variant": variant,
                "family": str(family),
                "family_kind": kind,
                "row_count": total,
                "flagged_row_count": flagged,
                "flagged_row_rate_defined": row_rate is not None,
                "flagged_row_rate": row_rate,
                "exact_group_count": group_count,
                "equal_exact_group_weighted_flagged_rate_defined": group_rate
                is not None,
                "equal_exact_group_weighted_flagged_rate": group_rate,
                "interpretation": interpretation,
            }
        )
        if row_rate is not None:
            (benign_row_rates if kind == "benign" else attack_row_rates).append(
                row_rate
            )
            (
                benign_family_names if kind == "benign" else attack_family_names
            ).append(str(family))
        if group_rate is not None:
            (benign_group_rates if kind == "benign" else attack_group_rates).append(
                group_rate
            )
    macro = {
        "attack_present_family_macro_recall": (
            float(np.mean(attack_row_rates)) if attack_row_rates else None
        ),
        "benign_present_family_macro_false_positive_rate": (
            float(np.mean(benign_row_rates)) if benign_row_rates else None
        ),
        "attack_present_family_macro_equal_group_weighted_recall": (
            float(np.mean(attack_group_rates)) if attack_group_rates else None
        ),
        "benign_present_family_macro_equal_group_weighted_false_positive_rate": (
            float(np.mean(benign_group_rates)) if benign_group_rates else None
        ),
        "attack_families_included": len(attack_row_rates),
        "benign_families_included": len(benign_row_rates),
        "attack_family_set_sha256": canonical_json_sha256(attack_family_names),
        "benign_family_set_sha256": canonical_json_sha256(benign_family_names),
        "macro_scope": (
            "unweighted mean over families present in this exact test variant; "
            "the included count and family-set hash define the denominator"
        ),
    }
    return result, macro


def fit_and_predict_selectors(
    split_frame: pd.DataFrame, base_config: PublicExperimentConfig
) -> tuple[
    pd.DataFrame,
    dict[str, np.ndarray],
    dict[str, Mapping[str, Any]],
    dict[str, Any],
]:
    """Refit learned models and recalibrate every selector for one group split."""

    train = split_frame[split_frame[ANALYSIS_SPLIT] == "train"]
    calibration = split_frame[split_frame[ANALYSIS_SPLIT] == "calibration"]
    test = split_frame[split_frame[ANALYSIS_SPLIT] == "test"].copy()
    y_train = train["true_label"].to_numpy(dtype=int)
    y_cal = calibration["true_label"].to_numpy(dtype=int)

    rate_cal = np.log1p(calibration["flow_pkts_per_sec"].to_numpy(dtype=float))
    rate_test = np.log1p(test["flow_pkts_per_sec"].to_numpy(dtype=float))
    dispersion_cal = -np.log1p(
        calibration["flow_iat.std"].to_numpy(dtype=float)
    )
    dispersion_test = -np.log1p(test["flow_iat.std"].to_numpy(dtype=float))
    rate_rule = calibrate_score_threshold(
        rate_cal, y_cal, base_config.calibration_target_fpr
    )
    dispersion_rule = calibrate_score_threshold(
        dispersion_cal, y_cal, base_config.calibration_target_fpr
    )
    or_rule = calibrate_or_rule(
        rate_cal,
        dispersion_cal,
        y_cal,
        base_config.calibration_target_fpr,
    )

    logistic = Pipeline(
        [
            ("scale", StandardScaler()),
            (
                "model",
                LogisticRegression(
                    class_weight="balanced",
                    max_iter=base_config.logistic_max_iter,
                    random_state=base_config.logistic_random_state,
                ),
            ),
        ]
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ConvergenceWarning)
        logistic.fit(train[list(COMPACT_FEATURES)], y_train)
    convergence = [
        warning
        for warning in caught
        if issubclass(warning.category, ConvergenceWarning)
    ]
    if convergence:
        raise SensitivityError("compact logistic failed to converge")
    logistic_cal = logistic.predict_proba(calibration[list(COMPACT_FEATURES)])[:, 1]
    logistic_test = logistic.predict_proba(test[list(COMPACT_FEATURES)])[:, 1]
    logistic_rule = calibrate_score_threshold(
        logistic_cal, y_cal, base_config.calibration_target_fpr
    )

    forest = RandomForestClassifier(
        n_estimators=base_config.forest_estimators,
        max_depth=base_config.forest_max_depth,
        min_samples_leaf=base_config.forest_min_samples_leaf,
        max_features="sqrt",
        class_weight="balanced_subsample",
        random_state=base_config.forest_random_state,
        n_jobs=1,
    )
    forest.fit(train[list(REFERENCE_FEATURES)], y_train)
    forest_cal = forest.predict_proba(calibration[list(REFERENCE_FEATURES)])[:, 1]
    forest_test = forest.predict_proba(test[list(REFERENCE_FEATURES)])[:, 1]
    forest_rule = calibrate_score_threshold(
        forest_cal, y_cal, base_config.calibration_target_fpr
    )

    rules: dict[str, Mapping[str, Any]] = {
        "rate_only": rate_rule,
        "dispersion_only": dispersion_rule,
        "timing_or": or_rule,
        "compact_logistic": logistic_rule,
        "random_forest_reference": forest_rule,
    }
    predictions = {
        "rate_only": apply_score_rule(rate_test, rate_rule),
        "dispersion_only": apply_score_rule(dispersion_test, dispersion_rule),
        "timing_or": apply_or_rule(rate_test, dispersion_test, or_rule),
        "compact_logistic": apply_score_rule(logistic_test, logistic_rule),
        "random_forest_reference": apply_score_rule(forest_test, forest_rule),
    }
    scaler = logistic.named_steps["scale"]
    logistic_model = logistic.named_steps["model"]
    metadata = {
        "compact_logistic": {
            "features_in_order": list(COMPACT_FEATURES),
            "standardizer_mean": scaler.mean_.tolist(),
            "standardizer_scale": scaler.scale_.tolist(),
            "coefficients_in_standardized_feature_space": logistic_model.coef_[
                0
            ].tolist(),
            "intercept": logistic_model.intercept_.tolist(),
            "classes": logistic_model.classes_.tolist(),
            "iterations_by_class": logistic_model.n_iter_.tolist(),
            "convergence_warning_count": 0,
            "random_state": base_config.logistic_random_state,
            "max_iter": base_config.logistic_max_iter,
        },
        "random_forest_reference": {
            "features_in_order": list(REFERENCE_FEATURES),
            "feature_importances": forest.feature_importances_.tolist(),
            "classes": forest.classes_.tolist(),
            "estimators": base_config.forest_estimators,
            "max_depth": base_config.forest_max_depth,
            "min_samples_leaf": base_config.forest_min_samples_leaf,
            "random_state": base_config.forest_random_state,
            "workers": 1,
        },
    }
    if tuple(predictions) != SUPPORTED_SELECTORS:
        raise SensitivityError("selector implementation order differs from frozen config")
    return test, predictions, rules, metadata


def _calibration_rows(
    seed: int, rules: Mapping[str, Mapping[str, Any]]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for selector in SUPPORTED_SELECTORS:
        rule = rules[selector]
        comparator = (
            str(rule.get("comparator"))
            if "comparator" in rule
            else f"{rule.get('rate_comparator')} OR {rule.get('dispersion_comparator')}"
        )
        rows.append(
            {
                "split_seed": seed,
                "selector": selector,
                "comparator": comparator,
                "decision_rule": str(rule.get("decision_rule", "")),
                "target_fpr": rule.get("target_fpr"),
                "threshold": rule.get("threshold"),
                "rate_threshold": rule.get("rate_threshold"),
                "dispersion_threshold": rule.get("dispersion_threshold"),
                "allowed_false_positives": rule.get("allowed_false_positives"),
                "rate_false_positive_budget": rule.get("rate_fp_budget"),
                "dispersion_false_positive_budget": rule.get("dispersion_fp_budget"),
                "calibration_false_positives": rule.get(
                    "calibration_false_positives"
                ),
                "calibration_fpr": rule.get("calibration_fpr"),
                "calibration_recall": rule.get("calibration_recall"),
                "benign_rows_tied_at_threshold": rule.get(
                    "benign_rows_tied_at_threshold"
                ),
                "all_rows_tied_at_threshold": rule.get(
                    "all_rows_tied_at_threshold"
                ),
                "benign_rate_ties_at_threshold": rule.get(
                    "benign_rate_ties_at_threshold"
                ),
                "benign_dispersion_ties_at_threshold": rule.get(
                    "benign_dispersion_ties_at_threshold"
                ),
            }
        )
    return rows


def dominant_test_group(
    test: pd.DataFrame,
    catalog: pd.DataFrame,
    families: Sequence[str],
    seed: int,
) -> dict[str, Any]:
    if test.empty:
        raise SensitivityError("cannot select a dominant group from an empty test set")
    sizes = (
        test.groupby(EXACT_GROUP_ID, sort=True)
        .size()
        .rename("test_rows")
        .reset_index()
        .sort_values(["test_rows", EXACT_GROUP_ID], ascending=[False, True])
    )
    group_id = int(sizes.iloc[0][EXACT_GROUP_ID])
    subset = test[test[EXACT_GROUP_ID] == group_id]
    catalog_row = catalog.set_index(EXACT_GROUP_ID).loc[group_id]
    result: dict[str, Any] = {
        "split_seed": seed,
        EXACT_GROUP_ID: group_id,
        EXACT_GROUP_TUPLE_SHA256: str(catalog_row[EXACT_GROUP_TUPLE_SHA256]),
        "selection_rule": DOMINANT_GROUP_RULE,
        "test_rows": len(test),
        "test_exact_group_count": int(test[EXACT_GROUP_ID].nunique()),
        "dominant_group_rows": len(subset),
        "dominant_group_test_row_share": float(len(subset) / len(test)),
        "dominant_group_benign_rows": int((subset["true_label"] == 0).sum()),
        "dominant_group_attack_rows": int((subset["true_label"] == 1).sum()),
        "dominant_group_distinct_families": int(subset["Attack_type"].nunique()),
    }
    for family in families:
        result[f"family_rows::{family}"] = int(
            subset["Attack_type"].astype(str).eq(str(family)).sum()
        )
    return result


def _derived_group_bootstrap_seed(
    config: SensitivityConfig, split_seed: int, variant: str
) -> int:
    if variant not in METRIC_VARIANTS:
        raise SensitivityError(f"unknown bootstrap variant {variant!r}")
    payload = (
        b"public-group-bootstrap-v1\0"
        + int(config.group_bootstrap_seed).to_bytes(8, "big", signed=False)
        + int(split_seed).to_bytes(8, "big", signed=False)
        + variant.encode("ascii")
    )
    return int.from_bytes(hashlib.sha256(payload).digest()[:8], "big")


def _bootstrap_interval(
    values: np.ndarray,
    point_estimate: float | None,
    config: SensitivityConfig,
    *,
    support_available: bool,
    unavailable_reason: str,
) -> dict[str, Any]:
    values = np.asarray(values, dtype=float)
    defined = np.isfinite(values)
    defined_count = int(defined.sum())
    available = bool(support_available and defined_count)
    if available:
        lower_percent, upper_percent = config.percentile_interval_percent
        finite_values = values[defined]
        lower = float(np.percentile(finite_values, lower_percent, method="linear"))
        upper = float(np.percentile(finite_values, upper_percent, method="linear"))
        reason = ""
    else:
        lower = None
        upper = None
        reason = (
            unavailable_reason
            if not support_available
            else "every exact-group resample has an undefined denominator"
        )
    return {
        "point_estimate": point_estimate,
        "interval_available": available,
        "defined_replicate_count": defined_count,
        "undefined_replicate_count": int(len(values) - defined_count),
        "configured_replicate_count": config.group_bootstrap_replicates,
        "lower": lower,
        "upper": upper,
        "lower_percent": config.percentile_interval_percent[0],
        "upper_percent": config.percentile_interval_percent[1],
        "percentile_method": "numpy linear",
        "interval_values_policy": (
            "percentiles use defined finite replicates; every configured replicate "
            "is retained with an explicit defined flag"
        ),
        "unavailable_reason": reason,
    }


def group_bootstrap_sensitivity(
    test: pd.DataFrame,
    predictions: Mapping[str, np.ndarray],
    families: Sequence[str],
    seed: int,
    dominant_group_id: int,
    config: SensitivityConfig,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Run deterministic within-release IID exact-group resampling.

    Each draw samples exact groups with replacement and retains every row of a
    selected group. The same group multiplicities are reused for all selectors.
    These are sensitivity intervals for this released table, not confidence
    intervals for captures, devices, sessions, time periods, or a population.
    """

    config.validate()
    raw_rows: list[dict[str, Any]] = []
    interval_rows: list[dict[str, Any]] = []
    full_group_ids = test[EXACT_GROUP_ID].to_numpy(dtype=np.int64)
    full_labels = test["true_label"].to_numpy(dtype=int)
    full_family_names = test["Attack_type"].astype(str).to_numpy()
    prediction_arrays = {
        selector: np.asarray(predictions[selector], dtype=bool)
        for selector in SUPPORTED_SELECTORS
    }
    for selector, prediction in prediction_arrays.items():
        if len(prediction) != len(test):
            raise SensitivityError(
                f"bootstrap prediction length differs for {selector}"
            )

    for variant in METRIC_VARIANTS:
        keep = (
            np.ones(len(test), dtype=bool)
            if variant == "full_test"
            else full_group_ids != int(dominant_group_id)
        )
        group_ids = full_group_ids[keep]
        labels = full_labels[keep]
        family_names = full_family_names[keep]
        unique_groups, inverse = np.unique(group_ids, return_inverse=True)
        group_count = len(unique_groups)
        if not group_count:
            raise SensitivityError("bootstrap variant has no exact groups")
        derived_seed = _derived_group_bootstrap_seed(config, seed, variant)
        rng = np.random.Generator(np.random.PCG64(derived_seed))
        weights = rng.multinomial(
            group_count,
            np.full(group_count, 1.0 / group_count, dtype=float),
            size=config.group_bootstrap_replicates,
        )
        unique_sampled_counts = np.count_nonzero(weights, axis=1)
        attack_by_group = np.bincount(
            inverse, weights=(labels == 1).astype(np.int64), minlength=group_count
        ).astype(np.int64)
        benign_by_group = np.bincount(
            inverse, weights=(labels == 0).astype(np.int64), minlength=group_count
        ).astype(np.int64)
        attack_denominators = weights @ attack_by_group
        benign_denominators = weights @ benign_by_group

        present_families = [
            family for family in families if np.any(family_names == str(family))
        ]
        family_total_by_group = np.column_stack(
            [
                np.bincount(
                    inverse,
                    weights=(family_names == str(family)).astype(np.int64),
                    minlength=group_count,
                ).astype(np.int64)
                for family in present_families
            ]
        )
        family_denominators = weights @ family_total_by_group
        family_group_support = np.count_nonzero(family_total_by_group, axis=0)
        attack_family_indices = np.asarray(
            [
                index
                for index, family in enumerate(present_families)
                if family not in NORMAL_FAMILIES
            ],
            dtype=int,
        )
        benign_family_indices = np.asarray(
            [
                index
                for index, family in enumerate(present_families)
                if family in NORMAL_FAMILIES
            ],
            dtype=int,
        )

        selector_values: dict[str, dict[str, np.ndarray]] = {}
        for selector in SUPPORTED_SELECTORS:
            prediction = prediction_arrays[selector][keep]
            tp_by_group = np.bincount(
                inverse,
                weights=((labels == 1) & prediction).astype(np.int64),
                minlength=group_count,
            ).astype(np.int64)
            fp_by_group = np.bincount(
                inverse,
                weights=((labels == 0) & prediction).astype(np.int64),
                minlength=group_count,
            ).astype(np.int64)
            tp = weights @ tp_by_group
            fp = weights @ fp_by_group
            recall = np.full(config.group_bootstrap_replicates, np.nan)
            false_positive_rate = np.full(
                config.group_bootstrap_replicates, np.nan
            )
            np.divide(
                tp,
                attack_denominators,
                out=recall,
                where=attack_denominators > 0,
            )
            np.divide(
                fp,
                benign_denominators,
                out=false_positive_rate,
                where=benign_denominators > 0,
            )

            family_flagged_by_group = np.column_stack(
                [
                    np.bincount(
                        inverse,
                        weights=(
                            (family_names == str(family)) & prediction
                        ).astype(np.int64),
                        minlength=group_count,
                    ).astype(np.int64)
                    for family in present_families
                ]
            )
            family_flagged = weights @ family_flagged_by_group
            family_rates = np.full(family_flagged.shape, np.nan)
            np.divide(
                family_flagged,
                family_denominators,
                out=family_rates,
                where=family_denominators > 0,
            )

            metric_values: dict[str, np.ndarray] = {
                "recall_tpr": recall,
                "false_positive_rate": false_positive_rate,
            }
            point_metrics = descriptive_binary_metrics(labels, prediction)
            point_estimates: dict[str, float | None] = {
                "recall_tpr": point_metrics["recall_tpr"],
                "false_positive_rate": point_metrics["false_positive_rate"],
            }
            for family_kind, indices, metric_name in (
                (
                    "attack",
                    attack_family_indices,
                    "attack_present_family_macro_recall",
                ),
                (
                    "benign",
                    benign_family_indices,
                    "benign_present_family_macro_false_positive_rate",
                ),
            ):
                family_metric = np.full(config.group_bootstrap_replicates, np.nan)
                if len(indices):
                    defined = np.isfinite(family_rates[:, indices]).all(axis=1)
                    family_metric[defined] = np.mean(
                        family_rates[defined][:, indices], axis=1
                    )
                    original_rates = []
                    for family_index in indices:
                        denominator = int(family_total_by_group[:, family_index].sum())
                        numerator = int(
                            family_flagged_by_group[:, family_index].sum()
                        )
                        original_rates.append(numerator / denominator)
                    point_estimates[metric_name] = float(np.mean(original_rates))
                else:
                    point_estimates[metric_name] = None
                metric_values[metric_name] = family_metric

                support_counts = family_group_support[indices]
                minimum_support = int(support_counts.min()) if len(indices) else 0
                support_available = bool(
                    len(indices)
                    and minimum_support
                    >= config.group_bootstrap_macro_min_groups_per_family
                )
                interval = _bootstrap_interval(
                    family_metric,
                    point_estimates[metric_name],
                    config,
                    support_available=support_available,
                    unavailable_reason=(
                        f"{family_kind} present-family macro has minimum exact-group "
                        f"support {minimum_support}, below frozen minimum "
                        f"{config.group_bootstrap_macro_min_groups_per_family}"
                    ),
                )
                interval_rows.append(
                    {
                        "split_seed": seed,
                        "variant": variant,
                        "selector": selector,
                        "metric": metric_name,
                        "derived_resample_seed_u64": str(derived_seed),
                        "exact_group_count": group_count,
                        "included_family_count": len(indices),
                        "included_family_set_sha256": canonical_json_sha256(
                            [present_families[index] for index in indices]
                        ),
                        "minimum_family_exact_group_support": minimum_support,
                        "macro_support_minimum_required": (
                            config.group_bootstrap_macro_min_groups_per_family
                        ),
                        **interval,
                        "interpretation": (
                            "within-release IID exact-group-resampling sensitivity "
                            "interval; not a capture, device, session, time, or "
                            "population confidence interval"
                        ),
                    }
                )

            for metric_name in ("recall_tpr", "false_positive_rate"):
                interval = _bootstrap_interval(
                    metric_values[metric_name],
                    point_estimates[metric_name],
                    config,
                    support_available=True,
                    unavailable_reason="",
                )
                interval_rows.append(
                    {
                        "split_seed": seed,
                        "variant": variant,
                        "selector": selector,
                        "metric": metric_name,
                        "derived_resample_seed_u64": str(derived_seed),
                        "exact_group_count": group_count,
                        "included_family_count": 0,
                        "included_family_set_sha256": "",
                        "minimum_family_exact_group_support": 0,
                        "macro_support_minimum_required": 0,
                        **interval,
                        "interpretation": (
                            "within-release IID exact-group-resampling sensitivity "
                            "interval; not a capture, device, session, time, or "
                            "population confidence interval"
                        ),
                    }
                )
            selector_values[selector] = metric_values

        for replicate in range(config.group_bootstrap_replicates):
            row: dict[str, Any] = {
                "split_seed": seed,
                "variant": variant,
                "replicate_index_zero_based": replicate,
                "derived_resample_seed_u64": str(derived_seed),
                "sampled_group_draw_count": group_count,
                "unique_sampled_group_count": int(unique_sampled_counts[replicate]),
            }
            for selector in SUPPORTED_SELECTORS:
                for metric in GROUP_BOOTSTRAP_METRICS:
                    value = float(selector_values[selector][metric][replicate])
                    defined = math.isfinite(value)
                    row[f"{selector}::{metric}::defined"] = defined
                    row[f"{selector}::{metric}::value"] = value if defined else None
            raw_rows.append(row)
    return raw_rows, interval_rows


SEED_METRIC_VALUE_COLUMNS = (
    "accuracy",
    "precision",
    "recall_tpr",
    "specificity_tnr",
    "false_positive_rate",
    "false_negative_rate",
    "f1",
    "predicted_positive_rate",
    "equal_exact_group_weighted_accuracy",
    "equal_exact_group_weighted_recall_tpr",
    "equal_exact_group_weighted_false_positive_rate",
    "attack_present_family_macro_recall",
    "benign_present_family_macro_false_positive_rate",
    "attack_present_family_macro_equal_group_weighted_recall",
    "benign_present_family_macro_equal_group_weighted_false_positive_rate",
)


def evaluate_seed(
    split_frame: pd.DataFrame,
    catalog: pd.DataFrame,
    families: Sequence[str],
    seed: int,
    base_config: PublicExperimentConfig,
    sensitivity_config: SensitivityConfig,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, Any],
    dict[str, Any],
]:
    test, predictions, rules, model_metadata = fit_and_predict_selectors(
        split_frame, base_config
    )
    dominant = dominant_test_group(test, catalog, families, seed)
    dominant_id = int(dominant[EXACT_GROUP_ID])
    bootstrap_rows, bootstrap_interval_rows = group_bootstrap_sensitivity(
        test,
        predictions,
        families,
        seed,
        dominant_id,
        sensitivity_config,
    )
    keep_after_removal = test[EXACT_GROUP_ID].to_numpy(dtype=np.int64) != dominant_id
    metric_rows: list[dict[str, Any]] = []
    family_rows: list[dict[str, Any]] = []
    y_full = test["true_label"].to_numpy(dtype=int)
    group_full = test[EXACT_GROUP_ID].to_numpy(dtype=np.int64)
    for selector in SUPPORTED_SELECTORS:
        prediction_full = np.asarray(predictions[selector], dtype=bool)
        for variant in METRIC_VARIANTS:
            keep = (
                np.ones(len(test), dtype=bool)
                if variant == "full_test"
                else keep_after_removal
            )
            variant_frame = test.loc[keep].copy()
            variant_prediction = prediction_full[keep]
            row_metrics = descriptive_binary_metrics(y_full[keep], variant_prediction)
            group_metrics = equal_group_weighted_metrics(
                group_full[keep], y_full[keep], variant_prediction
            )
            per_family, macro = family_metrics(
                variant_frame,
                variant_prediction,
                families,
                seed=seed,
                selector=selector,
                variant=variant,
            )
            family_rows.extend(per_family)
            metric_rows.append(
                {
                    "split_seed": seed,
                    "selector": selector,
                    "variant": variant,
                    "test_row_count": len(variant_frame),
                    "test_exact_group_count": int(
                        variant_frame[EXACT_GROUP_ID].nunique()
                    ),
                    "dominant_group_removed_id": (
                        "" if variant == "full_test" else dominant_id
                    ),
                    "tp": row_metrics["tp"],
                    "fp": row_metrics["fp"],
                    "tn": row_metrics["tn"],
                    "fn": row_metrics["fn"],
                    **{name: row_metrics[name] for name in SEED_METRIC_VALUE_COLUMNS[:8]},
                    **{
                        name: group_metrics[name]
                        for name in SEED_METRIC_VALUE_COLUMNS[8:11]
                    },
                    "accuracy_group_count": group_metrics["accuracy_group_count"],
                    "attack_group_count": group_metrics["attack_group_count"],
                    "benign_group_count": group_metrics["benign_group_count"],
                    **{
                        name: macro[name]
                        for name in SEED_METRIC_VALUE_COLUMNS[11:]
                    },
                    "attack_families_included": macro[
                        "attack_families_included"
                    ],
                    "benign_families_included": macro[
                        "benign_families_included"
                    ],
                    "attack_family_set_sha256": macro["attack_family_set_sha256"],
                    "benign_family_set_sha256": macro["benign_family_set_sha256"],
                    "present_family_macro_scope": macro["macro_scope"],
                }
            )
    model_metadata = {
        "split_seed": seed,
        "fit_partition": "train",
        "threshold_partition": "calibration",
        "test_partition_used_for_fit_or_calibration": False,
        "models": model_metadata,
    }
    return (
        metric_rows,
        family_rows,
        _calibration_rows(seed, rules),
        bootstrap_rows,
        bootstrap_interval_rows,
        model_metadata,
        dominant,
    )


def observed_split_distribution(
    values: Sequence[float | None], percentile_interval: tuple[float, float]
) -> dict[str, Any]:
    observed = np.asarray([float(value) for value in values if value is not None])
    if not len(observed):
        return {
            "defined": False,
            "observed_split_count": 0,
            "reason": "metric undefined in every retained fixed split",
        }
    if not np.isfinite(observed).all():
        raise SensitivityError("non-finite value in split-sensitivity distribution")
    lower, upper = percentile_interval
    return {
        "defined": True,
        "observed_split_count": int(len(observed)),
        "mean": float(np.mean(observed)),
        "median": float(np.median(observed)),
        "minimum": float(np.min(observed)),
        "maximum": float(np.max(observed)),
        "observed_percentile_interval_percent": [lower, upper],
        "observed_percentile_interval": [
            float(np.percentile(observed, lower, method="linear")),
            float(np.percentile(observed, upper, method="linear")),
        ],
        "percentile_method": "numpy linear",
        "interpretation": (
            "descriptive distribution over the fixed group-split seeds; not a "
            "confidence, sampling, or deployment-population interval"
        ),
    }


def _present_family_macro_distribution(
    rows: Sequence[Mapping[str, Any]],
    metric: str,
    percentile_interval: tuple[float, float],
) -> dict[str, Any]:
    family_kind = "attack" if metric.startswith("attack_") else "benign"
    hash_key = f"{family_kind}_family_set_sha256"
    family_sets = sorted(
        {
            str(row[hash_key])
            for row in rows
            if row.get(metric) is not None and row.get(hash_key)
        }
    )
    if len(family_sets) <= 1:
        result = observed_split_distribution(
            [row.get(metric) for row in rows], percentile_interval
        )
        result["family_set_sha256"] = family_sets[0] if family_sets else None
        result["pooled_across_different_family_sets"] = False
        return result
    return {
        "defined": False,
        "pooled_across_different_family_sets": False,
        "reason": (
            "present-family denominator differs across splits; no pooled macro "
            "distribution is reported"
        ),
        "family_set_count": len(family_sets),
        "by_family_set_sha256": {
            family_set: observed_split_distribution(
                [
                    row.get(metric)
                    for row in rows
                    if row.get(hash_key) == family_set
                ],
                percentile_interval,
            )
            for family_set in family_sets
        },
    }


def aggregate_seed_metrics(
    rows: Sequence[Mapping[str, Any]], config: SensitivityConfig
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "fixed_split_seed_count_configured": len(config.group_split_seeds),
        "percentile_scope": NO_INFERENCE_STATEMENT,
        "by_selector_and_variant": {},
        "dominant_group_removal_delta_removed_minus_full": {},
    }
    for selector in SUPPORTED_SELECTORS:
        selector_result: dict[str, Any] = {}
        for variant in METRIC_VARIANTS:
            selected = [
                row
                for row in rows
                if row["selector"] == selector and row["variant"] == variant
            ]
            selector_result[variant] = {}
            for metric in SEED_METRIC_VALUE_COLUMNS:
                if "present_family_macro" in metric:
                    distribution = _present_family_macro_distribution(
                        selected, metric, config.percentile_interval_percent
                    )
                else:
                    distribution = observed_split_distribution(
                        [row.get(metric) for row in selected],
                        config.percentile_interval_percent,
                    )
                selector_result[variant][metric] = distribution
            selector_result[variant]["present_family_denominators"] = {
                "attack_family_count": observed_split_distribution(
                    [row.get("attack_families_included") for row in selected],
                    config.percentile_interval_percent,
                ),
                "benign_family_count": observed_split_distribution(
                    [row.get("benign_families_included") for row in selected],
                    config.percentile_interval_percent,
                ),
                "interpretation": (
                    "Present-family macro values are comparable only when their "
                    "family-set hashes match; per-family distributions are reported "
                    "separately."
                ),
            }
        result["by_selector_and_variant"][selector] = selector_result

        by_seed = {
            int(row["split_seed"]): row
            for row in rows
            if row["selector"] == selector and row["variant"] == "full_test"
        }
        removed_by_seed = {
            int(row["split_seed"]): row
            for row in rows
            if row["selector"] == selector
            and row["variant"] == "dominant_group_removed"
        }
        common = sorted(set(by_seed) & set(removed_by_seed))
        delta_result: dict[str, Any] = {}
        for metric in SEED_METRIC_VALUE_COLUMNS:
            deltas: list[float | None] = []
            for seed in common:
                before = by_seed[seed].get(metric)
                after = removed_by_seed[seed].get(metric)
                if "present_family_macro" in metric:
                    family_kind = "attack" if metric.startswith("attack_") else "benign"
                    hash_key = f"{family_kind}_family_set_sha256"
                    if by_seed[seed].get(hash_key) != removed_by_seed[seed].get(
                        hash_key
                    ):
                        deltas.append(None)
                        continue
                deltas.append(
                    None
                    if before is None or after is None
                    else float(after) - float(before)
                )
            delta_result[metric] = observed_split_distribution(
                deltas, config.percentile_interval_percent
            )
        result["dominant_group_removal_delta_removed_minus_full"][
            selector
        ] = delta_result
    return result


def aggregate_family_metrics(
    rows: Sequence[Mapping[str, Any]], config: SensitivityConfig
) -> dict[str, Any]:
    """Summarize each family separately across the fixed split list."""

    result: dict[str, Any] = {}
    selectors = sorted({str(row["selector"]) for row in rows})
    families = sorted({str(row["family"]) for row in rows})
    for selector in selectors:
        result[selector] = {}
        for variant in METRIC_VARIANTS:
            result[selector][variant] = {}
            for family in families:
                selected = [
                    row
                    for row in rows
                    if row["selector"] == selector
                    and row["variant"] == variant
                    and row["family"] == family
                ]
                present = [row for row in selected if int(row["row_count"]) > 0]
                result[selector][variant][family] = {
                    "configured_record_count": len(selected),
                    "family_present_split_count": len(present),
                    "family_absent_split_count": len(selected) - len(present),
                    "present_split_seed_ids": [
                        int(row["split_seed"]) for row in present
                    ],
                    "flagged_row_rate": observed_split_distribution(
                        [row.get("flagged_row_rate") for row in selected],
                        config.percentile_interval_percent,
                    ),
                    "equal_exact_group_weighted_flagged_rate": (
                        observed_split_distribution(
                            [
                                row.get(
                                    "equal_exact_group_weighted_flagged_rate"
                                )
                                for row in selected
                            ],
                            config.percentile_interval_percent,
                        )
                    ),
                    "interpretation": (
                        "descriptive fixed-release family metric across seeds where "
                        "that family occurs; absence is retained, not imputed or "
                        "replaced"
                    ),
                }
    return result


def _prepare_output_directory(output_dir: Path) -> Path:
    output_dir = Path(output_dir).resolve()
    additional_results = (PROJECT_ROOT / "results_additional").resolve()
    try:
        output_dir.relative_to(additional_results)
    except ValueError as exc:
        raise SensitivityError(
            "output directory must be inside the separate results_additional/ tree; "
            "the immutable v1 results/ tree and source directories are forbidden"
        ) from exc
    if output_dir.exists() and any(output_dir.iterdir()):
        raise SensitivityError(
            f"stale/nonempty output directory is forbidden: {output_dir}"
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def _input_record(path: Path) -> dict[str, str]:
    path = Path(path).resolve()
    try:
        relative = path.relative_to(PROJECT_ROOT.resolve()).as_posix()
    except ValueError as exc:
        raise SensitivityError(f"input artifact is outside project: {path}") from exc
    if not path.is_file():
        raise SensitivityError(f"missing input artifact: {path}")
    return {"artifact_path": relative, "sha256": file_sha256(path)}


def verify_frozen_public_stage(
    manifest_path: Path = FROZEN_PUBLIC_MANIFEST_PATH,
) -> dict[str, Any]:
    """Verify the exact immutable v1 public-stage record before reuse."""

    manifest_path = Path(manifest_path).resolve()
    if manifest_path != FROZEN_PUBLIC_MANIFEST_PATH.resolve():
        raise SensitivityError("only the committed frozen public manifest is accepted")
    observed_manifest_hash = file_sha256(manifest_path)
    if observed_manifest_hash != FROZEN_PUBLIC_MANIFEST_SHA256:
        raise SensitivityError("frozen public-stage manifest SHA-256 mismatch")
    manifest = load_json_strict(manifest_path)
    if not isinstance(manifest, Mapping):
        raise SensitivityError("frozen public-stage manifest must be an object")
    if manifest.get("schema_version") != "public-rt-iot2022-2.0":
        raise SensitivityError("frozen public-stage schema mismatch")

    expected_sources = {
        "data/public/rt_iot2022/original/RT_IOT2022": EXPECTED_CSV_SHA256,
        "data/public/rt_iot2022/original/rt-iot2022.zip": EXPECTED_ARCHIVE_SHA256,
    }
    if manifest.get("source_files") != expected_sources:
        raise SensitivityError("frozen public-stage source binding differs")
    reproducibility = manifest.get("reproducibility_inputs")
    if not isinstance(reproducibility, Mapping):
        raise SensitivityError("frozen public-stage reproducibility binding is absent")
    expected_inputs = {
        "generator": BASE_GENERATOR_PATH,
        "immutable_config": BASE_DEFAULT_CONFIG,
        "requirements": REQUIREMENTS_PATH,
    }
    for label, path in expected_inputs.items():
        record = reproducibility.get(label)
        if not isinstance(record, Mapping):
            raise SensitivityError(f"frozen public-stage input missing: {label}")
        if record.get("artifact_path") != _display_path(path):
            raise SensitivityError(f"frozen public-stage path differs: {label}")
        if record.get("sha256") != file_sha256(path):
            raise SensitivityError(f"frozen public-stage input hash differs: {label}")

    generated = manifest.get("generated_files")
    if not isinstance(generated, Mapping):
        raise SensitivityError("frozen public-stage generated-files map is absent")
    expected_names = set(generated) | {"manifest.json"}
    observed_names = {
        path.name for path in manifest_path.parent.iterdir() if path.is_file()
    }
    if observed_names != expected_names:
        raise SensitivityError("frozen public-stage artifact file set differs")
    for name, expected_hash in generated.items():
        if Path(name).name != name:
            raise SensitivityError("unsafe path in frozen public-stage manifest")
        if file_sha256(manifest_path.parent / name) != expected_hash:
            raise SensitivityError(f"frozen public-stage artifact hash differs: {name}")
    return {
        "schema_version": manifest["schema_version"],
        "manifest": _input_record(manifest_path),
        "generated_file_count": len(generated),
        "generated_file_map_sha256": canonical_json_sha256(generated),
        "generator_sha256": reproducibility["generator"]["sha256"],
        "config_sha256": reproducibility["immutable_config"]["sha256"],
    }


def _input_provenance(
    config_path: Path,
    config: SensitivityConfig,
    base_config_path: Path,
    base_config: PublicExperimentConfig,
    protocol_path: Path,
    archive_path: Path,
    csv_path: Path,
    frozen_public_binding: Mapping[str, Any],
) -> dict[str, Any]:
    source = {
        "official_dataset_page": "https://archive.ics.uci.edu/dataset/942/rt-iot2022",
        "official_download_url": (
            "https://archive.ics.uci.edu/static/public/942/rt-iot2022.zip"
        ),
        "license": "CC BY 4.0",
        "doi": "10.24432/C5P338",
        "archive": _input_record(archive_path),
        "extracted_table": _input_record(csv_path),
    }
    if source["archive"]["sha256"] != EXPECTED_ARCHIVE_SHA256:
        raise SensitivityError("official RT-IoT2022 archive SHA-256 mismatch")
    if source["extracted_table"]["sha256"] != EXPECTED_CSV_SHA256:
        raise SensitivityError("official RT-IoT2022 table SHA-256 mismatch")
    inputs = {
        "sensitivity_generator": _input_record(GENERATOR_PATH),
        "frozen_public_generator_reused": _input_record(BASE_GENERATOR_PATH),
        "sensitivity_config": _input_record(config_path),
        "frozen_public_config": _input_record(base_config_path),
        "frozen_public_result_manifest": _input_record(
            FROZEN_PUBLIC_MANIFEST_PATH
        ),
        "frozen_protocol": _input_record(protocol_path),
        "official_downloader": _input_record(DOWNLOADER_PATH),
        "dataset_provenance_record": _input_record(DATA_PROVENANCE_PATH),
        "requirements": _input_record(REQUIREMENTS_PATH),
    }
    if inputs["frozen_protocol"]["sha256"] != config.protocol_sha256:
        raise SensitivityError("frozen protocol SHA-256 mismatch")
    return {
        "source_files": source,
        "input_files": inputs,
        "frozen_public_stage_binding": dict(frozen_public_binding),
        "effective_sensitivity_config_sha256": canonical_json_sha256(asdict(config)),
        "effective_base_public_config_sha256": canonical_json_sha256(
            asdict(base_config)
        ),
        "runtime": runtime_record(),
        "determinism_scope": (
            "Deterministic on the same bound source, configuration, host, and "
            "software stack with fixed model random states and one forest worker; "
            "byte identity across different numerical stacks or architectures is "
            "not claimed."
        ),
    }


def _assert_inputs_unchanged(provenance: Mapping[str, Any]) -> None:
    expected_input_paths = {
        "sensitivity_generator": "experiments/public_group_sensitivity.py",
        "frozen_public_generator_reused": "experiments/public_rt_iot2022.py",
        "sensitivity_config": "configs/public_group_sensitivity.json",
        "frozen_public_config": "configs/public_rt_iot2022.json",
        "frozen_public_result_manifest": "results/public_rt_iot2022/manifest.json",
        "frozen_protocol": "EXPERIMENTAL_PROTOCOL_FINAL.md",
        "official_downloader": "data/public/rt_iot2022/download.py",
        "dataset_provenance_record": "data/public/rt_iot2022/PROVENANCE.md",
        "requirements": "requirements.txt",
    }
    if set(provenance.get("input_files", {})) != set(expected_input_paths):
        raise SensitivityError("manifest input-file key set is incomplete")
    for section in ("input_files",):
        for label, record in provenance[section].items():
            if record.get("artifact_path") != expected_input_paths[label]:
                raise SensitivityError(f"unexpected bound path for input {label}")
            path = _project_path(str(record["artifact_path"]), label)
            if file_sha256(path) != record["sha256"]:
                raise SensitivityError(f"input changed during analysis: {label}")
    if (
        provenance["input_files"]["frozen_protocol"].get("sha256")
        != EXPECTED_PROTOCOL_SHA256
    ):
        raise SensitivityError("bound frozen protocol SHA-256 is not authoritative")
    if (
        provenance["input_files"]["sensitivity_config"].get("sha256")
        != EXPECTED_SENSITIVITY_CONFIG_SHA256
    ):
        raise SensitivityError("bound sensitivity config SHA-256 is not authoritative")
    expected_sources = {
        "archive": (
            "data/public/rt_iot2022/original/rt-iot2022.zip",
            EXPECTED_ARCHIVE_SHA256,
        ),
        "extracted_table": (
            "data/public/rt_iot2022/original/RT_IOT2022",
            EXPECTED_CSV_SHA256,
        ),
    }
    for label in ("archive", "extracted_table"):
        record = provenance["source_files"][label]
        expected_path, expected_sha256 = expected_sources[label]
        if (
            record.get("artifact_path") != expected_path
            or record.get("sha256") != expected_sha256
        ):
            raise SensitivityError(f"official source binding differs for {label}")
        path = _project_path(str(record["artifact_path"]), label)
        if file_sha256(path) != record["sha256"]:
            raise SensitivityError(f"source changed during analysis: {label}")
    observed_frozen_binding = verify_frozen_public_stage()
    if canonical_json_sha256(observed_frozen_binding) != canonical_json_sha256(
        provenance.get("frozen_public_stage_binding")
    ):
        raise SensitivityError("frozen public-stage binding changed during analysis")


def _verify_csv(path: Path, record: Mapping[str, Any]) -> None:
    raw_columns = record.get("columns")
    if not isinstance(raw_columns, list) or not all(
        isinstance(value, str) and value for value in raw_columns
    ):
        raise SensitivityError(f"invalid declared CSV schema for {path.name}")
    expected_columns = list(raw_columns)
    if len(expected_columns) != len(set(expected_columns)):
        raise SensitivityError(f"duplicate declared CSV column for {path.name}")
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != expected_columns:
            raise SensitivityError(f"CSV schema mismatch for {path.name}")
        count = 0
        for count, row in enumerate(reader, start=1):
            if None in row or set(row) != set(expected_columns):
                raise SensitivityError(f"malformed CSV row in {path.name}:{count + 1}")
            for column, value in row.items():
                if value.strip().lower() in {
                    "nan",
                    "+nan",
                    "-nan",
                    "inf",
                    "+inf",
                    "-inf",
                    "infinity",
                    "+infinity",
                    "-infinity",
                }:
                    raise SensitivityError(
                        f"non-finite CSV value in {path.name}:{count + 1}:{column}"
                    )
        if count != int(record["row_count"]):
            raise SensitivityError(f"CSV row count mismatch for {path.name}")


def verify_manifest(manifest_path: Path, *, require_success: bool = False) -> None:
    manifest_path = Path(manifest_path).resolve()
    manifest = load_json_strict(manifest_path)
    if not isinstance(manifest, Mapping):
        raise SensitivityError("manifest must be a JSON object")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise SensitivityError("manifest schema mismatch")
    generated = manifest.get("generated_files")
    if not isinstance(generated, Mapping):
        raise SensitivityError("manifest.generated_files must be an object")
    if set(generated) != EXPECTED_GENERATED_FILES:
        raise SensitivityError("manifest generated-file set differs from stage schema")
    expected_names = EXPECTED_GENERATED_FILES | {"manifest.json"}
    observed_names = {
        path.name for path in manifest_path.parent.iterdir() if path.is_file()
    }
    if observed_names != expected_names:
        raise SensitivityError(
            "output directory file set differs from manifest: "
            f"missing={sorted(expected_names - observed_names)}, "
            f"undeclared={sorted(observed_names - expected_names)}"
        )
    for name, record in generated.items():
        if Path(name).name != name:
            raise SensitivityError(f"unsafe generated filename: {name!r}")
        path = manifest_path.parent / name
        if file_sha256(path) != record.get("sha256"):
            raise SensitivityError(f"generated artifact hash mismatch: {name}")
        artifact_format = record.get("format")
        if artifact_format == "strict_json":
            load_json_strict(path)
        elif artifact_format == "strict_csv":
            _verify_csv(path, record)
        else:
            raise SensitivityError(f"unknown manifest format for {name}")
    provenance = manifest.get("provenance")
    if not isinstance(provenance, Mapping):
        raise SensitivityError("manifest provenance is missing")
    _assert_inputs_unchanged(provenance)
    summary = load_json_strict(manifest_path.parent / "summary.json")
    if not isinstance(summary, Mapping):
        raise SensitivityError("summary must be a JSON object")
    claimed_payload_hash = summary.get("result_payload_sha256")
    summary_without_hash = dict(summary)
    summary_without_hash.pop("result_payload_sha256", None)
    if canonical_json_sha256(summary_without_hash) != claimed_payload_hash:
        raise SensitivityError("summary result payload SHA-256 is invalid")
    if claimed_payload_hash != manifest.get("result_payload_sha256"):
        raise SensitivityError("manifest and summary result hashes differ")
    if summary.get("run_status") != manifest.get("run_status"):
        raise SensitivityError("manifest and summary run statuses differ")
    if require_success and manifest.get("run_status") != "complete":
        raise SensitivityError("completed public sensitivity study did not pass")
    if canonical_json_sha256(summary.get("provenance")) != canonical_json_sha256(
        provenance
    ):
        raise SensitivityError("manifest and summary provenance differ")

    family_counts = summary.get("source_validation", {}).get("family_counts", {})
    if not isinstance(family_counts, Mapping) or not family_counts:
        raise SensitivityError("summary family-count schema is absent")
    families = sorted(str(name) for name in family_counts)
    group_catalog_columns = (
        EXACT_GROUP_ID,
        EXACT_GROUP_TUPLE_SHA256,
        "first_source_row_position_zero_based",
        "row_count",
        "benign_rows",
        "attack_rows",
        "distinct_binary_labels",
        "distinct_families",
        *COMPACT_FEATURES,
        *(f"family_rows::{family}" for family in families),
    )
    dominant_columns = (
        "split_seed",
        EXACT_GROUP_ID,
        EXACT_GROUP_TUPLE_SHA256,
        "selection_rule",
        "test_rows",
        "test_exact_group_count",
        "dominant_group_rows",
        "dominant_group_test_row_share",
        "dominant_group_benign_rows",
        "dominant_group_attack_rows",
        "dominant_group_distinct_families",
        *(f"family_rows::{family}" for family in families),
    )
    expected_csv_schemas = {
        "group_catalog.csv": group_catalog_columns,
        "group_assignments.csv": GROUP_ASSIGNMENT_COLUMNS,
        "split_counts.csv": SPLIT_COUNT_COLUMNS,
        "seed_status.csv": SEED_STATUS_COLUMNS,
        "seed_metrics.csv": SEED_METRIC_COLUMNS,
        "family_metrics.csv": FAMILY_METRIC_COLUMNS,
        "calibration_rules.csv": CALIBRATION_COLUMNS,
        "projection_overlap_audit.csv": PROJECTION_OVERLAP_COLUMNS,
        "group_bootstrap_replicates.csv": GROUP_BOOTSTRAP_REPLICATE_COLUMNS,
        "group_bootstrap_intervals.csv": GROUP_BOOTSTRAP_INTERVAL_COLUMNS,
        "dominant_groups.csv": dominant_columns,
    }
    for name, columns in expected_csv_schemas.items():
        if generated[name].get("columns") != list(columns):
            raise SensitivityError(f"fixed CSV schema differs for {name}")

    split_execution = summary.get("split_execution", {})
    group_definition = summary.get("exact_group_definition", {})
    configured = int(split_execution.get("configured_seed_count", -1))
    executed = int(split_execution.get("executed_seed_count", -1))
    successful = int(split_execution.get("successful_seed_count", -1))
    groups = int(group_definition.get("distinct_exact_groups", -1))
    if configured != 30 or executed != configured or groups <= 0:
        raise SensitivityError("summary execution/group counts violate stage schema")
    expected_row_counts = {
        "group_catalog.csv": groups,
        "group_assignments.csv": configured * groups,
        "split_counts.csv": configured * len(SPLIT_NAMES) * (3 + len(families)),
        "seed_status.csv": configured,
        "seed_metrics.csv": successful
        * len(SUPPORTED_SELECTORS)
        * len(METRIC_VARIANTS),
        "family_metrics.csv": successful
        * len(SUPPORTED_SELECTORS)
        * len(METRIC_VARIANTS)
        * len(families),
        "calibration_rules.csv": successful * len(SUPPORTED_SELECTORS),
        "projection_overlap_audit.csv": configured * 5,
        "group_bootstrap_replicates.csv": successful
        * len(METRIC_VARIANTS)
        * 2000,
        "group_bootstrap_intervals.csv": successful
        * len(METRIC_VARIANTS)
        * len(SUPPORTED_SELECTORS)
        * len(GROUP_BOOTSTRAP_METRICS),
        "dominant_groups.csv": successful,
    }
    for name, expected_count in expected_row_counts.items():
        if int(generated[name].get("row_count", -1)) != expected_count:
            raise SensitivityError(f"declared row count violates stage schema: {name}")


GROUP_ASSIGNMENT_COLUMNS = (
    "split_seed",
    EXACT_GROUP_ID,
    EXACT_GROUP_TUPLE_SHA256,
    "split_bucket",
    ANALYSIS_SPLIT,
)
SPLIT_COUNT_COLUMNS = (
    "split_seed",
    "split",
    "category_type",
    "category",
    "row_count",
    "exact_group_count",
)
SEED_STATUS_COLUMNS = (
    "split_seed",
    "status",
    "failure_reason_count",
    "failure_reasons",
    "absent_test_family_count",
    "absent_test_families",
    "split_assignment_sha256",
    "train_rows",
    "calibration_rows",
    "test_rows",
    "train_exact_groups",
    "calibration_exact_groups",
    "test_exact_groups",
    "maximum_splits_per_exact_group",
    "maximum_splits_per_reference_input_tuple",
)
SEED_METRIC_COLUMNS = (
    "split_seed",
    "selector",
    "variant",
    "test_row_count",
    "test_exact_group_count",
    "dominant_group_removed_id",
    "tp",
    "fp",
    "tn",
    "fn",
    *SEED_METRIC_VALUE_COLUMNS[:8],
    *SEED_METRIC_VALUE_COLUMNS[8:11],
    "accuracy_group_count",
    "attack_group_count",
    "benign_group_count",
    *SEED_METRIC_VALUE_COLUMNS[11:],
    "attack_families_included",
    "benign_families_included",
    "attack_family_set_sha256",
    "benign_family_set_sha256",
    "present_family_macro_scope",
)
FAMILY_METRIC_COLUMNS = (
    "split_seed",
    "selector",
    "variant",
    "family",
    "family_kind",
    "row_count",
    "flagged_row_count",
    "flagged_row_rate_defined",
    "flagged_row_rate",
    "exact_group_count",
    "equal_exact_group_weighted_flagged_rate_defined",
    "equal_exact_group_weighted_flagged_rate",
    "interpretation",
)
CALIBRATION_COLUMNS = (
    "split_seed",
    "selector",
    "comparator",
    "decision_rule",
    "target_fpr",
    "threshold",
    "rate_threshold",
    "dispersion_threshold",
    "allowed_false_positives",
    "rate_false_positive_budget",
    "dispersion_false_positive_budget",
    "calibration_false_positives",
    "calibration_fpr",
    "calibration_recall",
    "benign_rows_tied_at_threshold",
    "all_rows_tied_at_threshold",
    "benign_rate_ties_at_threshold",
    "benign_dispersion_ties_at_threshold",
)
PROJECTION_OVERLAP_COLUMNS = (
    "split_seed",
    "projection",
    "projection_role",
    "columns_in_order",
    "exact_cross_split_separation_required",
    "train_distinct_tuple_count",
    "calibration_distinct_tuple_count",
    "test_distinct_tuple_count",
    "train_calibration_overlap_tuple_count",
    "train_test_overlap_tuple_count",
    "calibration_test_overlap_tuple_count",
    "crossing_any_partition_pair_tuple_count",
    "rows_in_crossing_tuples",
    "interpretation",
)
GROUP_BOOTSTRAP_REPLICATE_BASE_COLUMNS = (
    "split_seed",
    "variant",
    "replicate_index_zero_based",
    "derived_resample_seed_u64",
    "sampled_group_draw_count",
    "unique_sampled_group_count",
)
GROUP_BOOTSTRAP_REPLICATE_COLUMNS = (
    *GROUP_BOOTSTRAP_REPLICATE_BASE_COLUMNS,
    *(
        f"{selector}::{metric}::{suffix}"
        for selector in SUPPORTED_SELECTORS
        for metric in GROUP_BOOTSTRAP_METRICS
        for suffix in ("defined", "value")
    ),
)
GROUP_BOOTSTRAP_INTERVAL_COLUMNS = (
    "split_seed",
    "variant",
    "selector",
    "metric",
    "derived_resample_seed_u64",
    "exact_group_count",
    "included_family_count",
    "included_family_set_sha256",
    "minimum_family_exact_group_support",
    "macro_support_minimum_required",
    "point_estimate",
    "interval_available",
    "defined_replicate_count",
    "undefined_replicate_count",
    "configured_replicate_count",
    "lower",
    "upper",
    "lower_percent",
    "upper_percent",
    "percentile_method",
    "interval_values_policy",
    "unavailable_reason",
    "interpretation",
)


def _write_artifact_set(
    output_dir: Path,
    *,
    catalog: pd.DataFrame,
    assignment_rows: Sequence[Mapping[str, Any]],
    split_count_rows: Sequence[Mapping[str, Any]],
    seed_status_rows: Sequence[Mapping[str, Any]],
    metric_rows: Sequence[Mapping[str, Any]],
    family_rows: Sequence[Mapping[str, Any]],
    calibration_rows: Sequence[Mapping[str, Any]],
    projection_overlap_rows: Sequence[Mapping[str, Any]],
    group_bootstrap_rows: Sequence[Mapping[str, Any]],
    group_bootstrap_interval_rows: Sequence[Mapping[str, Any]],
    dominant_rows: Sequence[Mapping[str, Any]],
    model_metadata: Mapping[str, Any],
    summary: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    csv_payloads: list[tuple[str, Sequence[Mapping[str, Any]], Sequence[str]]] = [
        ("group_catalog.csv", catalog.to_dict(orient="records"), tuple(catalog.columns)),
        ("group_assignments.csv", assignment_rows, GROUP_ASSIGNMENT_COLUMNS),
        ("split_counts.csv", split_count_rows, SPLIT_COUNT_COLUMNS),
        ("seed_status.csv", seed_status_rows, SEED_STATUS_COLUMNS),
        ("seed_metrics.csv", metric_rows, SEED_METRIC_COLUMNS),
        ("family_metrics.csv", family_rows, FAMILY_METRIC_COLUMNS),
        ("calibration_rules.csv", calibration_rows, CALIBRATION_COLUMNS),
        (
            "projection_overlap_audit.csv",
            projection_overlap_rows,
            PROJECTION_OVERLAP_COLUMNS,
        ),
        (
            "group_bootstrap_replicates.csv",
            group_bootstrap_rows,
            GROUP_BOOTSTRAP_REPLICATE_COLUMNS,
        ),
        (
            "group_bootstrap_intervals.csv",
            group_bootstrap_interval_rows,
            GROUP_BOOTSTRAP_INTERVAL_COLUMNS,
        ),
        (
            "dominant_groups.csv",
            dominant_rows,
            tuple(dominant_rows[0].keys()) if dominant_rows else (
                "split_seed",
                EXACT_GROUP_ID,
                EXACT_GROUP_TUPLE_SHA256,
                "selection_rule",
                "test_rows",
                "test_exact_group_count",
                "dominant_group_rows",
                "dominant_group_test_row_share",
                "dominant_group_benign_rows",
                "dominant_group_attack_rows",
                "dominant_group_distinct_families",
                *(
                    column
                    for column in catalog.columns
                    if str(column).startswith("family_rows::")
                ),
            ),
        ),
    ]
    generated: dict[str, dict[str, Any]] = {}
    for name, rows, columns in csv_payloads:
        path = output_dir / name
        count = write_csv_strict(path, rows, columns)
        generated[name] = {
            "format": "strict_csv",
            "sha256": file_sha256(path),
            "row_count": count,
            "columns": list(columns),
        }
    for name, payload in (
        ("model_metadata.json", model_metadata),
        ("summary.json", summary),
    ):
        path = output_dir / name
        write_json_strict(path, payload)
        generated[name] = {
            "format": "strict_json",
            "sha256": file_sha256(path),
        }
    return generated


def run_public_group_sensitivity(
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    *,
    config_path: Path = DEFAULT_CONFIG,
    csv_path: Path = DEFAULT_CSV,
    archive_path: Path = DEFAULT_ARCHIVE,
    acknowledge_final_protocol_frozen: bool = False,
) -> dict[str, Any]:
    """Execute the complete 30-split stage after an explicit protocol freeze."""

    if not acknowledge_final_protocol_frozen:
        raise SensitivityError(
            "authoritative execution is blocked until the final protocol "
            "EXPERIMENTAL_PROTOCOL_FINAL.md "
            "is frozen; pass the explicit acknowledgement only after that freeze"
        )
    config_path = Path(config_path).resolve()
    if config_path != DEFAULT_CONFIG.resolve():
        raise SensitivityError(
            "authoritative execution requires the committed frozen config at "
            "configs/public_group_sensitivity.json"
        )
    if file_sha256(config_path) != EXPECTED_SENSITIVITY_CONFIG_SHA256:
        raise SensitivityError("authoritative sensitivity config SHA-256 mismatch")
    if Path(csv_path).resolve() != DEFAULT_CSV.resolve():
        raise SensitivityError("authoritative execution requires the official table path")
    if Path(archive_path).resolve() != DEFAULT_ARCHIVE.resolve():
        raise SensitivityError("authoritative execution requires the official archive path")
    if Path(output_dir).resolve() != DEFAULT_OUTPUT_DIR.resolve():
        raise SensitivityError(
            "authoritative execution requires results_additional/"
            "public_group_sensitivity as its exact output directory"
        )
    config = load_config(config_path)
    base_config_path = _project_path(
        config.base_public_config_path, "base_public_config_path"
    )
    protocol_path = _project_path(config.protocol_path, "protocol_path")
    if file_sha256(protocol_path) != config.protocol_sha256:
        raise SensitivityError("frozen protocol SHA-256 mismatch")
    base_config = load_base_config(base_config_path)
    base_config.validate()
    frozen_public_binding = verify_frozen_public_stage()
    output_dir = _prepare_output_directory(output_dir)

    provenance = _input_provenance(
        config_path,
        config,
        base_config_path,
        base_config,
        protocol_path,
        archive_path,
        csv_path,
        frozen_public_binding,
    )
    source_frame, source_audit = load_and_split(
        csv_path=csv_path,
        archive_path=archive_path,
        config=base_config,
        config_path=base_config_path,
    )
    grouped_frame, catalog, families = define_exact_groups(
        source_frame, config.exact_group_columns
    )

    assignment_rows: list[dict[str, Any]] = []
    split_count_rows: list[dict[str, Any]] = []
    seed_status_rows: list[dict[str, Any]] = []
    metric_rows: list[dict[str, Any]] = []
    family_rows: list[dict[str, Any]] = []
    calibration_rows: list[dict[str, Any]] = []
    projection_overlap_rows: list[dict[str, Any]] = []
    group_bootstrap_rows: list[dict[str, Any]] = []
    group_bootstrap_interval_rows: list[dict[str, Any]] = []
    dominant_rows: list[dict[str, Any]] = []
    per_seed_model_metadata: list[dict[str, Any]] = []

    for seed in config.group_split_seeds:
        assignment = assign_groups(catalog, seed, config)
        assignment_rows.extend(assignment.to_dict(orient="records"))
        split_frame = materialize_split(grouped_frame, assignment)
        projection_overlap_rows.extend(projection_overlap_audit(split_frame, seed))
        split_count_rows.extend(_split_count_rows(split_frame, seed, families))
        reasons = validate_split(split_frame, families)
        present_test_families = set(
            split_frame.loc[
                split_frame[ANALYSIS_SPLIT] == "test", "Attack_type"
            ].astype(str)
        )
        absent_test_families = [
            family for family in families if family not in present_test_families
        ]

        row_counts = {
            split: int((split_frame[ANALYSIS_SPLIT] == split).sum())
            for split in SPLIT_NAMES
        }
        group_counts = {
            split: int(
                split_frame.loc[
                    split_frame[ANALYSIS_SPLIT] == split, EXACT_GROUP_ID
                ].nunique()
            )
            for split in SPLIT_NAMES
        }
        exact_crossings = split_frame.groupby(EXACT_GROUP_ID, sort=False)[
            ANALYSIS_SPLIT
        ].nunique()
        reference_crossings = split_frame.groupby(
            list(REFERENCE_FEATURES), sort=False, dropna=False
        )[ANALYSIS_SPLIT].nunique()

        if not reasons:
            try:
                (
                    seed_metrics,
                    seed_families,
                    seed_calibration,
                    seed_group_bootstrap,
                    seed_group_bootstrap_intervals,
                    seed_models,
                    seed_dominant,
                ) = evaluate_seed(
                    split_frame,
                    catalog,
                    families,
                    seed,
                    base_config,
                    config,
                )
                metric_rows.extend(seed_metrics)
                family_rows.extend(seed_families)
                calibration_rows.extend(seed_calibration)
                group_bootstrap_rows.extend(seed_group_bootstrap)
                group_bootstrap_interval_rows.extend(
                    seed_group_bootstrap_intervals
                )
                per_seed_model_metadata.append(seed_models)
                dominant_rows.append(seed_dominant)
            except (ValueError, RuntimeError, FloatingPointError) as exc:
                reasons.append(
                    f"selector_execution_failure:{type(exc).__name__}:{exc}"
                )

        seed_status_rows.append(
            {
                "split_seed": seed,
                "status": "failed" if reasons else "complete",
                "failure_reason_count": len(reasons),
                "failure_reasons": " | ".join(reasons),
                "absent_test_family_count": len(absent_test_families),
                "absent_test_families": " | ".join(absent_test_families),
                "split_assignment_sha256": split_assignment_sha256(assignment),
                "train_rows": row_counts["train"],
                "calibration_rows": row_counts["calibration"],
                "test_rows": row_counts["test"],
                "train_exact_groups": group_counts["train"],
                "calibration_exact_groups": group_counts["calibration"],
                "test_exact_groups": group_counts["test"],
                "maximum_splits_per_exact_group": int(exact_crossings.max()),
                "maximum_splits_per_reference_input_tuple": int(
                    reference_crossings.max()
                ),
            }
        )

    failed_seeds = [
        int(row["split_seed"])
        for row in seed_status_rows
        if row["status"] == "failed"
    ]
    successful_seeds = [
        int(row["split_seed"])
        for row in seed_status_rows
        if row["status"] == "complete"
    ]
    run_status = "complete" if not failed_seeds else "failed"
    aggregate = aggregate_seed_metrics(metric_rows, config)
    per_family_aggregate = aggregate_family_metrics(family_rows, config)
    if failed_seeds:
        aggregate_output: dict[str, Any] = {
            "authoritative_aggregate_available": False,
            "reason": (
                "At least one configured split failed; successful-seed-only values "
                "below are partial diagnostics and are not an authoritative "
                "30-split result."
            ),
            "partial_successful_seed_diagnostics": aggregate,
        }
        per_family_output: dict[str, Any] = {
            "authoritative_aggregate_available": False,
            "reason": "at least one configured split failed",
            "partial_successful_seed_diagnostics": per_family_aggregate,
        }
    else:
        aggregate_output = {
            "authoritative_aggregate_available": True,
            **aggregate,
        }
        per_family_output = {
            "authoritative_aggregate_available": True,
            "by_selector_variant_and_family": per_family_aggregate,
        }
    model_metadata = {
        "schema_version": SCHEMA_VERSION,
        "claim_boundary": CLAIM_BOUNDARY,
        "fit_and_calibration_policy": {
            "learned_models_refit_for_every_group_split": list(
                LEARNED_MODEL_SELECTORS
            ),
            "hand_built_comparator_thresholds_recalibrated_for_every_group_split": list(
                CALIBRATED_HAND_BUILT_COMPARATORS
            ),
            "learned_model_thresholds_recalibrated_for_every_group_split": list(
                LEARNED_MODEL_SELECTORS
            ),
            "test_rows_used_for_fit_or_calibration": False,
            "forest_workers": 1,
            "model_random_states_fixed_across_group_splits": True,
        },
        "successful_split_seeds": successful_seeds,
        "failed_split_seeds": failed_seeds,
        "per_seed": per_seed_model_metadata,
    }
    summary_without_hash = {
        "schema_version": SCHEMA_VERSION,
        "run_status": run_status,
        "effective_config": asdict(config),
        "source_validation": {
            "source": source_audit["source"],
            "shape": source_audit["shape"],
            "rows_retained": source_audit["rows_retained"],
            "family_counts": source_audit["family_counts"],
            "normal_families_as_distributed": source_audit[
                "normal_families_as_distributed"
            ],
            "missing_value_count": source_audit["missing_value_count"],
            "nonfinite_numeric_count": source_audit["nonfinite_numeric_count"],
            "limitations": source_audit["limitations"],
            "verified_loader_reused": "experiments.public_rt_iot2022.load_and_split",
            "frozen_stage_split_ignored": True,
        },
        "exact_group_definition": {
            "columns_in_order": list(config.exact_group_columns),
            "equality_relation": (
                "collision-free pandas value-tuple equality; group IDs are the "
                "first bound source-row positions and SHA-256 is only an exported "
                "identity fingerprint, never the equality relation"
            ),
            "distinct_exact_groups": int(len(catalog)),
            "source_rows": int(len(grouped_frame)),
            "maximum_group_rows": int(catalog["row_count"].max()),
            "compact_features_subset_of_reference_features": bool(
                set(COMPACT_FEATURES).issubset(REFERENCE_FEATURES)
            ),
            "learned_model_selectors_with_exact_input_separation": list(
                LEARNED_MODEL_SELECTORS
            ),
            "calibrated_hand_built_comparators": list(
                CALIBRATED_HAND_BUILT_COMPARATORS
            ),
            "timing_projection_boundary": (
                "The rate-only, dispersion-only, and timing-OR comparators are "
                "deterministic hand-built rules whose thresholds are selected on "
                "calibration only. Their lower-dimensional scalar projections can "
                "repeat across partitions; those overlaps are retained in "
                "projection_overlap_audit.csv and are not described as learned-model "
                "input separation."
            ),
            "identity_nonclaim": (
                "Exact groups are not capture, device, session, source, time, or "
                "independent-sampling identities."
            ),
        },
        "split_execution": {
            "configured_seed_count": len(config.group_split_seeds),
            "configured_seeds": list(config.group_split_seeds),
            "executed_seed_count": len(seed_status_rows),
            "successful_seed_count": len(successful_seeds),
            "successful_seeds": successful_seeds,
            "failed_seed_count": len(failed_seeds),
            "failed_seeds": failed_seeds,
            "failed_splits_are_never_replaced": True,
            "rare_family_absence_policy": (
                "Retain zero partition counts and null/undefined per-family metrics; "
                "do not fail, drop, or replace the configured seed."
            ),
            "seeds_with_absent_test_families": {
                str(row["split_seed"]): row["absent_test_families"].split(" | ")
                for row in seed_status_rows
                if row["absent_test_family_count"]
            },
            "atomic_exact_group_assignment": True,
            "all_assignment_and_count_rows_retained": True,
        },
        "descriptive_split_sensitivity": aggregate_output,
        "descriptive_per_family_split_sensitivity": per_family_output,
        "within_release_exact_group_bootstrap": {
            "scope": (
                "Within each successful fixed split and metric variant, sample the "
                "variant's exact compact-input groups IID with replacement, drawing "
                "the original number of groups and retaining all rows with each "
                "sampled group's multiplicity."
            ),
            "variants": list(METRIC_VARIANTS),
            "metrics": list(GROUP_BOOTSTRAP_METRICS),
            "method": config.group_bootstrap_method,
            "replicate_count_per_split_and_variant": (
                config.group_bootstrap_replicates
            ),
            "base_seed": config.group_bootstrap_seed,
            "random_bit_generator": "numpy.random.PCG64",
            "derived_seed_method": (
                "first unsigned 64 bits of SHA-256 over a fixed namespace, the "
                "uint64 base seed, uint64 split seed, and ASCII metric variant"
            ),
            "shared_group_multiplicities_across_all_selectors": True,
            "percentile_interval_percent": list(
                config.percentile_interval_percent
            ),
            "percentile_method": "numpy linear",
            "present_family_macro_minimum_exact_groups_per_included_family": (
                config.group_bootstrap_macro_min_groups_per_family
            ),
            "undefined_replicate_policy": (
                "Every replicate is retained with a defined flag. Percentiles use "
                "defined finite replicates. A present-family macro interval is "
                "unavailable unless every included source-variant family has the "
                "frozen minimum exact-group support."
            ),
            "interval_nonclaim": (
                "These are within-release exact-group-resampling sensitivity "
                "intervals, not confidence intervals for captures, devices, "
                "sessions, time periods, deployments, or populations."
            ),
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "inferential_statistics": NO_INFERENCE_STATEMENT,
        "artifact_scope": {
            "default_output_directory": "results_additional/public_group_sensitivity",
            "immutable_v1_results_modified": False,
            "row_predictions_retained": False,
            "reason_row_predictions_not_retained": (
                "All exact-group definitions, group catalogs, atomic assignments, "
                "partition counts, calibration rules, model metadata, and aggregate "
                "metrics are retained; duplicating 30 full row-prediction tables is "
                "outside this bounded sensitivity stage."
            ),
            "generated_artifacts": [
                "group_catalog.csv",
                "group_assignments.csv",
                "split_counts.csv",
                "seed_status.csv",
                "seed_metrics.csv",
                "family_metrics.csv",
                "calibration_rules.csv",
                "projection_overlap_audit.csv",
                "group_bootstrap_replicates.csv",
                "group_bootstrap_intervals.csv",
                "dominant_groups.csv",
                "model_metadata.json",
                "summary.json",
                "manifest.json",
            ],
        },
        "provenance": provenance,
    }
    summary = {
        **summary_without_hash,
        "result_payload_sha256": canonical_json_sha256(summary_without_hash),
    }
    generated = _write_artifact_set(
        output_dir,
        catalog=catalog,
        assignment_rows=assignment_rows,
        split_count_rows=split_count_rows,
        seed_status_rows=seed_status_rows,
        metric_rows=metric_rows,
        family_rows=family_rows,
        calibration_rows=calibration_rows,
        projection_overlap_rows=projection_overlap_rows,
        group_bootstrap_rows=group_bootstrap_rows,
        group_bootstrap_interval_rows=group_bootstrap_interval_rows,
        dominant_rows=dominant_rows,
        model_metadata=model_metadata,
        summary=summary,
    )
    _assert_inputs_unchanged(provenance)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "run_status": run_status,
        "result_payload_sha256": summary["result_payload_sha256"],
        "provenance": provenance,
        "generated_files": generated,
        "manifest_scope": (
            "Every regular file in this stage directory except manifest.json "
            "itself, whose inclusion would be self-referential. Undeclared files "
            "are forbidden."
        ),
        "claim_boundary": CLAIM_BOUNDARY,
    }
    manifest_path = output_dir / "manifest.json"
    write_json_strict(manifest_path, manifest)
    verify_manifest(manifest_path)
    if failed_seeds:
        raise SensitivityError(
            "one or more configured splits failed closed; inspect seed_status.csv: "
            f"{failed_seeds}"
        )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument(
        "--acknowledge-final-protocol-frozen",
        action="store_true",
        help=(
            "required acknowledgement that EXPERIMENTAL_PROTOCOL_FINAL.md was "
            "frozen before this authoritative 30-split execution"
        ),
    )
    parser.add_argument(
        "--verify-completed",
        action="store_true",
        help=(
            "read-only verification of the completed output tree; no split, "
            "fit, bootstrap, or output write is performed"
        ),
    )
    args = parser.parse_args()
    try:
        if args.verify_completed:
            if args.acknowledge_final_protocol_frozen:
                raise SensitivityError(
                    "--verify-completed cannot be combined with the execution acknowledgement"
                )
            verify_manifest(
                Path(args.output_dir) / "manifest.json", require_success=True
            )
            print("verification_status=passed")
            print(f"manifest={Path(args.output_dir) / 'manifest.json'}")
            return 0
        summary = run_public_group_sensitivity(
            args.output_dir,
            config_path=args.config,
            csv_path=args.csv,
            archive_path=args.archive,
            acknowledge_final_protocol_frozen=args.acknowledge_final_protocol_frozen,
        )
    except (SensitivityError, OSError) as exc:
        print(f"ERROR: {exc}")
        return 1
    print(f"run_status={summary['run_status']}")
    print(f"result_payload_sha256={summary['result_payload_sha256']}")
    print(f"summary={Path(args.output_dir) / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
