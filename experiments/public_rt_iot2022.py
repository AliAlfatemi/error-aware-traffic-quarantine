#!/usr/bin/env python3
"""Leakage-audited RT-IoT2022 flow-feature analysis.

The official UCI artifact contains completed-flow aggregates rather than raw
packet timestamps.  This program therefore evaluates flow-row selectors.  It
does not evaluate the manuscript's exact online IAT window, packet maturation,
packet redirection, kernel execution, or capture-to-capture generalization.

All source rows are retained.  Exact learned-model inputs are assigned to one
global hash-bucket partition before fitting or calibration, including inputs
whose distributed labels conflict.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import math
import platform
import sys
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any, Iterable, Mapping

import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = Path(__file__).resolve()
REQUIREMENTS_PATH = PROJECT_ROOT / "requirements.txt"
DEFAULT_CONFIG = PROJECT_ROOT / "configs" / "public_rt_iot2022.json"
DEFAULT_CSV = (
    PROJECT_ROOT / "data" / "public" / "rt_iot2022" / "original" / "RT_IOT2022"
)
DEFAULT_ARCHIVE = DEFAULT_CSV.with_name("rt-iot2022.zip")
EXPECTED_ARCHIVE_SHA256 = (
    "bcaa24d62abbb1215be576d5cf9c02dfcb0bb7c4c2f5a00e03055afaa1ed109e"
)
EXPECTED_CSV_SHA256 = (
    "956956c09c1764584fa08acd0f6876475626bcedcd6a6b1f8c492c2e9a2089ea"
)

SOURCE_INDEX_COLUMN = "Unnamed: 0"
EXPORTED_INDEX_COLUMN = "class_local_row_id"
NORMAL_FAMILIES = ("MQTT_Publish", "Thing_Speak", "Wipro_bulb")

# Only these two fields enter the hand-built timing comparators.  In
# particular, flow_iat.avg is not used by the rate-only, dispersion-only, or
# OR rule; it is used by the learned models below.
TIMING_COLUMNS = ("flow_pkts_per_sec", "flow_iat.std")
COMPACT_FEATURES = (
    "flow_pkts_per_sec",
    "flow_iat.avg",
    "flow_iat.std",
    "flow_pkts_payload.avg",
    "flow_SYN_flag_count",
)
REFERENCE_FEATURES = (
    "flow_duration",
    "fwd_pkts_tot",
    "bwd_pkts_tot",
    "flow_pkts_per_sec",
    "down_up_ratio",
    "flow_SYN_flag_count",
    "flow_ACK_flag_count",
    "flow_pkts_payload.avg",
    "flow_pkts_payload.std",
    "flow_iat.avg",
    "flow_iat.std",
    "idle.avg",
)
if not set(COMPACT_FEATURES).issubset(REFERENCE_FEATURES):
    raise AssertionError("compact learned inputs must be covered by reference inputs")

SPLIT_NAMES = ("train", "calibration", "test")
STRICT_COMPARATOR = "score_strictly_greater_than_threshold"


@dataclass(frozen=True)
class PublicExperimentConfig:
    schema_version: str = "public-rt-iot2022-2.0"
    train_bucket_end: int = 60
    calibration_bucket_end: int = 80
    split_modulus: int = 100
    calibration_target_fpr: float = 0.01
    logistic_random_state: int = 1701
    logistic_max_iter: int = 1000
    forest_random_state: int = 1702
    forest_estimators: int = 160
    forest_max_depth: int = 12
    forest_min_samples_leaf: int = 4

    def validate(self) -> None:
        if self.schema_version != "public-rt-iot2022-2.0":
            raise ValueError(f"unsupported config schema {self.schema_version!r}")
        if not (
            0 < self.train_bucket_end < self.calibration_bucket_end < self.split_modulus
        ):
            raise ValueError("split bucket boundaries must be strictly increasing")
        if not 0.0 <= self.calibration_target_fpr < 1.0:
            raise ValueError("calibration_target_fpr must be in [0, 1)")
        for name in (
            "split_modulus",
            "logistic_max_iter",
            "forest_estimators",
            "forest_max_depth",
            "forest_min_samples_leaf",
        ):
            if int(getattr(self, name)) <= 0:
                raise ValueError(f"{name} must be positive")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_sha256(payload: Any) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def write_json(path: Path, payload: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def load_config(path: Path = DEFAULT_CONFIG) -> PublicExperimentConfig:
    path = Path(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("public experiment config must be a JSON object")
    expected = {item.name for item in fields(PublicExperimentConfig)}
    observed = set(payload)
    if observed != expected:
        raise ValueError(
            "config fields differ: "
            f"missing={sorted(expected - observed)}, unknown={sorted(observed - expected)}"
        )
    config = PublicExperimentConfig(**payload)
    config.validate()
    return config


def _resolve_config(
    config: PublicExperimentConfig | None, config_path: Path
) -> tuple[PublicExperimentConfig, dict[str, Any]]:
    """Return the effective config and its immutable-input binding."""

    config_path = Path(config_path).resolve()
    from_file = load_config(config_path)
    effective = from_file if config is None else config
    effective.validate()
    if asdict(effective) != asdict(from_file):
        raise ValueError(
            "in-memory config differs from immutable config_path; write a separate "
            "config file and pass that path"
        )
    return effective, {
        "artifact_path": _display_path(config_path),
        "sha256": file_sha256(config_path),
        "effective_config_sha256": canonical_sha256(asdict(effective)),
    }


def _display_path(path: Path) -> str:
    path = Path(path).resolve()
    try:
        return path.relative_to(PROJECT_ROOT.resolve()).as_posix()
    except ValueError:
        return path.name


def runtime_record() -> dict[str, Any]:
    return {
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "numpy": np.__version__,
        "pandas": pd.__version__,
        "scipy": importlib.metadata.version("scipy"),
        "scikit_learn": sklearn.__version__,
        "matplotlib": importlib.metadata.version("matplotlib"),
    }


def reproducibility_inputs(config_path: Path = DEFAULT_CONFIG) -> dict[str, Any]:
    config_path = Path(config_path).resolve()
    return {
        "generator": {
            "artifact_path": _display_path(GENERATOR_PATH),
            "sha256": file_sha256(GENERATOR_PATH),
        },
        "immutable_config": {
            "artifact_path": _display_path(config_path),
            "sha256": file_sha256(config_path),
        },
        "requirements": {
            "artifact_path": _display_path(REQUIREMENTS_PATH),
            "sha256": file_sha256(REQUIREMENTS_PATH),
        },
        "runtime": runtime_record(),
        "determinism_scope": (
            "Deterministic on the same host and bound software stack with one "
            "forest worker; byte-identical behavior across different numerical "
            "libraries, architectures, or hosts is not claimed."
        ),
    }


def wilson_interval(
    successes: int, total: int, z: float = 1.959963984540054
) -> list[float]:
    """Descriptive row-level Wilson interval; no independence claim is implied."""

    if total <= 0:
        return [0.0, 0.0]
    probability = successes / total
    denominator = 1.0 + z * z / total
    center = (probability + z * z / (2.0 * total)) / denominator
    half = (
        z
        * math.sqrt(
            probability * (1.0 - probability) / total
            + z * z / (4.0 * total * total)
        )
        / denominator
    )
    return [max(0.0, center - half), min(1.0, center + half)]


def _safe_div(numerator: float, denominator: float) -> float:
    return float(numerator / denominator) if denominator else 0.0


def _weighted_rate(mask: np.ndarray, weights: np.ndarray) -> float:
    return _safe_div(float(weights[mask].sum()), float(weights.sum()))


def _row_hash(frame: pd.DataFrame, columns: Iterable[str]) -> pd.Series:
    """Version-bound deterministic uint64 row signature."""

    return pd.util.hash_pandas_object(frame[list(columns)], index=False).astype("uint64")


def _pairwise_overlap(group_sets: Mapping[str, set[int]]) -> dict[str, int]:
    return {
        "train_calibration": len(group_sets["train"] & group_sets["calibration"]),
        "train_test": len(group_sets["train"] & group_sets["test"]),
        "calibration_test": len(
            group_sets["calibration"] & group_sets["test"]
        ),
    }


def _signature_overlap_audit(frame: pd.DataFrame, hash_column: str) -> dict[str, Any]:
    sets = {
        split: set(
            int(value)
            for value in frame.loc[frame["split"] == split, hash_column].tolist()
        )
        for split in SPLIT_NAMES
    }
    return {
        "distinct_signatures_per_split": {
            split: len(values) for split, values in sets.items()
        },
        "cross_split_overlap_counts": _pairwise_overlap(sets),
    }


def _conflict_audit(frame: pd.DataFrame, hash_column: str) -> dict[str, Any]:
    grouped = (
        frame.groupby(hash_column, sort=False)
        .agg(
            rows=(hash_column, "size"),
            distinct_families=("Attack_type", "nunique"),
            distinct_binary_labels=("true_label", "nunique"),
        )
    )
    family_conflict = grouped["distinct_families"] > 1
    binary_conflict = grouped["distinct_binary_labels"] > 1
    return {
        "group_count": int(len(grouped)),
        "duplicate_rows_after_first_within_exact_input": int(
            len(frame) - len(grouped)
        ),
        "family_label_conflicts": {
            "group_count": int(family_conflict.sum()),
            "rows_in_conflicting_groups": int(
                grouped.loc[family_conflict, "rows"].sum()
            ),
        },
        "binary_label_conflicts": {
            "group_count": int(binary_conflict.sum()),
            "rows_in_conflicting_groups": int(
                grouped.loc[binary_conflict, "rows"].sum()
            ),
        },
        "retention_policy": "all rows, including every conflicting-label row, are retained",
    }


def _split_assignment_sha256(frame: pd.DataFrame) -> str:
    codes = frame["split"].map({"train": 0, "calibration": 1, "test": 2})
    payload = np.column_stack(
        [
            frame["global_learned_input_group_hash_u64"].to_numpy(dtype=np.uint64),
            codes.to_numpy(dtype=np.uint64),
        ]
    )
    return hashlib.sha256(payload.astype("<u8", copy=False).tobytes()).hexdigest()


def load_and_split(
    csv_path: Path = DEFAULT_CSV,
    archive_path: Path = DEFAULT_ARCHIVE,
    config: PublicExperimentConfig | None = None,
    config_path: Path = DEFAULT_CONFIG,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Validate the immutable source and assign globally input-safe splits."""

    if config is None:
        config = load_config(config_path)
    config.validate()
    csv_path = Path(csv_path)
    archive_path = Path(archive_path)
    if file_sha256(archive_path) != EXPECTED_ARCHIVE_SHA256:
        raise ValueError("RT-IoT2022 archive SHA-256 mismatch")
    if file_sha256(csv_path) != EXPECTED_CSV_SHA256:
        raise ValueError("RT-IoT2022 CSV SHA-256 mismatch")

    frame = pd.read_csv(csv_path)
    if frame.shape != (123117, 85):
        raise ValueError(f"unexpected RT-IoT2022 shape {frame.shape}")
    required = {
        SOURCE_INDEX_COLUMN,
        "Attack_type",
        *TIMING_COLUMNS,
        *COMPACT_FEATURES,
        *REFERENCE_FEATURES,
        "fwd_pkts_payload.tot",
        "bwd_pkts_payload.tot",
    }
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError(f"missing RT-IoT2022 columns: {missing}")
    if int(frame.isna().sum().sum()) != 0:
        raise ValueError("RT-IoT2022 unexpectedly contains missing values")
    numeric = frame.select_dtypes(include=[np.number]).to_numpy(dtype=float)
    if not np.isfinite(numeric).all():
        raise ValueError("RT-IoT2022 unexpectedly contains non-finite values")

    frame = frame.rename(columns={SOURCE_INDEX_COLUMN: EXPORTED_INDEX_COLUMN}).copy()
    source_feature_columns = [
        column
        for column in frame.columns
        if column not in {EXPORTED_INDEX_COLUMN, "Attack_type"}
    ]
    frame["source_file_row_position_zero_based"] = np.arange(
        len(frame), dtype=np.int64
    )
    frame["true_label"] = (
        ~frame["Attack_type"].isin(NORMAL_FAMILIES)
    ).astype(int)

    frame["full_feature_hash_u64"] = _row_hash(
        frame, source_feature_columns
    )
    frame["reference_input_hash_u64"] = _row_hash(frame, REFERENCE_FEATURES)
    frame["compact_input_hash_u64"] = _row_hash(frame, COMPACT_FEATURES)

    # The global grouping relation is equality under *either* learned input.
    # COMPACT_FEATURES is a strict subset of REFERENCE_FEATURES, so equality of
    # the compact tuple is the coarser equivalence relation and exactly defines
    # the connected components.  This keeps identical 5-feature and 12-feature
    # inputs in one partition.  Hash collisions would only merge groups and are
    # therefore conservative for leakage prevention.
    frame["global_learned_input_group_hash_u64"] = frame[
        "compact_input_hash_u64"
    ]
    buckets = (
        frame["global_learned_input_group_hash_u64"] % config.split_modulus
    ).astype(int)
    frame["split"] = np.where(
        buckets < config.train_bucket_end,
        "train",
        np.where(
            buckets < config.calibration_bucket_end, "calibration", "test"
        ),
    )
    frame["packet_weight"] = (
        frame["fwd_pkts_tot"].astype(float)
        + frame["bwd_pkts_tot"].astype(float)
    )
    frame["payload_byte_weight"] = (
        frame["fwd_pkts_payload.tot"].astype(float)
        + frame["bwd_pkts_payload.tot"].astype(float)
    )

    overlap_audits = {
        "compact_5_feature_learned_input": _signature_overlap_audit(
            frame, "compact_input_hash_u64"
        ),
        "reference_12_feature_learned_input": _signature_overlap_audit(
            frame, "reference_input_hash_u64"
        ),
    }
    for name, record in overlap_audits.items():
        if any(record["cross_split_overlap_counts"].values()):
            raise AssertionError(f"learned-input split leakage for {name}: {record}")

    split_counts = {
        split: int((frame["split"] == split).sum()) for split in SPLIT_NAMES
    }
    split_label_counts = {
        split: {
            "benign": int(
                ((frame["split"] == split) & (frame["true_label"] == 0)).sum()
            ),
            "attack": int(
                ((frame["split"] == split) & (frame["true_label"] == 1)).sum()
            ),
        }
        for split in SPLIT_NAMES
    }
    family_counts = {
        str(family): int(count)
        for family, count in frame["Attack_type"].value_counts().sort_index().items()
    }
    split_family_counts = {
        split: {
            str(family): int(count)
            for family, count in frame.loc[
                frame["split"] == split, "Attack_type"
            ]
            .value_counts()
            .sort_index()
            .items()
        }
        for split in SPLIT_NAMES
    }

    global_group_sizes = frame.groupby(
        "global_learned_input_group_hash_u64", sort=False
    ).size()
    largest_groups_overall: list[dict[str, Any]] = []
    for group_hash, group_rows in global_group_sizes.nlargest(10).items():
        group_frame = frame[
            frame["global_learned_input_group_hash_u64"] == group_hash
        ]
        split = str(group_frame["split"].iloc[0])
        largest_groups_overall.append(
            {
                "group_hash_u64_as_string": str(int(group_hash)),
                "rows": int(group_rows),
                "split": split,
                "fraction_of_assigned_split_rows": float(
                    group_rows / split_counts[split]
                ),
                "family_counts": {
                    str(family): int(count)
                    for family, count in group_frame["Attack_type"]
                    .value_counts()
                    .sort_index()
                    .items()
                },
                "benign_rows": int((group_frame["true_label"] == 0).sum()),
                "attack_rows": int((group_frame["true_label"] == 1).sum()),
            }
        )
    largest_group_by_split: dict[str, Any] = {}
    for split in SPLIT_NAMES:
        split_hashes = frame.loc[
            frame["split"] == split, "global_learned_input_group_hash_u64"
        ]
        sizes = split_hashes.value_counts()
        largest_hash = int(sizes.index[0])
        largest_rows = int(sizes.iloc[0])
        largest_group_by_split[split] = {
            "group_hash_u64_as_string": str(largest_hash),
            "rows": largest_rows,
            "fraction_of_split_rows": float(largest_rows / split_counts[split]),
            "exceeds_10_percent_of_split_rows": bool(
                largest_rows / split_counts[split] > 0.10
            ),
        }

    zero_dispersion = frame["flow_iat.std"].eq(0.0)
    zero_packet_counts = frame.loc[zero_dispersion, "packet_weight"]
    dispersion_degeneracy = {
        "zero_flow_iat_std_rows": int(zero_dispersion.sum()),
        "zero_flow_iat_std_fraction": float(zero_dispersion.mean()),
        "zero_std_rows_by_total_packets": {
            str(int(packet_count)): int(count)
            for packet_count, count in zero_packet_counts.value_counts()
            .sort_index()
            .items()
        },
        "all_zero_std_rows_have_one_or_two_total_packets": bool(
            zero_packet_counts.between(1, 2).all()
        ),
        "nonzero_std_rows_with_at_most_two_total_packets": int(
            ((~zero_dispersion) & (frame["packet_weight"] <= 2)).sum()
        ),
        "interpretation": (
            "flow_iat.std is structurally zero for every one- or two-packet "
            "flow row, so the dispersion comparator is largely a flow-length "
            "degeneracy check rather than evidence for a mature online IAT window"
        ),
    }

    conflicts = {
        "full_83_minus_index_and_label_feature_vector": _conflict_audit(
            frame, "full_feature_hash_u64"
        ),
        "reference_12_feature_learned_input": _conflict_audit(
            frame, "reference_input_hash_u64"
        ),
        "compact_5_feature_learned_input": _conflict_audit(
            frame, "compact_input_hash_u64"
        ),
    }

    audit = {
        "source": {
            "official_url": "https://archive.ics.uci.edu/dataset/942/rt-iot2022",
            "download_url": "https://archive.ics.uci.edu/static/public/942/rt-iot2022.zip",
            "license": "CC BY 4.0",
            "doi": "10.24432/C5P338",
            "archive_sha256": EXPECTED_ARCHIVE_SHA256,
            "csv_sha256": EXPECTED_CSV_SHA256,
        },
        "shape": {"rows": len(frame), "source_columns": 85},
        "rows_retained": len(frame),
        "renamed_source_index": {
            "distributed_header": SOURCE_INDEX_COLUMN,
            "analysis_name": EXPORTED_INDEX_COLUMN,
            "interpretation": "class-local row identifier; not a capture or time identifier",
        },
        "normal_families_as_distributed": list(NORMAL_FAMILIES),
        "attack_family_count": int(
            frame.loc[frame["true_label"] == 1, "Attack_type"].nunique()
        ),
        "family_counts": family_counts,
        "split_family_counts": split_family_counts,
        "split_distinct_family_counts": {
            split: len(counts) for split, counts in split_family_counts.items()
        },
        "conflicting_label_audits": conflicts,
        "global_grouping": {
            "policy": (
                "connected grouping under equality of any evaluated learned-model "
                "input; compact equality defines the components because the compact "
                "features are a subset of the reference features"
            ),
            "implementation": (
                "pandas.util.hash_pandas_object uint64 over the five compact fields; "
                "version is bound in the manifest"
            ),
            "split_rule": (
                f"global group hash mod {config.split_modulus}: "
                f"0-{config.train_bucket_end - 1} train, "
                f"{config.train_bucket_end}-{config.calibration_bucket_end - 1} "
                f"calibration, {config.calibration_bucket_end}-"
                f"{config.split_modulus - 1} test"
            ),
            "distinct_global_groups": int(
                frame["global_learned_input_group_hash_u64"].nunique()
            ),
            "maximum_global_group_rows": int(global_group_sizes.max()),
            "largest_group_by_split": largest_group_by_split,
            "ten_largest_groups_overall": largest_groups_overall,
            "concentration_warning": (
                "large repeated compact-input groups dominate realized row counts "
                "in every partition; group-safe hash buckets are not row-balanced"
            ),
            "split_assignment_sha256": _split_assignment_sha256(frame),
        },
        "learned_input_overlap_audits": overlap_audits,
        "split_counts": split_counts,
        "split_label_counts": split_label_counts,
        "dispersion_feature_degeneracy": dispersion_degeneracy,
        "missing_value_count": 0,
        "nonfinite_numeric_count": 0,
        "limitations": [
            "completed-flow aggregates only; no packet timestamps or exact online IAT windows",
            "no capture, device, or session grouping identifier is distributed in the CSV",
            "hash grouping prevents identical learned-input leakage but not same-environment dependence",
            "source rows are contiguous class blocks; no temporal or capture independence is claimed",
            "the data are highly class-imbalanced and include conflicting labels for identical inputs",
            "IAT fields are CICFlowMeter-style microsecond-scale aggregates",
        ],
    }
    return frame, audit


def _threshold_for_false_positives(
    negative_scores: np.ndarray, allowed_false_positives: int
) -> float:
    """Finite boundary used with a strict `score > threshold` comparator."""

    ordered = np.sort(np.asarray(negative_scores, dtype=float))[::-1]
    if not len(ordered):
        raise ValueError("calibration has no benign scores")
    if not np.isfinite(ordered).all():
        raise ValueError("calibration scores must be finite")
    if allowed_false_positives < 0 or allowed_false_positives >= len(ordered):
        raise ValueError("allowed false positives must be in [0, benign_count)")
    # With a strict comparator, the boundary at rank `allowed` admits at most
    # `allowed` larger scores.  All ties at the boundary are conservatively
    # excluded.  No nextafter/subnormal sentinel is required.
    return float(ordered[allowed_false_positives])


def apply_score_rule(scores: np.ndarray, rule: Mapping[str, Any]) -> np.ndarray:
    if rule.get("comparator") != STRICT_COMPARATOR:
        raise ValueError(f"unsupported score comparator {rule.get('comparator')!r}")
    return np.asarray(scores, dtype=float) > float(rule["threshold"])


def calibrate_score_threshold(
    scores: np.ndarray, labels: np.ndarray, target_fpr: float
) -> dict[str, Any]:
    labels = np.asarray(labels, dtype=int)
    scores = np.asarray(scores, dtype=float)
    if not 0.0 <= target_fpr < 1.0:
        raise ValueError("target_fpr must be in [0, 1)")
    benign_scores = scores[labels == 0]
    allowed = int(math.floor(target_fpr * len(benign_scores) + 1e-12))
    threshold = _threshold_for_false_positives(benign_scores, allowed)
    rule: dict[str, Any] = {
        "threshold": threshold,
        "comparator": STRICT_COMPARATOR,
        "decision_rule": "score > threshold (ties are not flagged)",
        "target_fpr": target_fpr,
        "allowed_false_positives": allowed,
    }
    prediction = apply_score_rule(scores, rule)
    fp = int(((labels == 0) & prediction).sum())
    tp = int(((labels == 1) & prediction).sum())
    rule.update(
        {
            "calibration_false_positives": fp,
            "calibration_fpr": _safe_div(fp, int((labels == 0).sum())),
            "calibration_recall": _safe_div(tp, int((labels == 1).sum())),
            "benign_rows_tied_at_threshold": int(
                (benign_scores == threshold).sum()
            ),
            "all_rows_tied_at_threshold": int((scores == threshold).sum()),
        }
    )
    return rule


def apply_or_rule(
    rate_scores: np.ndarray,
    dispersion_scores: np.ndarray,
    rule: Mapping[str, Any],
) -> np.ndarray:
    if rule.get("rate_comparator") != STRICT_COMPARATOR:
        raise ValueError("unsupported rate comparator")
    if rule.get("dispersion_comparator") != STRICT_COMPARATOR:
        raise ValueError("unsupported dispersion comparator")
    return (np.asarray(rate_scores, dtype=float) > float(rule["rate_threshold"])) | (
        np.asarray(dispersion_scores, dtype=float)
        > float(rule["dispersion_threshold"])
    )


def calibrate_or_rule(
    rate_scores: np.ndarray,
    dispersion_scores: np.ndarray,
    labels: np.ndarray,
    target_fpr: float,
) -> dict[str, Any]:
    labels = np.asarray(labels, dtype=int)
    rate_scores = np.asarray(rate_scores, dtype=float)
    dispersion_scores = np.asarray(dispersion_scores, dtype=float)
    if not 0.0 <= target_fpr < 1.0:
        raise ValueError("target_fpr must be in [0, 1)")
    negative = labels == 0
    benign_count = int(negative.sum())
    budget = int(math.floor(target_fpr * benign_count + 1e-12))
    best: dict[str, Any] | None = None
    for rate_budget in range(budget + 1):
        dispersion_budget = budget - rate_budget
        rate_threshold = _threshold_for_false_positives(
            rate_scores[negative], rate_budget
        )
        dispersion_threshold = _threshold_for_false_positives(
            dispersion_scores[negative], dispersion_budget
        )
        candidate: dict[str, Any] = {
            "rate_threshold": rate_threshold,
            "dispersion_threshold": dispersion_threshold,
            "rate_comparator": STRICT_COMPARATOR,
            "dispersion_comparator": STRICT_COMPARATOR,
            "decision_rule": (
                "rate_score > rate_threshold OR dispersion_score > "
                "dispersion_threshold; ties are not flagged"
            ),
            "target_fpr": target_fpr,
            "allowed_false_positives": budget,
            "rate_fp_budget": rate_budget,
            "dispersion_fp_budget": dispersion_budget,
        }
        prediction = apply_or_rule(rate_scores, dispersion_scores, candidate)
        fp = int((negative & prediction).sum())
        if fp > budget:
            continue
        tp = int(((labels == 1) & prediction).sum())
        candidate.update(
            {
                "calibration_false_positives": fp,
                "calibration_fpr": _safe_div(fp, benign_count),
                "calibration_recall": _safe_div(
                    tp, int((labels == 1).sum())
                ),
                "benign_rate_ties_at_threshold": int(
                    (rate_scores[negative] == rate_threshold).sum()
                ),
                "benign_dispersion_ties_at_threshold": int(
                    (
                        dispersion_scores[negative]
                        == dispersion_threshold
                    ).sum()
                ),
            }
        )
        if best is None or (
            candidate["calibration_recall"], -candidate["calibration_fpr"]
        ) > (best["calibration_recall"], -best["calibration_fpr"]):
            best = candidate
    if best is None:
        raise RuntimeError("no feasible OR calibration threshold")
    return best


def confusion_counts(labels: np.ndarray, prediction: np.ndarray) -> dict[str, int]:
    labels = np.asarray(labels, dtype=int)
    prediction = np.asarray(prediction, dtype=bool)
    return {
        "tp": int(((labels == 1) & prediction).sum()),
        "fp": int(((labels == 0) & prediction).sum()),
        "tn": int(((labels == 0) & ~prediction).sum()),
        "fn": int(((labels == 1) & ~prediction).sum()),
    }


def metric_summary(
    labels: np.ndarray,
    prediction: np.ndarray,
    scores: np.ndarray,
    packet_weights: np.ndarray,
    byte_weights: np.ndarray,
) -> dict[str, Any]:
    labels = np.asarray(labels, dtype=int)
    prediction = np.asarray(prediction, dtype=bool)
    scores = np.asarray(scores, dtype=float)
    packet_weights = np.asarray(packet_weights, dtype=float)
    byte_weights = np.asarray(byte_weights, dtype=float)
    lengths = {
        len(labels), len(prediction), len(scores), len(packet_weights), len(byte_weights)
    }
    if len(lengths) != 1:
        raise ValueError("metric arrays must have identical lengths")
    counts = confusion_counts(labels, prediction)
    tp, fp, tn, fn = (counts[key] for key in ("tp", "fp", "tn", "fn"))
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    specificity = _safe_div(tn, tn + fp)
    f1 = _safe_div(2.0 * precision * recall, precision + recall)
    denominator = math.sqrt(
        max(0.0, (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    )
    attack_mask = labels == 1
    benign_mask = labels == 0
    interval_note = (
        "descriptive conditional row-level Wilson interval; rows are not "
        "asserted independent and no capture/group confidence interval is available"
    )
    return {
        "unit_of_analysis": "completed distributed flow row",
        "uncertainty_scope": interval_note,
        "confusion": counts,
        "metrics": {
            "precision": {
                "estimate": precision,
                "descriptive_conditional_row_wilson95": wilson_interval(
                    tp, tp + fp
                ),
            },
            "recall_tpr": {
                "estimate": recall,
                "descriptive_conditional_row_wilson95": wilson_interval(
                    tp, tp + fn
                ),
            },
            "false_positive_rate": {
                "estimate": 1.0 - specificity,
                "descriptive_conditional_row_wilson95": wilson_interval(
                    fp, fp + tn
                ),
            },
            "specificity_tnr": specificity,
            "balanced_accuracy": (recall + specificity) / 2.0,
            "f1": f1,
            "mcc": _safe_div(tp * tn - fp * fn, denominator),
            "average_precision": float(average_precision_score(labels, scores)),
            "roc_auc": float(roc_auc_score(labels, scores)),
        },
        "retrospective_whole_flow_mass_association": {
            "interpretation": (
                "packet and payload totals weight completed flow rows after the "
                "fact; these fractions are not operational packet diversion, "
                "goodput, or pre-classification leakage measurements"
            ),
            "attack_packet_mass_on_flagged_rows_fraction": _weighted_rate(
                prediction[attack_mask], packet_weights[attack_mask]
            ),
            "attack_payload_mass_on_flagged_rows_fraction": _weighted_rate(
                prediction[attack_mask], byte_weights[attack_mask]
            ),
            "benign_packet_mass_on_flagged_rows_fraction": _weighted_rate(
                prediction[benign_mask], packet_weights[benign_mask]
            ),
            "benign_payload_mass_on_flagged_rows_fraction": _weighted_rate(
                prediction[benign_mask], byte_weights[benign_mask]
            ),
        },
    }


def _family_rates(
    families: pd.Series, prediction: np.ndarray
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    values = families.astype(str).to_numpy()
    prediction = np.asarray(prediction, dtype=bool)
    for family in sorted(set(values)):
        mask = values == family
        flagged = int(prediction[mask].sum())
        total = int(mask.sum())
        result[family] = {
            "flow_row_count": total,
            "flagged_row_count": flagged,
            "flagged_row_rate": _safe_div(flagged, total),
            "descriptive_conditional_row_wilson95": wilson_interval(
                flagged, total
            ),
            "interpretation": (
                "benign-family false-positive row rate"
                if family in NORMAL_FAMILIES
                else "attack-family recall over flow rows"
            ),
        }
    attack_rates = [
        record["flagged_row_rate"]
        for family, record in result.items()
        if family not in NORMAL_FAMILIES
    ]
    benign_rates = [
        record["flagged_row_rate"]
        for family, record in result.items()
        if family in NORMAL_FAMILIES
    ]
    macro = {
        "attack_family_macro_recall": float(np.mean(attack_rates)),
        "attack_family_count": len(attack_rates),
        "benign_family_macro_false_positive_rate": float(np.mean(benign_rates)),
        "benign_family_count": len(benign_rates),
        "interpretation": (
            "unweighted descriptive mean of per-family row rates; not a "
            "confidence interval or a population-generalization estimate"
        ),
    }
    return result, macro


def _selector_metadata() -> dict[str, Any]:
    return {
        "rate_only": {
            "input": ["flow_pkts_per_sec"],
            "score": "log1p(flow_pkts_per_sec); larger is more attack-like",
        },
        "dispersion_only": {
            "input": ["flow_iat.std"],
            "score": "-log1p(flow_iat.std); larger/lower dispersion is more attack-like",
            "degeneracy_warning": (
                "zero standard deviation is structural for all one- and two-packet rows"
            ),
        },
        "timing_or": {
            "inputs": ["flow_pkts_per_sec", "flow_iat.std"],
            "rule": "strict rate comparator OR strict dispersion comparator",
            "explicit_non_input": "flow_iat.avg",
        },
        "compact_logistic": {
            "inputs": list(COMPACT_FEATURES),
            "fit_partition": "train",
            "threshold_partition": "calibration",
        },
        "random_forest_reference": {
            "inputs": list(REFERENCE_FEATURES),
            "fit_partition": "train",
            "threshold_partition": "calibration",
            "claim_boundary": "accuracy reference; not asserted XDP-deployable",
        },
    }


def run_public_experiment(
    output_dir: Path,
    csv_path: Path = DEFAULT_CSV,
    archive_path: Path = DEFAULT_ARCHIVE,
    config: PublicExperimentConfig | None = None,
    config_path: Path = DEFAULT_CONFIG,
) -> dict[str, Any]:
    config, config_binding = _resolve_config(config, config_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    frame, audit = load_and_split(
        csv_path, archive_path, config=config, config_path=config_path
    )
    train = frame[frame["split"] == "train"]
    calibration = frame[frame["split"] == "calibration"]
    test = frame[frame["split"] == "test"].copy()
    y_train = train["true_label"].to_numpy(dtype=int)
    y_cal = calibration["true_label"].to_numpy(dtype=int)
    y_test = test["true_label"].to_numpy(dtype=int)

    rate_cal = np.log1p(calibration["flow_pkts_per_sec"].to_numpy(dtype=float))
    rate_test = np.log1p(test["flow_pkts_per_sec"].to_numpy(dtype=float))
    dispersion_cal = -np.log1p(
        calibration["flow_iat.std"].to_numpy(dtype=float)
    )
    dispersion_test = -np.log1p(test["flow_iat.std"].to_numpy(dtype=float))
    rate_rule = calibrate_score_threshold(
        rate_cal, y_cal, config.calibration_target_fpr
    )
    dispersion_rule = calibrate_score_threshold(
        dispersion_cal, y_cal, config.calibration_target_fpr
    )
    or_rule = calibrate_or_rule(
        rate_cal, dispersion_cal, y_cal, config.calibration_target_fpr
    )

    logistic = Pipeline(
        [
            ("scale", StandardScaler()),
            (
                "model",
                LogisticRegression(
                    class_weight="balanced",
                    max_iter=config.logistic_max_iter,
                    random_state=config.logistic_random_state,
                ),
            ),
        ]
    )
    logistic.fit(train[list(COMPACT_FEATURES)], y_train)
    logistic_cal = logistic.predict_proba(
        calibration[list(COMPACT_FEATURES)]
    )[:, 1]
    logistic_test = logistic.predict_proba(test[list(COMPACT_FEATURES)])[:, 1]
    logistic_rule = calibrate_score_threshold(
        logistic_cal, y_cal, config.calibration_target_fpr
    )

    forest = RandomForestClassifier(
        n_estimators=config.forest_estimators,
        max_depth=config.forest_max_depth,
        min_samples_leaf=config.forest_min_samples_leaf,
        max_features="sqrt",
        class_weight="balanced_subsample",
        random_state=config.forest_random_state,
        n_jobs=1,
    )
    forest.fit(train[list(REFERENCE_FEATURES)], y_train)
    forest_cal = forest.predict_proba(
        calibration[list(REFERENCE_FEATURES)]
    )[:, 1]
    forest_test = forest.predict_proba(test[list(REFERENCE_FEATURES)])[:, 1]
    forest_rule = calibrate_score_threshold(
        forest_cal, y_cal, config.calibration_target_fpr
    )

    scores = {
        "rate_only": rate_test,
        "dispersion_only": dispersion_test,
        "timing_or": np.maximum(
            rate_test - or_rule["rate_threshold"],
            dispersion_test - or_rule["dispersion_threshold"],
        ),
        "compact_logistic": logistic_test,
        "random_forest_reference": forest_test,
    }
    predictions = {
        "rate_only": apply_score_rule(rate_test, rate_rule),
        "dispersion_only": apply_score_rule(dispersion_test, dispersion_rule),
        "timing_or": apply_or_rule(rate_test, dispersion_test, or_rule),
        "compact_logistic": apply_score_rule(logistic_test, logistic_rule),
        "random_forest_reference": apply_score_rule(forest_test, forest_rule),
    }
    calibration_record = {
        "rate_only": rate_rule,
        "dispersion_only": dispersion_rule,
        "timing_or": or_rule,
        "compact_logistic": logistic_rule,
        "random_forest_reference": forest_rule,
    }

    packet_weights = test["packet_weight"].to_numpy(dtype=float)
    byte_weights = test["payload_byte_weight"].to_numpy(dtype=float)
    selectors: dict[str, Any] = {}
    for name in predictions:
        selectors[name] = metric_summary(
            y_test,
            predictions[name],
            scores[name],
            packet_weights,
            byte_weights,
        )
        selectors[name]["calibration"] = calibration_record[name]
        by_family, macro = _family_rates(test["Attack_type"], predictions[name])
        selectors[name]["by_family"] = by_family
        selectors[name]["macro_family_averages"] = macro

    prediction_frame = test[
        [
            "source_file_row_position_zero_based",
            EXPORTED_INDEX_COLUMN,
            "global_learned_input_group_hash_u64",
            "reference_input_hash_u64",
            "compact_input_hash_u64",
            "Attack_type",
            "true_label",
            "packet_weight",
            "payload_byte_weight",
        ]
    ].copy()
    for name in predictions:
        prediction_frame[f"{name}_score"] = scores[name]
        prediction_frame[f"{name}_prediction"] = predictions[name].astype(int)
    predictions_path = output_dir / "test_predictions.csv"
    prediction_frame.to_csv(predictions_path, index=False, lineterminator="\n")

    split_path = output_dir / "split_manifest.csv"
    frame[
        [
            "source_file_row_position_zero_based",
            EXPORTED_INDEX_COLUMN,
            "global_learned_input_group_hash_u64",
            "reference_input_hash_u64",
            "compact_input_hash_u64",
            "full_feature_hash_u64",
            "Attack_type",
            "true_label",
            "split",
        ]
    ].to_csv(split_path, index=False, lineterminator="\n")

    scaler = logistic.named_steps["scale"]
    logistic_model = logistic.named_steps["model"]
    model_metadata = {
        "selector_definitions": _selector_metadata(),
        "compact_logistic": {
            "features_in_order": list(COMPACT_FEATURES),
            "standardizer_mean": scaler.mean_.tolist(),
            "standardizer_scale": scaler.scale_.tolist(),
            "coefficients_in_standardized_feature_space": logistic_model.coef_[
                0
            ].tolist(),
            "intercept": logistic_model.intercept_.tolist(),
            "classes": logistic_model.classes_.tolist(),
        },
        "random_forest_reference": {
            "features_in_order": list(REFERENCE_FEATURES),
            "feature_importances": forest.feature_importances_.tolist(),
            "estimators": config.forest_estimators,
            "max_depth": config.forest_max_depth,
            "min_samples_leaf": config.forest_min_samples_leaf,
            "workers": 1,
            "claim_boundary": (
                "accuracy reference on completed-flow aggregates; not asserted "
                "to be directly XDP-deployable"
            ),
        },
    }
    model_path = output_dir / "model_metadata.json"
    write_json(model_path, model_metadata)

    repro = reproducibility_inputs(config_path)
    repro["immutable_config"].update(config_binding)
    summary_without_hash = {
        "schema_version": config.schema_version,
        "determinism": {
            "same_host_same_bound_runtime": True,
            "scope": repro["determinism_scope"],
        },
        "effective_config": asdict(config),
        "reproducibility_binding": repro,
        "dataset_audit": audit,
        "feature_and_selector_policy": {
            "excluded_from_learned_models": [
                "class_local_row_id and source row position",
                "Attack_type and derived binary label",
                "origin and response ports",
                "protocol and service categories",
                "direct endpoint identifiers (not distributed)",
            ],
            "selector_definitions": _selector_metadata(),
        },
        "selectors": selectors,
        "artifacts": {
            "test_predictions": "test_predictions.csv",
            "split_manifest": "split_manifest.csv",
            "model_metadata": "model_metadata.json",
        },
        "claim_boundary": (
            "in-dataset evaluation on precomputed RT-IoT2022 completed-flow "
            "aggregates; not packet-timestamp, exact-window, maturation, "
            "capture-group, operational diversion, kernel, or XDP evidence"
        ),
    }
    summary = {
        **summary_without_hash,
        "result_payload_sha256": canonical_sha256(summary_without_hash),
    }
    summary_path = output_dir / "summary.json"
    write_json(summary_path, summary)

    generated_paths = (predictions_path, split_path, model_path, summary_path)
    manifest = {
        "schema_version": config.schema_version,
        "source_files": {
            "data/public/rt_iot2022/original/rt-iot2022.zip": EXPECTED_ARCHIVE_SHA256,
            "data/public/rt_iot2022/original/RT_IOT2022": EXPECTED_CSV_SHA256,
        },
        "reproducibility_inputs": repro,
        "generated_files": {
            path.name: file_sha256(path) for path in generated_paths
        },
        "manifest_scope": (
            "all generated files except manifest.json itself, whose inclusion "
            "would be self-referential"
        ),
    }
    write_json(output_dir / "manifest.json", manifest)
    verify_manifest(output_dir / "manifest.json")
    return summary


def verify_manifest(manifest_path: Path) -> None:
    manifest_path = Path(manifest_path)
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    for name, expected in payload["generated_files"].items():
        observed = file_sha256(manifest_path.parent / name)
        if observed != expected:
            raise ValueError(f"generated artifact hash mismatch for {name}")
    source_map = {
        "data/public/rt_iot2022/original/rt-iot2022.zip": DEFAULT_ARCHIVE,
        "data/public/rt_iot2022/original/RT_IOT2022": DEFAULT_CSV,
    }
    for name, expected in payload["source_files"].items():
        if name not in source_map or file_sha256(source_map[name]) != expected:
            raise ValueError(f"source artifact hash mismatch for {name}")
    for key in ("generator", "immutable_config", "requirements"):
        record = payload["reproducibility_inputs"][key]
        path = PROJECT_ROOT / record["artifact_path"]
        if file_sha256(path) != record["sha256"]:
            raise ValueError(f"reproducibility input hash mismatch for {key}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args()
    summary = run_public_experiment(
        args.output_dir,
        csv_path=args.csv,
        archive_path=args.archive,
        config_path=args.config,
    )
    print(f"result_payload_sha256={summary['result_payload_sha256']}")
    print(f"summary={args.output_dir / 'summary.json'}")


if __name__ == "__main__":
    main()
