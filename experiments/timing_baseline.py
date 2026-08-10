#!/usr/bin/env python3
"""Immutable preservation of the original timing-only synthetic baseline.

This historical baseline intentionally keeps three questions separate:

1. Can a small timing-only classifier distinguish the synthetic flow models?
2. Does putting already-tagged traffic on a physically separate finite-capacity
   queue preserve the capacity available to the fast path?
3. What transient timeouts can an RFC-style conforming sender experience when
   its RTT changes abruptly?

The classifier result is a negative result: it misses most synthetic attacks.
The queue calculation assumes traffic has already been labeled correctly, and
the TCP calculation is only a narrow timeout transient.  These limitations are
part of the preserved result, not post-hoc qualifications.

The generator is self-contained so that a future top-level experiment
orchestrator can replace ``experiments/reproducible_pipeline.py`` without
changing this baseline's code or provenance.  It never writes dashboard data
and refuses to write into a nonempty output directory.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import math
import platform
from collections import deque
from dataclasses import MISSING, asdict, dataclass, fields
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = Path(__file__).resolve()
REQUIREMENTS_PATH = PROJECT_ROOT / "requirements.txt"
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "configs" / "timing_baseline.json"
DEFAULT_RESULTS_DIR = PROJECT_ROOT / "results" / "timing_baseline_v1"

BENIGN_TYPES = ("benign_human", "benign_automated", "benign_paced")
ATTACK_TYPES = ("bot_volumetric", "bot_low_rate", "bot_jitter_mimicry")
ALL_TYPES = BENIGN_TYPES + ATTACK_TYPES


@dataclass(frozen=True)
class ExperimentConfig:
    schema_version: str = "timing-baseline-1.0"
    window_iats: int = 20
    rate_mean_iat_threshold_s: float = 0.020
    calibration_target_fpr: float = 0.01
    calibration_seeds: tuple[int, ...] = (101, 211, 307, 401, 503)
    test_seeds: tuple[int, ...] = (
        1009,
        1013,
        1019,
        1021,
        1031,
        1033,
        1039,
        1049,
        1051,
        1061,
        1063,
        1069,
        1087,
        1091,
        1093,
        1097,
        1103,
        1109,
        1117,
        1123,
    )
    calibration_flows_per_type_per_seed: int = 80
    test_flows_per_type_per_seed: int = 100
    bootstrap_replicates: int = 5000
    bootstrap_seed: int = 90210
    sensitivity_jitter_s: tuple[float, ...] = (
        0.0,
        0.0005,
        0.001,
        0.0015,
        0.002,
        0.0025,
        0.003,
        0.004,
        0.005,
        0.010,
        0.030,
        0.100,
        0.200,
        0.500,
        1.000,
    )
    sensitivity_flows_per_point_per_seed: int = 100
    fast_capacity_pps: float = 2000.0
    fast_benign_offered_pps: float = 800.0
    fast_buffer_packets: int = 1000
    fast_propagation_delay_s: float = 0.020
    quarantine_capacity_pps: float = 250.0
    quarantine_buffer_packets: int = 500
    quarantine_propagation_delay_s: float = 3.0
    quarantine_offered_loads_pps: tuple[float, ...] = (
        0.0,
        100.0,
        200.0,
        250.0,
        500.0,
        750.0,
        1000.0,
        1500.0,
        2000.0,
        3000.0,
    )
    queue_packet_unit_bytes: int = 1500
    queue_duration_s: float = 30.0
    queue_measurement_start_s: float = 5.0
    latency_sample_limit_per_seed: int = 100
    tcp_base_rtt_s: float = 0.040
    tcp_initial_rto_s: float = 1.0
    tcp_max_rto_s: float = 60.0
    tcp_reference_window_packets: int = 64
    tcp_added_rtt_values_s: tuple[float, ...] = (
        0.0,
        0.25,
        0.5,
        1.0,
        1.5,
        2.0,
        3.0,
        4.0,
        5.0,
    )

    def validate(self) -> None:
        if self.schema_version != "timing-baseline-1.0":
            raise ValueError(f"unsupported config schema {self.schema_version!r}")

        positive_integer_fields = (
            "window_iats",
            "calibration_flows_per_type_per_seed",
            "test_flows_per_type_per_seed",
            "bootstrap_replicates",
            "bootstrap_seed",
            "sensitivity_flows_per_point_per_seed",
            "fast_buffer_packets",
            "quarantine_buffer_packets",
            "queue_packet_unit_bytes",
            "latency_sample_limit_per_seed",
            "tcp_reference_window_packets",
        )
        for name in positive_integer_fields:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")

        for name, values in (
            ("calibration_seeds", self.calibration_seeds),
            ("test_seeds", self.test_seeds),
        ):
            if not values or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in values
            ):
                raise ValueError(f"{name} must contain nonnegative integer seeds")
            if len(set(values)) != len(values):
                raise ValueError(f"{name} must not contain duplicates")
        if set(self.calibration_seeds) & set(self.test_seeds):
            raise ValueError("calibration_seeds and test_seeds must be disjoint")

        finite_numeric_fields = (
            "rate_mean_iat_threshold_s",
            "calibration_target_fpr",
            "fast_capacity_pps",
            "fast_benign_offered_pps",
            "fast_propagation_delay_s",
            "quarantine_capacity_pps",
            "quarantine_propagation_delay_s",
            "queue_duration_s",
            "queue_measurement_start_s",
            "tcp_base_rtt_s",
            "tcp_initial_rto_s",
            "tcp_max_rto_s",
        )
        for name in finite_numeric_fields:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} must be numeric")
            if not math.isfinite(float(value)):
                raise ValueError(f"{name} must be finite")

        if self.window_iats < 2:
            raise ValueError("window_iats must be at least two")
        if self.rate_mean_iat_threshold_s <= 0.0:
            raise ValueError("rate_mean_iat_threshold_s must be positive")
        if not 0.0 <= self.calibration_target_fpr < 1.0:
            raise ValueError("calibration_target_fpr must be in [0, 1)")
        if self.fast_capacity_pps <= 0.0 or self.quarantine_capacity_pps <= 0.0:
            raise ValueError("queue capacities must be positive")
        if self.fast_benign_offered_pps < 0.0:
            raise ValueError("fast_benign_offered_pps must be nonnegative")
        if self.fast_propagation_delay_s < 0.0 or self.quarantine_propagation_delay_s < 0.0:
            raise ValueError("propagation delays must be nonnegative")
        if not 0.0 <= self.queue_measurement_start_s < self.queue_duration_s:
            raise ValueError("measurement start must lie inside the queue duration")
        if self.tcp_base_rtt_s <= 0.0 or self.tcp_initial_rto_s <= 0.0:
            raise ValueError("TCP base RTT and initial RTO must be positive")
        if self.tcp_max_rto_s < self.tcp_initial_rto_s:
            raise ValueError("tcp_max_rto_s must be at least tcp_initial_rto_s")

        for name, values in (
            ("sensitivity_jitter_s", self.sensitivity_jitter_s),
            ("quarantine_offered_loads_pps", self.quarantine_offered_loads_pps),
            ("tcp_added_rtt_values_s", self.tcp_added_rtt_values_s),
        ):
            if not values:
                raise ValueError(f"{name} must not be empty")
            if any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or float(value) < 0.0
                for value in values
            ):
                raise ValueError(f"{name} must contain finite nonnegative numbers")
            numeric = tuple(float(value) for value in values)
            if numeric != tuple(sorted(set(numeric))):
                raise ValueError(f"{name} must be strictly increasing and unique")


@dataclass(frozen=True)
class FlowObservation:
    flow_id: str
    seed: int
    traffic_type: str
    true_label: str
    mean_iat_s: float
    variance_iat_s2: float
    minimum_iat_s: float
    maximum_iat_s: float


@dataclass(frozen=True)
class ClassifierConfig:
    window_iats: int
    mean_iat_rate_threshold_s: float
    variance_threshold_s2: float
    calibration_target_fpr: float


def _json_default(value: Any) -> Any:
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Cannot serialize {type(value)!r}")


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(
        payload,
        indent=2,
        sort_keys=True,
        allow_nan=False,
        default=_json_default,
    )
    path.write_text(text + "\n", encoding="utf-8")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_sha256(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=_json_default,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _display_path(path: Path) -> str:
    """Return a portable artifact label, never a host-specific absolute path."""

    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(PROJECT_ROOT.resolve()).as_posix()
    except ValueError:
        return resolved.name


def _reject_nonfinite_json(token: str) -> None:
    raise ValueError(f"non-finite JSON constant is forbidden: {token}")


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> ExperimentConfig:
    """Load an exact, complete committed configuration.

    Unknown or missing keys, non-finite JSON constants, scalar/list shape
    changes, and invalid parameter ranges are rejected rather than defaulted.
    """

    path = Path(path)
    payload = json.loads(
        path.read_text(encoding="utf-8"), parse_constant=_reject_nonfinite_json
    )
    if not isinstance(payload, dict):
        raise ValueError("timing baseline config must be a JSON object")
    expected = {item.name for item in fields(ExperimentConfig)}
    observed = set(payload)
    if observed != expected:
        raise ValueError(
            "config fields differ: "
            f"missing={sorted(expected - observed)}, "
            f"unknown={sorted(observed - expected)}"
        )

    normalized: dict[str, Any] = {}
    for item in fields(ExperimentConfig):
        value = payload[item.name]
        default = item.default
        if default is MISSING:
            raise AssertionError(f"config field {item.name} lacks a default")
        if isinstance(default, tuple):
            if not isinstance(value, list):
                raise ValueError(f"{item.name} must be a JSON array")
            normalized[item.name] = tuple(value)
        else:
            if isinstance(value, (dict, list)):
                raise ValueError(f"{item.name} must be a scalar")
            normalized[item.name] = value

    config = ExperimentConfig(**normalized)
    config.validate()
    return config


def runtime_record() -> dict[str, Any]:
    record = {
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "numpy": np.__version__,
        "matplotlib": importlib.metadata.version("matplotlib"),
        "scipy": importlib.metadata.version("scipy"),
    }
    return {"record": record, "sha256": canonical_sha256(record)}


def _log_uniform(rng: np.random.Generator, low: float, high: float) -> float:
    return float(math.exp(rng.uniform(math.log(low), math.log(high))))


def _positive_normal(
    rng: np.random.Generator,
    center: float,
    sigma: float,
    count: int,
    minimum: float = 0.0001,
) -> np.ndarray:
    return np.maximum(minimum, rng.normal(center, sigma, size=count))


def generate_iats(
    traffic_type: str,
    rng: np.random.Generator,
    count: int,
    *,
    mimic_jitter_s: float | None = None,
) -> np.ndarray:
    """Generate one flow's IAT window from a documented stylized model.

    These distributions are not asserted to represent Internet-wide traffic.
    They deliberately include low-variance benign automation and paced clients,
    which overlap the variance-only attack heuristic.
    """

    if traffic_type == "benign_human":
        # Interactive sessions alternate short within-action bursts and longer
        # think times. The per-flow mixture weight varies across users.
        think_probability = float(rng.uniform(0.20, 0.45))
        think_mask = rng.random(count) < think_probability
        burst = rng.lognormal(mean=math.log(0.18), sigma=0.55, size=count)
        think = rng.lognormal(mean=math.log(2.5), sigma=0.65, size=count)
        values = np.where(think_mask, think, burst)
        return np.maximum(0.002, values)

    if traffic_type == "benign_automated":
        # Heartbeats and polling jobs can be very regular and are therefore a
        # hard benign case for a machine-rhythm detector.
        center = float(rng.uniform(0.40, 2.00))
        sigma = _log_uniform(rng, 0.015, 0.18)
        return _positive_normal(rng, center, sigma, count)

    if traffic_type == "benign_paced":
        # Paced APIs/streaming are faster than heartbeat traffic but remain
        # above the explicit volumetric-rate rule used here.
        center = float(rng.uniform(0.040, 0.200))
        sigma_fraction = _log_uniform(rng, 0.03, 0.30)
        return _positive_normal(rng, center, center * sigma_fraction, count)

    if traffic_type == "bot_volumetric":
        center = _log_uniform(rng, 0.002, 0.012)
        sigma_fraction = _log_uniform(rng, 0.02, 0.20)
        return _positive_normal(rng, center, center * sigma_fraction, count)

    if traffic_type == "bot_low_rate":
        center = float(rng.uniform(0.50, 1.80))
        sigma = _log_uniform(rng, 0.002, 0.080)
        return _positive_normal(rng, center, sigma, count)

    if traffic_type == "bot_jitter_mimicry":
        center = float(rng.uniform(0.50, 1.80))
        sigma = (
            float(mimic_jitter_s)
            if mimic_jitter_s is not None
            else _log_uniform(rng, 0.030, 0.60)
        )
        return _positive_normal(rng, center, sigma, count)

    raise ValueError(f"Unknown traffic type: {traffic_type}")


def generate_flow_observations(
    seed: int,
    flows_per_type: int,
    window_iats: int,
    traffic_types: Sequence[str] = ALL_TYPES,
    *,
    mimic_jitter_s: float | None = None,
) -> list[FlowObservation]:
    rng = np.random.default_rng(seed)
    observations: list[FlowObservation] = []
    for traffic_type in traffic_types:
        label = "benign" if traffic_type in BENIGN_TYPES else "attack"
        for index in range(flows_per_type):
            iats = generate_iats(
                traffic_type,
                rng,
                window_iats,
                mimic_jitter_s=mimic_jitter_s,
            )
            observations.append(
                FlowObservation(
                    flow_id=f"{seed}:{traffic_type}:{index:04d}",
                    seed=seed,
                    traffic_type=traffic_type,
                    true_label=label,
                    mean_iat_s=float(np.mean(iats)),
                    variance_iat_s2=float(np.var(iats, ddof=1)),
                    minimum_iat_s=float(np.min(iats)),
                    maximum_iat_s=float(np.max(iats)),
                )
            )
    return observations


def classify_flow(
    flow: FlowObservation,
    classifier: ClassifierConfig,
) -> tuple[str, str]:
    if flow.mean_iat_s <= classifier.mean_iat_rate_threshold_s:
        return "attack", "mean_iat_rate_rule"
    if flow.variance_iat_s2 <= classifier.variance_threshold_s2:
        return "attack", "low_iat_variance_rule"
    return "benign", "no_rule_fired"


def _confusion_from_predictions(records: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for record in records:
        truth = record["true_label"]
        prediction = record["predicted_label"]
        if truth == "attack" and prediction == "attack":
            counts["tp"] += 1
        elif truth == "benign" and prediction == "attack":
            counts["fp"] += 1
        elif truth == "benign" and prediction == "benign":
            counts["tn"] += 1
        elif truth == "attack" and prediction == "benign":
            counts["fn"] += 1
        else:
            raise ValueError(f"Invalid truth/prediction pair: {truth}/{prediction}")
    return counts


def _safe_div(numerator: float, denominator: float) -> float:
    return float(numerator / denominator) if denominator else 0.0


def metrics_from_confusion(counts: dict[str, int]) -> dict[str, float]:
    tp, fp, tn, fn = (counts[key] for key in ("tp", "fp", "tn", "fn"))
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    specificity = _safe_div(tn, tn + fp)
    accuracy = _safe_div(tp + tn, tp + fp + tn + fn)
    return {
        "precision": precision,
        "recall_tpr": recall,
        "specificity_tnr": specificity,
        "false_positive_rate": _safe_div(fp, fp + tn),
        "accuracy": accuracy,
        "balanced_accuracy": (recall + specificity) / 2.0,
        "f1": _safe_div(2.0 * precision * recall, precision + recall),
    }


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> list[float]:
    if total <= 0:
        return [0.0, 0.0]
    p = successes / total
    denominator = 1.0 + z * z / total
    center = (p + z * z / (2.0 * total)) / denominator
    half_width = (
        z
        * math.sqrt(p * (1.0 - p) / total + z * z / (4.0 * total * total))
        / denominator
    )
    low = max(0.0, center - half_width)
    high = min(1.0, center + half_width)
    if low < 1e-15:
        low = 0.0
    if 1.0 - high < 1e-15:
        high = 1.0
    return [low, high]


def calibrate_classifier(
    flows: Sequence[FlowObservation],
    config: ExperimentConfig,
) -> tuple[ClassifierConfig, dict[str, Any]]:
    """Choose the largest variance threshold meeting the benign FPR cap.

    The rate threshold is fixed before calibration. Only calibration flows are
    inspected. Maximizing the threshold maximizes attack recall subject to the
    empirical calibration FPR constraint because the decision is monotone.
    """

    candidates = sorted({0.0, *(flow.variance_iat_s2 for flow in flows)})
    best_threshold: float | None = None
    best_counts: dict[str, int] | None = None
    for threshold in candidates:
        candidate = ClassifierConfig(
            window_iats=config.window_iats,
            mean_iat_rate_threshold_s=config.rate_mean_iat_threshold_s,
            variance_threshold_s2=float(threshold),
            calibration_target_fpr=config.calibration_target_fpr,
        )
        records = []
        for flow in flows:
            prediction, _ = classify_flow(flow, candidate)
            records.append(
                {"true_label": flow.true_label, "predicted_label": prediction}
            )
        counts = _confusion_from_predictions(records)
        fpr = metrics_from_confusion(counts)["false_positive_rate"]
        if fpr <= config.calibration_target_fpr + 1e-15:
            best_threshold = float(threshold)
            best_counts = counts
        else:
            break

    if best_threshold is None or best_counts is None:
        raise RuntimeError("The fixed rate rule already exceeds the calibration FPR target")

    classifier = ClassifierConfig(
        window_iats=config.window_iats,
        mean_iat_rate_threshold_s=config.rate_mean_iat_threshold_s,
        variance_threshold_s2=best_threshold,
        calibration_target_fpr=config.calibration_target_fpr,
    )
    return classifier, {
        "selection_rule": (
            "largest variance threshold with empirical benign-flow FPR <= target; "
            "rate threshold fixed before calibration"
        ),
        "flow_count": len(flows),
        "confusion": best_counts,
        "metrics": metrics_from_confusion(best_counts),
    }


def prediction_records(
    flows: Sequence[FlowObservation],
    classifier: ClassifierConfig,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for flow in flows:
        prediction, reason = classify_flow(flow, classifier)
        record = asdict(flow)
        record.update(
            {
                "predicted_label": prediction,
                "decision_reason": reason,
                "packets_required_for_decision": classifier.window_iats + 1,
            }
        )
        records.append(record)
    return records


def _bootstrap_metric_intervals(
    per_seed_confusion: Sequence[dict[str, int]],
    replicates: int,
    seed: int,
) -> dict[str, list[float]]:
    rng = np.random.default_rng(seed)
    n_seeds = len(per_seed_confusion)
    metric_samples: dict[str, list[float]] = {
        key: [] for key in metrics_from_confusion(per_seed_confusion[0])
    }
    for _ in range(replicates):
        indices = rng.integers(0, n_seeds, size=n_seeds)
        pooled = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
        for index in indices:
            for key in pooled:
                pooled[key] += per_seed_confusion[int(index)][key]
        metrics = metrics_from_confusion(pooled)
        for key, value in metrics.items():
            metric_samples[key].append(value)
    return {
        key: [
            float(np.quantile(values, 0.025)),
            float(np.quantile(values, 0.975)),
        ]
        for key, values in metric_samples.items()
    }


def summarize_classification(
    records_by_seed: dict[int, list[dict[str, Any]]],
    config: ExperimentConfig,
) -> dict[str, Any]:
    per_seed = []
    all_records: list[dict[str, Any]] = []
    per_seed_confusion = []
    for seed in config.test_seeds:
        records = records_by_seed[seed]
        counts = _confusion_from_predictions(records)
        per_seed_confusion.append(counts)
        per_seed.append(
            {"seed": seed, "confusion": counts, "metrics": metrics_from_confusion(counts)}
        )
        all_records.extend(records)

    aggregate = _confusion_from_predictions(all_records)
    aggregate_metrics = metrics_from_confusion(aggregate)
    bootstrap_intervals = _bootstrap_metric_intervals(
        per_seed_confusion,
        config.bootstrap_replicates,
        config.bootstrap_seed,
    )
    metrics_with_ci = {
        key: {"estimate": value, "ci95": bootstrap_intervals[key]}
        for key, value in aggregate_metrics.items()
    }

    by_type: dict[str, Any] = {}
    for traffic_type in ALL_TYPES:
        subset = [record for record in all_records if record["traffic_type"] == traffic_type]
        positives = sum(record["predicted_label"] == "attack" for record in subset)
        estimate = positives / len(subset)
        by_type[traffic_type] = {
            "true_label": subset[0]["true_label"],
            "flow_count": len(subset),
            "flagged_count": positives,
            "flagged_rate": estimate,
            "flagged_rate_ci95_wilson": wilson_interval(positives, len(subset)),
            "rate_interpretation": (
                "false_positive_rate" if traffic_type in BENIGN_TYPES else "recall_tpr"
            ),
        }

    return {
        "unit_of_analysis": "flow",
        "decision_after_iats": config.window_iats,
        "decision_after_packets": config.window_iats + 1,
        "test_seed_count": len(config.test_seeds),
        "aggregate_confusion": aggregate,
        "aggregate_metrics": metrics_with_ci,
        "ci_method": (
            f"percentile bootstrap over {len(config.test_seeds)} held-out seeds, "
            f"{config.bootstrap_replicates} replicates; per-type rates use Wilson score"
        ),
        "by_traffic_type": by_type,
        "per_seed": per_seed,
    }


def sensitivity_evaluation(
    classifier: ClassifierConfig,
    config: ExperimentConfig,
    raw_dir: Path,
) -> dict[str, Any]:
    pooled = {
        jitter: {"flagged": 0, "total": 0}
        for jitter in config.sensitivity_jitter_s
    }
    for seed in config.test_seeds:
        seed_rows = []
        for point_index, jitter in enumerate(config.sensitivity_jitter_s):
            # Derive a stable independent RNG seed for every point.
            point_seed = seed * 1000 + point_index + 17
            flows = generate_flow_observations(
                point_seed,
                config.sensitivity_flows_per_point_per_seed,
                config.window_iats,
                traffic_types=("bot_jitter_mimicry",),
                mimic_jitter_s=jitter,
            )
            records = prediction_records(flows, classifier)
            flagged = sum(record["predicted_label"] == "attack" for record in records)
            total = len(records)
            pooled[jitter]["flagged"] += flagged
            pooled[jitter]["total"] += total
            seed_rows.append(
                {
                    "jitter_standard_deviation_s": jitter,
                    "flow_count": total,
                    "flagged_count": flagged,
                    "recall_tpr": flagged / total,
                }
            )
        write_json(
            raw_dir / f"sensitivity_seed_{seed}.json",
            {"seed": seed, "results": seed_rows},
        )

    points = []
    for jitter in config.sensitivity_jitter_s:
        flagged = pooled[jitter]["flagged"]
        total = pooled[jitter]["total"]
        points.append(
            {
                "jitter_standard_deviation_s": jitter,
                "flow_count": total,
                "flagged_count": flagged,
                "recall_tpr": flagged / total,
                "recall_tpr_ci95_wilson": wilson_interval(flagged, total),
            }
        )
    return {
        "traffic_model": "bot_jitter_mimicry with Gaussian additive timing jitter",
        "classifier_frozen_after_calibration": True,
        "points": points,
    }


def poisson_arrivals(
    rng: np.random.Generator,
    rate_pps: float,
    duration_s: float,
) -> np.ndarray:
    if rate_pps <= 0.0:
        return np.empty(0, dtype=float)
    arrivals: list[float] = []
    current = 0.0
    while True:
        current += float(rng.exponential(1.0 / rate_pps))
        if current >= duration_s:
            break
        arrivals.append(current)
    return np.asarray(arrivals, dtype=float)


def simulate_finite_queue(
    arrivals_s: np.ndarray,
    capacity_pps: float,
    buffer_packets: int,
    propagation_delay_s: float,
    measurement_start_s: float,
    duration_s: float,
) -> dict[str, Any]:
    """Simulate a finite FIFO server plus a separate propagation delay.

    `capacity_pps` controls serialized service. `propagation_delay_s` is added
    after service and permits arbitrary packets in flight; it never changes the
    server's departure spacing.
    """

    if capacity_pps <= 0.0:
        raise ValueError("capacity_pps must be positive")
    if buffer_packets < 1:
        raise ValueError("buffer_packets must be at least one")

    service_time = 1.0 / capacity_pps
    in_system_completion_times: deque[float] = deque()
    accepted_arrivals: list[float] = []
    service_completions: list[float] = []
    release_times: list[float] = []
    latencies: list[float] = []
    dropped = 0

    for arrival in arrivals_s:
        arrival_value = float(arrival)
        while in_system_completion_times and in_system_completion_times[0] <= arrival_value:
            in_system_completion_times.popleft()
        if len(in_system_completion_times) >= buffer_packets:
            dropped += 1
            continue
        previous_completion = (
            in_system_completion_times[-1]
            if in_system_completion_times
            else arrival_value
        )
        completion = max(arrival_value, previous_completion) + service_time
        release = completion + propagation_delay_s
        in_system_completion_times.append(completion)
        accepted_arrivals.append(arrival_value)
        service_completions.append(completion)
        release_times.append(release)
        latencies.append(release - arrival_value)

    measurement_duration = duration_s - measurement_start_s
    measured_arrivals = sum(measurement_start_s <= t < duration_s for t in arrivals_s)
    measured_accepts = 0
    measured_latencies = []
    for arrival, latency in zip(accepted_arrivals, latencies):
        if measurement_start_s <= arrival < duration_s:
            measured_accepts += 1
            measured_latencies.append(latency)
    measured_drops = measured_arrivals - measured_accepts

    if len(accepted_arrivals) + dropped != len(arrivals_s):
        raise AssertionError("queue conservation failed for full interval")
    if measured_accepts + measured_drops != measured_arrivals:
        raise AssertionError("queue conservation failed for measurement interval")
    if any(
        abs((release - completion) - propagation_delay_s) > 1e-9
        for release, completion in zip(release_times, service_completions)
    ):
        raise AssertionError("propagation delay changed inside the queue model")
    if any(
        later - earlier < service_time - 1e-9
        for earlier, later in zip(service_completions, service_completions[1:])
    ):
        raise AssertionError("server emitted packets faster than configured capacity")

    completions_in_window = sum(
        measurement_start_s <= completion < duration_s
        for completion in service_completions
    )
    return {
        "offered_packet_count": int(len(arrivals_s)),
        "accepted_packet_count": len(accepted_arrivals),
        "dropped_packet_count": dropped,
        "measurement_offered_packet_count": measured_arrivals,
        "measurement_accepted_packet_count": measured_accepts,
        "measurement_dropped_packet_count": measured_drops,
        "accepted_rate_pps": measured_accepts / measurement_duration,
        "service_departure_rate_pps": completions_in_window / measurement_duration,
        "drop_fraction": _safe_div(measured_drops, measured_arrivals),
        "latency_mean_s": (
            float(np.mean(measured_latencies)) if measured_latencies else None
        ),
        "latency_p95_s": (
            float(np.quantile(measured_latencies, 0.95))
            if measured_latencies
            else None
        ),
        "latency_samples_s": measured_latencies,
        "service_capacity_pps": capacity_pps,
        "buffer_packets": buffer_packets,
        "propagation_delay_s": propagation_delay_s,
        "semantics": "finite FIFO service followed by non-serializing propagation delay",
        "invariant_checks": [
            "accepted + dropped = offered",
            "measurement accepted + measurement dropped = measurement offered",
            "release time - service completion time = propagation delay",
            "service completion spacing >= 1 / service capacity",
        ],
    }


def simulate_tagged_shared_queue(
    benign_arrivals_s: np.ndarray,
    attack_arrivals_s: np.ndarray,
    capacity_pps: float,
    buffer_packets: int,
    propagation_delay_s: float,
    measurement_start_s: float,
    duration_s: float,
) -> dict[str, Any]:
    """Counterfactual FIFO in which benign and attack packets share capacity."""

    events = [
        *( (float(arrival), "benign") for arrival in benign_arrivals_s ),
        *( (float(arrival), "attack") for arrival in attack_arrivals_s ),
    ]
    events.sort(key=lambda item: (item[0], item[1]))
    service_time = 1.0 / capacity_pps
    completions_in_system: deque[float] = deque()
    accepted: list[tuple[float, str, float, float]] = []
    dropped = {"benign": 0, "attack": 0}

    for arrival, label in events:
        while completions_in_system and completions_in_system[0] <= arrival:
            completions_in_system.popleft()
        if len(completions_in_system) >= buffer_packets:
            dropped[label] += 1
            continue
        prior_completion = completions_in_system[-1] if completions_in_system else arrival
        completion = max(arrival, prior_completion) + service_time
        completions_in_system.append(completion)
        accepted.append((arrival, label, completion, completion + propagation_delay_s - arrival))

    offered = {"benign": len(benign_arrivals_s), "attack": len(attack_arrivals_s)}
    accepted_total = {
        label: sum(record[1] == label for record in accepted)
        for label in ("benign", "attack")
    }
    for label in ("benign", "attack"):
        if accepted_total[label] + dropped[label] != offered[label]:
            raise AssertionError(f"tagged queue conservation failed for {label}")

    measurement_duration = duration_s - measurement_start_s
    by_label: dict[str, Any] = {}
    for label, source_arrivals in (
        ("benign", benign_arrivals_s),
        ("attack", attack_arrivals_s),
    ):
        measured_offered = sum(
            measurement_start_s <= value < duration_s for value in source_arrivals
        )
        measured_records = [
            record
            for record in accepted
            if record[1] == label
            and measurement_start_s <= record[0] < duration_s
        ]
        measured_accepted = len(measured_records)
        measured_dropped = measured_offered - measured_accepted
        if measured_accepted + measured_dropped != measured_offered:
            raise AssertionError(f"tagged measurement conservation failed for {label}")
        departure_count = sum(
            record[1] == label
            and measurement_start_s <= record[2] < duration_s
            for record in accepted
        )
        latencies = [record[3] for record in measured_records]
        by_label[label] = {
            "offered_packet_count": offered[label],
            "accepted_packet_count": accepted_total[label],
            "dropped_packet_count": dropped[label],
            "measurement_offered_packet_count": measured_offered,
            "measurement_accepted_packet_count": measured_accepted,
            "measurement_dropped_packet_count": measured_dropped,
            "service_departure_rate_pps": departure_count / measurement_duration,
            "drop_fraction": _safe_div(measured_dropped, measured_offered),
            "latency_mean_s": float(np.mean(latencies)) if latencies else None,
        }

    total_departure_rate = (
        by_label["benign"]["service_departure_rate_pps"]
        + by_label["attack"]["service_departure_rate_pps"]
    )
    if total_departure_rate > capacity_pps * 1.01:
        raise AssertionError("tagged shared queue exceeded configured service capacity")
    return {
        "scope": "counterfactual shared finite FIFO",
        "capacity_pps": capacity_pps,
        "buffer_packets": buffer_packets,
        "propagation_delay_s": propagation_delay_s,
        "by_label": by_label,
        "invariant_checks": [
            "per-label accepted + dropped = offered",
            "per-label measurement accepted + dropped = offered",
            "aggregate departures <= configured capacity (sampling tolerance)",
        ],
    }


def _mean_ci95(values: Sequence[float]) -> dict[str, Any]:
    array = np.asarray(values, dtype=float)
    mean = float(np.mean(array))
    if len(array) <= 1:
        interval = [mean, mean]
    else:
        half_width = 1.959963984540054 * float(np.std(array, ddof=1)) / math.sqrt(len(array))
        interval = [mean - half_width, mean + half_width]
    return {"mean": mean, "ci95_normal_across_seeds": interval}


def isolation_evaluation(config: ExperimentConfig, raw_dir: Path) -> dict[str, Any]:
    pooled_by_load: dict[float, dict[str, list[float]]] = {
        load: {
            "fast_departure": [],
            "fast_latency": [],
            "quarantine_departure": [],
            "quarantine_latency": [],
            "quarantine_drop_fraction": [],
            "shared_benign_departure": [],
            "shared_benign_latency": [],
            "shared_benign_drop_fraction": [],
        }
        for load in config.quarantine_offered_loads_pps
    }
    baseline_latency_samples_ms: list[float] = []
    isolated_fast_latency_samples_ms: list[float] = []
    quarantine_latency_samples_ms: list[float] = []
    representative_load = 200.0

    for seed in config.test_seeds:
        fast_rng = np.random.default_rng(seed + 200_000)
        fast_arrivals = poisson_arrivals(
            fast_rng,
            config.fast_benign_offered_pps,
            config.queue_duration_s,
        )
        baseline = simulate_finite_queue(
            fast_arrivals,
            config.fast_capacity_pps,
            config.fast_buffer_packets,
            config.fast_propagation_delay_s,
            config.queue_measurement_start_s,
            config.queue_duration_s,
        )
        # The isolated fast path sees the exact same arrivals and resources.
        # Classifier processing cost is intentionally outside this queue model.
        isolated_fast = simulate_finite_queue(
            fast_arrivals,
            config.fast_capacity_pps,
            config.fast_buffer_packets,
            config.fast_propagation_delay_s,
            config.queue_measurement_start_s,
            config.queue_duration_s,
        )

        sample_limit = config.latency_sample_limit_per_seed
        baseline_latency_samples_ms.extend(
            1000.0 * value for value in baseline["latency_samples_s"][:sample_limit]
        )
        isolated_fast_latency_samples_ms.extend(
            1000.0 * value for value in isolated_fast["latency_samples_s"][:sample_limit]
        )

        seed_rows = []
        for load_index, offered_load in enumerate(config.quarantine_offered_loads_pps):
            quarantine_rng = np.random.default_rng(seed * 10_000 + load_index + 700_000)
            attack_arrivals = poisson_arrivals(
                quarantine_rng,
                offered_load,
                config.queue_duration_s,
            )
            quarantine = simulate_finite_queue(
                attack_arrivals,
                config.quarantine_capacity_pps,
                config.quarantine_buffer_packets,
                config.quarantine_propagation_delay_s,
                config.queue_measurement_start_s,
                config.queue_duration_s,
            )
            shared_counterfactual = simulate_tagged_shared_queue(
                fast_arrivals,
                attack_arrivals,
                config.fast_capacity_pps,
                config.fast_buffer_packets,
                config.fast_propagation_delay_s,
                config.queue_measurement_start_s,
                config.queue_duration_s,
            )
            values = pooled_by_load[offered_load]
            values["fast_departure"].append(isolated_fast["service_departure_rate_pps"])
            values["fast_latency"].append(isolated_fast["latency_mean_s"])
            values["quarantine_departure"].append(
                quarantine["service_departure_rate_pps"]
            )
            values["quarantine_latency"].append(
                quarantine["latency_mean_s"]
                if quarantine["latency_mean_s"] is not None
                else config.quarantine_propagation_delay_s
            )
            values["quarantine_drop_fraction"].append(quarantine["drop_fraction"])
            shared_benign = shared_counterfactual["by_label"]["benign"]
            values["shared_benign_departure"].append(
                shared_benign["service_departure_rate_pps"]
            )
            values["shared_benign_latency"].append(
                shared_benign["latency_mean_s"]
                if shared_benign["latency_mean_s"] is not None
                else config.fast_propagation_delay_s
            )
            values["shared_benign_drop_fraction"].append(
                shared_benign["drop_fraction"]
            )
            if offered_load == representative_load:
                quarantine_latency_samples_ms.extend(
                    1000.0 * value
                    for value in quarantine["latency_samples_s"][:sample_limit]
                )
            seed_rows.append(
                {
                    "quarantine_offered_load_pps": offered_load,
                    "fast_service_departure_rate_pps": isolated_fast[
                        "service_departure_rate_pps"
                    ],
                    "fast_latency_mean_s": isolated_fast["latency_mean_s"],
                    "quarantine_service_departure_rate_pps": quarantine[
                        "service_departure_rate_pps"
                    ],
                    "quarantine_offered_packet_count": quarantine[
                        "offered_packet_count"
                    ],
                    "quarantine_accepted_packet_count": quarantine[
                        "accepted_packet_count"
                    ],
                    "quarantine_dropped_packet_count": quarantine[
                        "dropped_packet_count"
                    ],
                    "quarantine_measurement_offered_packet_count": quarantine[
                        "measurement_offered_packet_count"
                    ],
                    "quarantine_measurement_accepted_packet_count": quarantine[
                        "measurement_accepted_packet_count"
                    ],
                    "quarantine_measurement_dropped_packet_count": quarantine[
                        "measurement_dropped_packet_count"
                    ],
                    "quarantine_latency_mean_s": quarantine["latency_mean_s"],
                    "quarantine_drop_fraction": quarantine["drop_fraction"],
                    "shared_counterfactual_benign_departure_rate_pps": shared_benign[
                        "service_departure_rate_pps"
                    ],
                    "shared_counterfactual_benign_latency_mean_s": shared_benign[
                        "latency_mean_s"
                    ],
                    "shared_counterfactual_benign_drop_fraction": shared_benign[
                        "drop_fraction"
                    ],
                    "shared_counterfactual_counts": {
                        "benign": shared_counterfactual["by_label"]["benign"],
                        "attack": shared_counterfactual["by_label"]["attack"],
                    },
                    "invariant_checks": {
                        "quarantine": quarantine["invariant_checks"],
                        "shared_counterfactual": shared_counterfactual[
                            "invariant_checks"
                        ],
                    },
                }
            )
        write_json(
            raw_dir / f"isolation_seed_{seed}.json",
            {
                "seed": seed,
                "fast_path_baseline": {
                    key: value
                    for key, value in baseline.items()
                    if key != "latency_samples_s"
                },
                "fast_path_isolated": {
                    key: value
                    for key, value in isolated_fast.items()
                    if key != "latency_samples_s"
                },
                "load_sweep": seed_rows,
            },
        )

    points = []
    for offered_load in config.quarantine_offered_loads_pps:
        values = pooled_by_load[offered_load]
        points.append(
            {
                "quarantine_offered_load_pps": offered_load,
                "fast_service_departure_rate_pps": _mean_ci95(values["fast_departure"]),
                "fast_latency_s": _mean_ci95(values["fast_latency"]),
                "quarantine_service_departure_rate_pps": _mean_ci95(
                    values["quarantine_departure"]
                ),
                "quarantine_latency_s": _mean_ci95(values["quarantine_latency"]),
                "quarantine_drop_fraction": _mean_ci95(
                    values["quarantine_drop_fraction"]
                ),
                "shared_counterfactual_benign_departure_rate_pps": _mean_ci95(
                    values["shared_benign_departure"]
                ),
                "shared_counterfactual_benign_latency_s": _mean_ci95(
                    values["shared_benign_latency"]
                ),
                "shared_counterfactual_benign_drop_fraction": _mean_ci95(
                    values["shared_benign_drop_fraction"]
                ),
            }
        )

    return {
        "scope": (
            "queue-level isolation conditional on traffic already being classified and redirected"
        ),
        "classifier_processing_cost_modeled": False,
        "packet_model": (
            f"equal unit packets ({config.queue_packet_unit_bytes} bytes each); "
            "capacities are expressed in packets per second"
        ),
        "fast_path": {
            "service_capacity_pps": config.fast_capacity_pps,
            "buffer_packets": config.fast_buffer_packets,
            "offered_benign_load_pps": config.fast_benign_offered_pps,
            "propagation_delay_s": config.fast_propagation_delay_s,
        },
        "quarantine_path": {
            "service_capacity_pps": config.quarantine_capacity_pps,
            "buffer_packets": config.quarantine_buffer_packets,
            "propagation_delay_s": config.quarantine_propagation_delay_s,
            "one_way_dwell_delay_s": config.quarantine_propagation_delay_s,
        },
        "service_delay_separation": (
            "C_q serializes service; D_q is appended after service and does not alter departure spacing"
        ),
        "shared_capacity_counterfactual": (
            "same benign and attack arrivals share C_f and K_f without redirection; "
            "included to show the conditional value of capacity isolation"
        ),
        "load_sweep": points,
        "latency_reference_load_pps": representative_load,
        "latency_samples_ms": {
            "no_defense_fast_path": baseline_latency_samples_ms,
            "isolated_fast_path": isolated_fast_latency_samples_ms,
            "quarantine_path": quarantine_latency_samples_ms,
        },
    }


def simulate_tcp_timeout_transient(
    added_rtt_delta_s: float,
    config: ExperimentConfig,
) -> dict[str, Any]:
    """Model the first delayed ACK and RTO backoff of a conforming sender.

    The model starts with one outstanding segment and a pre-change RTO. It
    counts timeout-triggered retransmissions before the original ACK arrives.
    This is a deliberately narrow transient, not a complete TCP stack.
    """

    new_rtt = config.tcp_base_rtt_s + added_rtt_delta_s
    ack_time = new_rtt
    deadline = config.tcp_initial_rto_s
    current_rto = config.tcp_initial_rto_s
    retransmissions = 0
    send_times = [0.0]
    while deadline < ack_time - 1e-12:
        retransmissions += 1
        send_times.append(deadline)
        current_rto = min(config.tcp_max_rto_s, current_rto * 2.0)
        deadline += current_rto

    reference_window_rate = min(
        config.quarantine_capacity_pps,
        config.tcp_reference_window_packets / new_rtt,
    )
    bdp_window_packets = math.ceil(config.quarantine_capacity_pps * new_rtt)
    adequate_window_rate = min(
        config.quarantine_capacity_pps,
        bdp_window_packets / new_rtt,
    )
    return {
        "added_rtt_delta_s": added_rtt_delta_s,
        "new_rtt_s": new_rtt,
        "first_ack_time_s": ack_time,
        "initial_transmissions_before_first_ack": len(send_times),
        "timeout_retransmissions_before_first_ack": retransmissions,
        "transmission_times_s": send_times,
        "backed_off_rto_at_first_ack_s": current_rto,
        "reference_window_packets": config.tcp_reference_window_packets,
        "reference_window_limited_rate_pps": reference_window_rate,
        "bdp_window_packets_for_path_capacity": bdp_window_packets,
        "adequate_window_rate_pps": adequate_window_rate,
    }


def tcp_transient_evaluation(config: ExperimentConfig) -> dict[str, Any]:
    return {
        "scope": (
            "single established conforming flow after an abrupt RTT increase; "
            "initial timeout/backoff only"
        ),
        "model_limitations": [
            "not a packet-accurate TCP implementation",
            "does not model application behavior, loss, receiver limits, or competing flows",
            "does not establish an attacker goodput bound",
        ],
        "steady_state_statement": (
            "Propagation delay alone does not serialize packets. With an adequate "
            "window, modeled rate reaches the explicit path service capacity; a fixed "
            "small window can instead be RTT-limited."
        ),
        "parameters": {
            "base_rtt_s": config.tcp_base_rtt_s,
            "initial_rto_s": config.tcp_initial_rto_s,
            "maximum_rto_s": config.tcp_max_rto_s,
            "path_service_capacity_pps": config.quarantine_capacity_pps,
            "delay_semantics": (
                "Delta_RTT is the abrupt round-trip-time increase and is distinct "
                "from the one-way queue-model dwell D_q"
            ),
        },
        "points": [
            simulate_tcp_timeout_transient(delay, config)
            for delay in config.tcp_added_rtt_values_s
        ],
    }


def validate_summary(summary: dict[str, Any], config: ExperimentConfig) -> list[str]:
    checks: list[str] = []
    if set(config.calibration_seeds) & set(config.test_seeds):
        raise ValueError("Calibration and test seeds overlap")
    checks.append("calibration and held-out test seeds are disjoint")

    classification = summary["classification"]
    confusion = classification["aggregate_confusion"]
    expected_per_label = (
        len(config.test_seeds)
        * config.test_flows_per_type_per_seed
        * len(BENIGN_TYPES)
    )
    if confusion["tn"] + confusion["fp"] != expected_per_label:
        raise ValueError("Benign confusion counts do not match generated test flows")
    if confusion["tp"] + confusion["fn"] != expected_per_label:
        raise ValueError("Attack confusion counts do not match generated test flows")
    checks.append("aggregate confusion matrix accounts for every held-out flow")

    historical_confusion = {"tp": 2043, "fp": 51, "tn": 5949, "fn": 3957}
    if confusion != historical_confusion:
        raise ValueError(
            "preserved baseline confusion changed: "
            f"expected={historical_confusion}, observed={confusion}"
        )
    checks.append(
        "historical negative classifier result reproduced exactly: "
        "TP=2043, FP=51, TN=5949, FN=3957"
    )

    for metric in classification["aggregate_metrics"].values():
        estimate = metric["estimate"]
        low, high = metric["ci95"]
        if not (0.0 <= low <= estimate <= high <= 1.0):
            raise ValueError("A classification confidence interval is invalid")
    checks.append("classification metrics and confidence intervals are bounded")

    isolation = summary["isolation"]
    fast_rates = []
    shared_benign_rates = []
    for point in isolation["load_sweep"]:
        q_rate = point["quarantine_service_departure_rate_pps"]["mean"]
        if q_rate > config.quarantine_capacity_pps * 1.01:
            raise ValueError("Quarantine service departures exceed configured capacity")
        fast_rates.append(point["fast_service_departure_rate_pps"]["mean"])
        shared_benign_rates.append(
            point["shared_counterfactual_benign_departure_rate_pps"]["mean"]
        )
    if max(fast_rates) - min(fast_rates) > 1e-12:
        raise ValueError("Isolated fast-path rate changed with quarantine offered load")
    checks.append("quarantine departures respect C_q and isolated fast rate is invariant")
    if shared_benign_rates[-1] >= fast_rates[-1] * 0.95:
        raise ValueError("Shared-capacity counterfactual did not show high-load contention")
    checks.append("shared-capacity counterfactual shows benign contention at maximum attack load")
    checks.append("per-run queue conservation, service-spacing, and dwell invariants executed")

    for point in summary["tcp_transient"]["points"]:
        if point["adequate_window_rate_pps"] > config.quarantine_capacity_pps + 1e-12:
            raise ValueError("TCP reference calculation exceeds service capacity")
    checks.append("TCP transient is capacity-capped and contains no 1/D security bound")

    return checks


def _dataset_hash(summary_without_hash: dict[str, Any]) -> str:
    canonical = json.dumps(
        summary_without_hash,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=_json_default,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def run_pipeline(
    results_dir: Path = DEFAULT_RESULTS_DIR,
    *,
    config_path: Path = DEFAULT_CONFIG_PATH,
) -> dict[str, Any]:
    """Generate the preserved baseline into a new or empty directory.

    No existing artifact is deleted or replaced.  This function has no
    dashboard path or dashboard side effect.
    """

    input_config_path = Path(config_path).resolve()
    config = load_config(input_config_path)
    results_dir = Path(results_dir).resolve()
    if results_dir.exists():
        if not results_dir.is_dir():
            raise FileExistsError(f"output path is not a directory: {results_dir}")
        if any(results_dir.iterdir()):
            raise FileExistsError(
                f"refusing to overwrite nonempty output directory: {results_dir}"
            )
    else:
        results_dir.mkdir(parents=True, exist_ok=False)
    raw_dir = results_dir / "raw"
    raw_dir.mkdir(parents=False, exist_ok=False)

    calibration_flows: list[FlowObservation] = []
    for seed in config.calibration_seeds:
        flows = generate_flow_observations(
            seed,
            config.calibration_flows_per_type_per_seed,
            config.window_iats,
        )
        calibration_flows.extend(flows)
        write_json(
            raw_dir / f"calibration_seed_{seed}.json",
            {
                "seed": seed,
                "split": "calibration",
                "flows": [asdict(flow) for flow in flows],
            },
        )

    classifier, calibration_summary = calibrate_classifier(calibration_flows, config)

    records_by_seed: dict[int, list[dict[str, Any]]] = {}
    for seed in config.test_seeds:
        flows = generate_flow_observations(
            seed,
            config.test_flows_per_type_per_seed,
            config.window_iats,
        )
        records = prediction_records(flows, classifier)
        records_by_seed[seed] = records
        write_json(
            raw_dir / f"test_seed_{seed}.json",
            {"seed": seed, "split": "held_out_test", "flows": records},
        )

    classification = summarize_classification(records_by_seed, config)
    sensitivity = sensitivity_evaluation(classifier, config, raw_dir)
    isolation = isolation_evaluation(config, raw_dir)
    tcp_transient = tcp_transient_evaluation(config)

    summary_without_hash: dict[str, Any] = {
        "schema_version": config.schema_version,
        "artifact_role": "historical negative timing-only synthetic baseline",
        "claim_scope": (
            "context evidence only; not the primary coupled, public-data, or "
            "packet-level evaluation"
        ),
        "deterministic": True,
        "wall_clock_timestamp_included": False,
        "config": asdict(config),
        "immutable_config": {
            "artifact_path": _display_path(input_config_path),
            "sha256": file_sha256(input_config_path),
            "effective_config_sha256": canonical_sha256(asdict(config)),
        },
        "classifier": asdict(classifier),
        "calibration": calibration_summary,
        "classification": classification,
        "sensitivity": sensitivity,
        "isolation": isolation,
        "tcp_transient": tcp_transient,
        "raw_data": {
            "directory": "raw",
            "format": "per-seed JSON with flow-level features/predictions or queue/sensitivity aggregates",
            "files": [
                f"raw/{path.name}"
                for path in sorted(raw_dir.glob("*.json"))
            ],
        },
        "limitations": [
            "All traffic is synthetic; results do not establish real-world detection accuracy.",
            "The frozen classifier has low held-out recall (2043/6000) and misses 3957/6000 synthetic attacks.",
            "The timing-only classifier overlaps benign automation and paced traffic.",
            "Queue isolation results are conditional on correct prior classification and redirection.",
            "The queue experiment is not coupled to the classifier's false negatives or false positives.",
            "Classifier execution cost and eBPF/XDP feasibility are not benchmarked here.",
            "Propagation delay is not a service time and does not create a universal 1/D goodput bound.",
            "The TCP calculation is a narrow timeout transient, not a packet-accurate stack or DDoS bound.",
        ],
    }
    summary_without_hash["validation_checks"] = validate_summary(
        summary_without_hash, config
    )
    dataset_hash = _dataset_hash(summary_without_hash)
    summary = {**summary_without_hash, "dataset_sha256": dataset_hash}

    summary_path = results_dir / "summary.json"
    write_json(summary_path, summary)
    output_config_path = results_dir / "config.json"
    write_json(output_config_path, asdict(config))
    runtime = runtime_record()
    generated_paths = [
        output_config_path,
        summary_path,
        *sorted(raw_dir.glob("*.json")),
    ]
    manifest = {
        "schema_version": config.schema_version,
        "dataset_sha256": dataset_hash,
        "deterministic": True,
        "timestamp_included": False,
        "artifact_role": "historical negative timing-only synthetic baseline",
        "seed_manifest": {
            "calibration": list(config.calibration_seeds),
            "held_out_test": list(config.test_seeds),
            "bootstrap": config.bootstrap_seed,
            "derived_seed_rule": (
                "sensitivity: test_seed*1000+point_index+17; "
                "fast queue: test_seed+200000; quarantine queue: "
                "test_seed*10000+load_index+700000"
            ),
        },
        "generated_files": {
            path.relative_to(results_dir).as_posix(): file_sha256(path)
            for path in generated_paths
        },
        "inputs": {
            "generator": {
                "artifact_path": _display_path(GENERATOR_PATH),
                "sha256": file_sha256(GENERATOR_PATH),
            },
            "immutable_config": {
                "artifact_path": _display_path(input_config_path),
                "sha256": file_sha256(input_config_path),
                "effective_config_sha256": canonical_sha256(asdict(config)),
            },
            "requirements": {
                "artifact_path": _display_path(REQUIREMENTS_PATH),
                "sha256": file_sha256(REQUIREMENTS_PATH),
            },
            "runtime": runtime,
        },
    }
    write_json(results_dir / "manifest.json", manifest)

    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help="strict immutable JSON configuration",
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=DEFAULT_RESULTS_DIR,
        help="new or empty directory for raw data, summary, and manifest",
    )
    args = parser.parse_args()
    summary = run_pipeline(
        args.results_dir,
        config_path=args.config,
    )
    metrics = summary["classification"]["aggregate_metrics"]
    confusion = summary["classification"]["aggregate_confusion"]
    print(f"dataset_sha256={summary['dataset_sha256']}")
    print(f"variance_threshold_s2={summary['classifier']['variance_threshold_s2']:.9g}")
    print(f"confusion={confusion}")
    print(
        "held_out_f1="
        f"{metrics['f1']['estimate']:.4f} "
        f"ci95={metrics['f1']['ci95']}"
    )
    print(f"summary={Path(args.results_dir) / 'summary.json'}")


if __name__ == "__main__":
    main()
