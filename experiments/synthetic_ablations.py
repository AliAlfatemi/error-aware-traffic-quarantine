#!/usr/bin/env python3
"""Deterministic synthetic robustness and selector-state ablations.

This is a simulation-only companion to :mod:`experiments.coupled_simulation`.
It evaluates four deliberately separated questions:

* observation-window sensitivity on disjoint synthetic splits;
* logical selector-state scaling under bounded LRU capacity and flow churn;
* dense behavior around a calibration-frozen mean-IAT decision boundary; and
* an oracle-after-maturity detector-state restart with fail-open/fail-closed
  reacquisition policies and finite FAST/QUAR byte queues.

Logical state bytes and state-operation counts are accounting-model outputs,
not measurements of Python, eBPF, kernel-map, CPU, or NIC behavior.  Likewise,
TCP-like and UDP-like remain workload annotations rather than transport stacks.
The CLI requires explicit output and refuses to overwrite a non-empty path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import sys
from collections import OrderedDict, defaultdict
from dataclasses import asdict, dataclass, fields, replace
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np

from experiments.coupled_simulation import (
    CoupledConfig,
    FlowTrace,
    PacketEvent,
    SelectorModel,
    _FiniteByteQueue,
    canonical_json_sha256,
    decisions_for_flows,
    fit_selectors,
    generate_flows,
    packet_events,
    sha256_file,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "configs" / "synthetic_ablations.json"
DEFAULT_COUPLED_CONFIG = ROOT / "configs" / "coupled_simulation.json"
REQUIREMENTS_PATH = ROOT / "requirements.txt"
KNOWN_SELECTORS = {
    "rate_only", "variance_only", "current_or_timing", "multifeature", "oracle"
}
FAILURE_SCENARIOS = ("no_failure", "restart_fail_open", "restart_fail_closed")
BOUNDARY_SCENARIOS = (
    "benign_stationary",
    "attack_stationary",
    "attack_window_aware_tail_acceleration",
)


@dataclass(frozen=True)
class AblationConfig:
    schema_version: str
    train_seeds: tuple[int, ...]
    calibration_seeds: tuple[int, ...]
    heldout_seeds: tuple[int, ...]
    observation_windows_iats: tuple[int, ...]
    reference_window_iats: int
    selectors: tuple[str, ...]
    boundary_window_iats: int
    boundary_selectors: tuple[str, ...]
    boundary_points: int
    boundary_half_width_fraction: float
    boundary_jitter_cvs: tuple[float, ...]
    boundary_phase_fractions: tuple[float, ...]
    boundary_tail_iats: int
    state_cardinalities: tuple[int, ...]
    state_map_capacity_entries: int
    state_start_spread_s: float
    state_lifetime_s: float
    state_long_flow_fraction: float
    state_short_packet_min: int
    state_short_packet_max: int
    state_entry_fixed_bytes: int
    state_iat_sample_bytes: int
    state_packet_size_sample_bytes: int
    failure_start_s: float
    failure_downtime_s: float
    failure_attack_scale: float
    failure_map_capacity_entries: int
    bootstrap_replicates: int
    bootstrap_seed: int

    def __post_init__(self) -> None:
        tuple_names = (
            "train_seeds", "calibration_seeds", "heldout_seeds",
            "observation_windows_iats", "selectors", "boundary_selectors",
            "boundary_jitter_cvs", "boundary_phase_fractions", "state_cardinalities",
        )
        if any(not isinstance(getattr(self, name), tuple) for name in tuple_names):
            raise TypeError("all seed, selector, window, and sweep collections must be tuples")
        seed_sets = (set(self.train_seeds), set(self.calibration_seeds), set(self.heldout_seeds))
        seed_values = (self.train_seeds, self.calibration_seeds, self.heldout_seeds)
        if any(len(values) != len(unique) for values, unique in zip(seed_values, seed_sets)):
            raise ValueError("seeds must be unique within each split")
        if any(seed_sets[i] & seed_sets[j] for i in range(3) for j in range(i + 1, 3)):
            raise ValueError("training, calibration, and held-out seeds must be disjoint")
        if len(self.heldout_seeds) < 30:
            raise ValueError("the authoritative configuration requires at least 30 held-out seeds")
        if tuple(sorted(set(self.observation_windows_iats))) != self.observation_windows_iats:
            raise ValueError("observation windows must be unique and strictly increasing")
        if any(window < 2 for window in self.observation_windows_iats):
            raise ValueError("observation windows require at least two IATs")
        if self.reference_window_iats not in self.observation_windows_iats:
            raise ValueError("reference window must occur in the observation-window sweep")
        if self.boundary_window_iats not in self.observation_windows_iats:
            raise ValueError("boundary window must occur in the observation-window sweep")
        if not self.selectors or set(self.selectors) - KNOWN_SELECTORS:
            raise ValueError("unknown or empty selector list")
        if not self.boundary_selectors or set(self.boundary_selectors) - set(self.selectors):
            raise ValueError("boundary selectors must be a non-empty subset of selectors")
        if "rate_only" not in self.boundary_selectors:
            raise ValueError("the dense comparator audit requires the calibrated rate-only selector")
        if self.boundary_points < 41 or self.boundary_points % 2 != 1:
            raise ValueError("boundary sweep must contain at least 41 points and an exact center")
        if not 0.0 < self.boundary_half_width_fraction < 1.0:
            raise ValueError("boundary half-width fraction must be in (0, 1)")
        if not self.boundary_jitter_cvs or any(
            not math.isfinite(value) or not 0.0 <= value < 0.5
            for value in self.boundary_jitter_cvs
        ):
            raise ValueError("boundary jitter CVs must be finite and in [0, 0.5)")
        if not self.boundary_phase_fractions or any(
            not math.isfinite(value) or not 0.0 <= value < 1.0
            for value in self.boundary_phase_fractions
        ):
            raise ValueError("boundary phases must be finite fractions in [0, 1)")
        if self.boundary_tail_iats < 1:
            raise ValueError("boundary tail must contain at least one IAT")
        if tuple(sorted(set(self.state_cardinalities))) != self.state_cardinalities:
            raise ValueError("state cardinalities must be unique and strictly increasing")
        if any(value <= 0 for value in self.state_cardinalities):
            raise ValueError("state cardinalities must be positive")
        if not (
            min(self.state_cardinalities) < self.state_map_capacity_entries
            < max(self.state_cardinalities)
        ):
            raise ValueError("cardinality sweep must span below and above map capacity")
        required_boundary = {
            self.state_map_capacity_entries - 1,
            self.state_map_capacity_entries,
            self.state_map_capacity_entries + 1,
        }
        if not required_boundary.issubset(self.state_cardinalities):
            raise ValueError("cardinality sweep must include capacity-1, capacity, and capacity+1")
        positive_ints = (
            self.state_map_capacity_entries, self.state_short_packet_min,
            self.state_short_packet_max, self.state_entry_fixed_bytes,
            self.state_iat_sample_bytes, self.state_packet_size_sample_bytes,
            self.failure_map_capacity_entries, self.bootstrap_replicates,
        )
        if any(value <= 0 for value in positive_ints):
            raise ValueError("integer resource and replication settings must be positive")
        if self.state_short_packet_min > self.state_short_packet_max:
            raise ValueError("short-flow packet bounds are reversed")
        finite = (
            self.state_start_spread_s, self.state_lifetime_s,
            self.state_long_flow_fraction, self.failure_start_s,
            self.failure_downtime_s, self.failure_attack_scale,
        )
        if any(not math.isfinite(value) for value in finite):
            raise ValueError("all floating-point configuration values must be finite")
        if self.state_start_spread_s < 0 or self.state_lifetime_s <= self.state_start_spread_s:
            raise ValueError("state lifetimes must overlap after the start spread")
        if not 0.0 <= self.state_long_flow_fraction <= 1.0:
            raise ValueError("long-flow fraction must be in [0, 1]")
        if self.failure_start_s <= 0 or self.failure_downtime_s <= 0:
            raise ValueError("failure start and downtime must be positive")
        if self.failure_attack_scale <= 0:
            raise ValueError("failure attack scale must be positive")

    def logical_state_bytes_per_entry(self, window_iats: int) -> int:
        """Logical payload only; excludes allocator, hash-table, and map overhead."""

        return (
            self.state_entry_fixed_bytes
            + window_iats * self.state_iat_sample_bytes
            + (window_iats + 1) * self.state_packet_size_sample_bytes
        )


def _tuple_fields() -> set[str]:
    return {
        "train_seeds", "calibration_seeds", "heldout_seeds",
        "observation_windows_iats", "selectors", "boundary_selectors",
        "boundary_jitter_cvs", "boundary_phase_fractions", "state_cardinalities",
    }


def _load_dataclass_json(path: Path, cls: type[Any], tuple_names: set[str]) -> Any:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"configuration must be a JSON object: {path}")
    expected = {field.name for field in fields(cls)}
    missing, extra = expected - set(payload), set(payload) - expected
    if missing or extra:
        raise ValueError(f"configuration keys mismatch; missing={sorted(missing)}, extra={sorted(extra)}")
    converted = {
        key: tuple(value) if key in tuple_names else value
        for key, value in payload.items()
    }
    return cls(**converted)


def load_ablation_config(path: Path = DEFAULT_CONFIG) -> AblationConfig:
    return _load_dataclass_json(Path(path), AblationConfig, _tuple_fields())


def load_coupled_config(path: Path = DEFAULT_COUPLED_CONFIG) -> CoupledConfig:
    tuple_names = {
        "train_seeds", "calibration_seeds", "heldout_seeds", "attack_scale_sweep",
        "quarantine_capacity_sweep_Bps", "quarantine_buffer_sweep_bytes",
        "quarantine_delay_sweep",
    }
    return _load_dataclass_json(Path(path), CoupledConfig, tuple_names)


def _json_default(value: Any) -> Any:
    if isinstance(value, np.integer):
        return int(value)
    if isinstance(value, np.floating):
        return float(value)
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"cannot JSON-serialize {type(value)!r}")


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, allow_nan=False, default=_json_default) + "\n",
        encoding="utf-8",
    )


def _stable_seed(*parts: object) -> int:
    digest = hashlib.sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()
    return int(digest[:16], 16) % (2**63 - 1)


def _rate_metrics(counts: Mapping[str, int]) -> dict[str, float]:
    tp, fp, tn, fn = (int(counts[name]) for name in ("tp", "fp", "tn", "fn"))
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    return {
        "precision": precision,
        "recall": recall,
        "fpr": fpr,
        "specificity": 1.0 - fpr,
        "f1": 2.0 * precision * recall / max(1e-300, precision + recall),
    }


def _percentile(values: Sequence[float], q: float) -> float | None:
    return float(np.quantile(values, q)) if values else None


def _bootstrap_mean_ci(
    values: Sequence[float], replicates: int, seed: int
) -> dict[str, Any]:
    array = np.asarray(values, dtype=float)
    if not len(array):
        return {"n": 0, "mean": None, "median": None, "ci95_bootstrap": [None, None]}
    if not np.all(np.isfinite(array)):
        raise ValueError("bootstrap input contains a non-finite value")
    rng = np.random.default_rng(seed)
    indices = rng.integers(0, len(array), size=(replicates, len(array)))
    samples = np.mean(array[indices], axis=1)
    return {
        "n": int(len(array)),
        "mean": float(np.mean(array)),
        "median": float(np.median(array)),
        "ci95_bootstrap": [
            float(np.quantile(samples, 0.025)),
            float(np.quantile(samples, 0.975)),
        ],
    }


def _wilson_interval(successes: int, total: int) -> list[float | None]:
    if total <= 0:
        return [None, None]
    z = 1.959963984540054
    p = successes / total
    denominator = 1.0 + z * z / total
    center = (p + z * z / (2.0 * total)) / denominator
    half = z * math.sqrt(p * (1.0 - p) / total + z * z / (4.0 * total * total)) / denominator
    return [max(0.0, center - half), min(1.0, center + half)]


def build_provenance(
    config: AblationConfig,
    config_path: Path,
    coupled_config: CoupledConfig,
    coupled_config_path: Path,
) -> dict[str, Any]:
    dependencies = {"numpy": np.__version__}
    runtime = {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_executable_name": Path(sys.executable).name,
        "platform_system": platform.system(),
        "platform_release": platform.release(),
        "machine": platform.machine(),
    }
    source_files = {
        "experiments/synthetic_ablations.py": sha256_file(Path(__file__)),
        "experiments/coupled_simulation.py": sha256_file(ROOT / "experiments" / "coupled_simulation.py"),
    }
    input_files = {
        "configs/synthetic_ablations.json": sha256_file(config_path),
        "configs/coupled_simulation.json": sha256_file(coupled_config_path),
        "requirements.txt": sha256_file(REQUIREMENTS_PATH),
    }
    payload: dict[str, Any] = {
        "config_is_frozen_dataclass": True,
        "ablation_config_canonical_sha256": canonical_json_sha256(asdict(config)),
        "coupled_config_canonical_sha256": canonical_json_sha256(asdict(coupled_config)),
        "input_file_sha256": input_files,
        "input_file_fingerprint_sha256": canonical_json_sha256(input_files),
        "source_sha256": source_files,
        "source_fingerprint_sha256": canonical_json_sha256(source_files),
        "dependencies": dependencies,
        "dependency_fingerprint_sha256": canonical_json_sha256(dependencies),
        "runtime": runtime,
        "runtime_fingerprint_sha256": canonical_json_sha256(runtime),
    }
    payload["combined_input_fingerprint_sha256"] = canonical_json_sha256({
        "ablation_config": payload["ablation_config_canonical_sha256"],
        "coupled_config": payload["coupled_config_canonical_sha256"],
        "input_files": payload["input_file_fingerprint_sha256"],
        "sources": payload["source_fingerprint_sha256"],
        "dependencies": payload["dependency_fingerprint_sha256"],
        "runtime": payload["runtime_fingerprint_sha256"],
    })
    return payload


def _coupled_for_ablation(base: CoupledConfig, config: AblationConfig, window: int) -> CoupledConfig:
    return replace(
        base,
        window_iats=window,
        train_seeds=config.train_seeds,
        calibration_seeds=config.calibration_seeds,
        heldout_seeds=config.heldout_seeds,
    )


def fit_window_models(
    config: AblationConfig, coupled: CoupledConfig
) -> tuple[dict[int, dict[str, SelectorModel]], dict[int, dict[str, Any]]]:
    training: list[FlowTrace] = []
    calibration: list[FlowTrace] = []
    reference = _coupled_for_ablation(coupled, config, config.reference_window_iats)
    for seed in config.train_seeds:
        training.extend(generate_flows(seed, "train", reference, 1.0))
    for seed in config.calibration_seeds:
        calibration.extend(generate_flows(seed, "calibration", reference, 1.0))
    models: dict[int, dict[str, SelectorModel]] = {}
    reports: dict[int, dict[str, Any]] = {}
    for window in config.observation_windows_iats:
        window_config = _coupled_for_ablation(coupled, config, window)
        fitted, report = fit_selectors(training, calibration, window_config)
        models[window] = {name: fitted[name] for name in config.selectors}
        reports[window] = report
    return models, reports


def observation_window_rows(
    seed: int,
    config: AblationConfig,
    coupled: CoupledConfig,
    models_by_window: Mapping[int, Mapping[str, SelectorModel]],
) -> list[dict[str, Any]]:
    reference = _coupled_for_ablation(coupled, config, config.reference_window_iats)
    flows = generate_flows(seed, "heldout", reference, 1.0)
    events = packet_events(flows, reference.duration_s)
    rows: list[dict[str, Any]] = []
    for window in config.observation_windows_iats:
        models = models_by_window[window]
        decisions_by_model = decisions_for_flows(flows, models)
        state_bytes = config.logical_state_bytes_per_entry(window)
        for selector in config.selectors:
            decisions = decisions_by_model[selector]
            all_counts = {name: 0 for name in ("tp", "fp", "tn", "fn")}
            mature_counts = {name: 0 for name in ("tp", "fp", "tn", "fn")}
            decision_delays: list[float] = []
            mature_attack = mature_benign = 0
            for flow in flows:
                decision = decisions[flow.flow_id]
                predicted = bool(decision.mature and decision.predicted_attack)
                key = (
                    "tp" if flow.true_label == "attack" and predicted else
                    "fn" if flow.true_label == "attack" else
                    "fp" if predicted else "tn"
                )
                all_counts[key] += 1
                if decision.mature:
                    mature_attack += flow.true_label == "attack"
                    mature_benign += flow.true_label == "benign"
                    mature_counts[key] += 1
                    if decision.decision_offset_s is not None:
                        decision_delays.append(float(decision.decision_offset_s))
            offered_attack_packets = offered_attack_bytes = 0
            provisional_attack_packets = provisional_attack_bytes = 0
            for event in events:
                if event.true_label != "attack":
                    continue
                offered_attack_packets += 1
                offered_attack_bytes += event.size_bytes
                if event.packet_index < window or not decisions[event.flow_id].mature:
                    provisional_attack_packets += 1
                    provisional_attack_bytes += event.size_bytes
            rates = _rate_metrics(all_counts)
            mature_rates = _rate_metrics(mature_counts)
            rows.append({
                "seed": seed,
                "split": "heldout",
                "window_iats": window,
                "maturity_packets": window + 1,
                "selector": selector,
                "flow_count": len(flows),
                "attack_flow_count": sum(flow.true_label == "attack" for flow in flows),
                "benign_flow_count": sum(flow.true_label == "benign" for flow in flows),
                "mature_flow_count": mature_attack + mature_benign,
                "mature_attack_flow_count": mature_attack,
                "mature_benign_flow_count": mature_benign,
                "mature_flow_fraction": (mature_attack + mature_benign) / max(1, len(flows)),
                **{f"flow_{name}": value for name, value in all_counts.items()},
                **{f"flow_{name}": value for name, value in rates.items()},
                **{f"mature_only_{name}": value for name, value in mature_rates.items()},
                "decision_delay_mean_s": float(np.mean(decision_delays)) if decision_delays else None,
                "decision_delay_p50_s": _percentile(decision_delays, 0.50),
                "decision_delay_p95_s": _percentile(decision_delays, 0.95),
                "offered_attack_packets": offered_attack_packets,
                "offered_attack_bytes": offered_attack_bytes,
                "provisional_attack_fast_packets": provisional_attack_packets,
                "provisional_attack_fast_bytes": provisional_attack_bytes,
                "provisional_attack_packet_fraction": provisional_attack_packets / max(1, offered_attack_packets),
                "provisional_attack_byte_fraction": provisional_attack_bytes / max(1, offered_attack_bytes),
                "logical_state_payload_bytes_per_entry": state_bytes,
                "upper_bound_all_flows_state_payload_bytes": state_bytes * len(flows),
                "scope_note": "flow classification uses complete retained traces; packet leakage is truncated at configured duration",
            })
    return rows


def _boundary_flow(
    seed: int,
    grid_index: int,
    target_mean_s: float,
    jitter_cv: float,
    phase_fraction: float,
    scenario: str,
    window: int,
    tail_iats: int,
) -> FlowTrace:
    if scenario not in BOUNDARY_SCENARIOS:
        raise ValueError(f"unknown boundary scenario {scenario}")
    timing_rng = np.random.default_rng(
        _stable_seed("boundary-timing", seed, grid_index, jitter_cv, phase_fraction)
    )
    feature_rng = np.random.default_rng(
        _stable_seed("boundary-features", seed, grid_index, jitter_cv, phase_fraction, scenario)
    )
    if jitter_cv == 0.0:
        prefix = np.full(window, target_mean_s, dtype=float)
    else:
        # Draw a longer sequence and select a phase-shifted finite window.  The
        # finite-window mean is intentionally not renormalized: phase can move
        # the observed statistic across the frozen comparator.
        noise = np.clip(timing_rng.normal(0.0, 1.0, window * 2), -3.0, 3.0)
        noise = (noise - np.mean(noise)) / max(float(np.std(noise, ddof=1)), 1e-12)
        start = int(round(phase_fraction * window))
        segment = noise[start:start + window]
        prefix = target_mean_s * np.maximum(0.10, 1.0 + jitter_cv * segment)
    if scenario == "attack_window_aware_tail_acceleration":
        tail_mean = target_mean_s * 0.20
    else:
        tail_mean = target_mean_s
    tail_noise = timing_rng.normal(0.0, 0.04, tail_iats)
    tail = tail_mean * np.maximum(0.25, 1.0 + tail_noise)
    iats = np.concatenate((prefix, tail))
    offsets = np.concatenate(([0.0], np.cumsum(iats)))
    if scenario == "benign_stationary":
        family, label, protocol = "benign_paced", "benign", "UDP-like"
        sizes = feature_rng.integers(700, 1501, size=len(iats) + 1)
    elif scenario == "attack_stationary":
        family, label, protocol = "attack_jitter", "attack", "UDP-like"
        sizes = feature_rng.integers(64, 1501, size=len(iats) + 1)
    else:
        family, label, protocol = "attack_window_aware", "attack", "TCP-like"
        sizes = feature_rng.integers(500, 1501, size=len(iats) + 1)
    return FlowTrace(
        flow_id=f"boundary:{seed}:{grid_index}:{jitter_cv:g}:{phase_fraction:g}:{scenario}",
        split="heldout_boundary_sensitivity",
        seed=seed,
        family=family,
        true_label=label,
        protocol=protocol,
        start_time_s=0.0,
        iats_s=tuple(float(value) for value in iats),
        arrival_offsets_s=tuple(float(value) for value in offsets),
        packet_sizes_bytes=tuple(int(value) for value in sizes),
    )


def threshold_boundary_rows(
    seed: int,
    config: AblationConfig,
    models: Mapping[str, SelectorModel],
) -> list[dict[str, Any]]:
    rate_threshold = models["rate_only"].rate_threshold_s
    if rate_threshold is None or not math.isfinite(rate_threshold):
        raise ValueError("rate-only branch is disabled; no finite boundary exists to sweep")
    targets = np.linspace(
        rate_threshold * (1.0 - config.boundary_half_width_fraction),
        rate_threshold * (1.0 + config.boundary_half_width_fraction),
        config.boundary_points,
    )
    rows: list[dict[str, Any]] = []
    for grid_index, target in enumerate(targets):
        for jitter_cv in config.boundary_jitter_cvs:
            for phase in config.boundary_phase_fractions:
                for scenario in BOUNDARY_SCENARIOS:
                    flow = _boundary_flow(
                        seed, grid_index, float(target), jitter_cv, phase, scenario,
                        config.boundary_window_iats, config.boundary_tail_iats,
                    )
                    prefix = np.asarray(flow.iats_s[: config.boundary_window_iats], dtype=float)
                    tail = np.asarray(flow.iats_s[config.boundary_window_iats :], dtype=float)
                    effective_mean = float(np.mean(prefix))
                    effective_cv = float(np.std(prefix, ddof=1) / max(effective_mean, 1e-300))
                    for selector in config.boundary_selectors:
                        decision = models[selector].decide(flow)
                        rows.append({
                            "seed": seed,
                            "split": "heldout_boundary_sensitivity",
                            "scenario": scenario,
                            "true_label": flow.true_label,
                            "selector": selector,
                            "window_iats": config.boundary_window_iats,
                            "grid_index": grid_index,
                            "grid_point_count": config.boundary_points,
                            "target_mean_iat_s": float(target),
                            "effective_mean_iat_s": effective_mean,
                            "frozen_rate_threshold_s": rate_threshold,
                            "signed_rate_margin_s": effective_mean - rate_threshold,
                            "normalized_rate_margin": effective_mean / rate_threshold - 1.0,
                            "jitter_cv_target": jitter_cv,
                            "effective_prefix_cv": effective_cv,
                            "phase_fraction": phase,
                            "predecision_timing_prefix_paired_across_scenarios": True,
                            "tail_mean_iat_s": float(np.mean(tail)),
                            "tail_rate_multiplier_vs_prefix": effective_mean / max(float(np.mean(tail)), 1e-300),
                            "predicted_attack": int(decision.predicted_attack),
                            "decision_score": decision.score,
                            "decision_mature": int(decision.mature),
                            "comparison_semantics": "rate-only predicts attack for mean_iat <= frozen threshold; multifeature uses its frozen calibrated score",
                        })
    return rows


def state_cardinality_row(
    seed: int,
    target_flows: int,
    config: AblationConfig,
) -> dict[str, Any]:
    window = config.reference_window_iats
    # Cardinality conditions are nested: a seed's N-flow workload is the exact
    # prefix of its larger-cardinality workload, supporting paired comparison.
    rng = np.random.default_rng(_stable_seed("state-cardinality", seed))
    events: list[tuple[float, str]] = []
    long_flow_count = 0
    for index in range(target_flows):
        flow_id = f"state:{seed}:{target_flows}:{index}"
        start = float(rng.uniform(0.0, config.state_start_spread_s))
        is_long = bool(rng.random() < config.state_long_flow_fraction)
        if is_long:
            packet_count = window + 1
            long_flow_count += 1
        else:
            packet_count = int(rng.integers(
                config.state_short_packet_min, config.state_short_packet_max + 1
            ))
        times = np.linspace(start, start + config.state_lifetime_s, packet_count)
        for packet_index, time_s in enumerate(times):
            # A tiny deterministic offset gives total ordering without
            # materially changing the intended overlapping lifetimes.
            events.append((float(time_s + packet_index * 1e-12), flow_id))
    events.sort(key=lambda item: (item[0], item[1]))

    state: OrderedDict[str, int] = OrderedDict()
    ever_inserted: set[str] = set()
    ever_mature: set[str] = set()
    insertions = reinsertions = evictions = state_progress_packets_lost = 0
    hits = peak_occupancy = mature_transitions = 0
    for _, flow_id in events:
        if flow_id in state:
            hits += 1
            progress = state.pop(flow_id)
        else:
            if len(state) >= config.state_map_capacity_entries:
                _, evicted_progress = state.popitem(last=False)
                evictions += 1
                state_progress_packets_lost += min(evicted_progress, window)
            if flow_id in ever_inserted:
                reinsertions += 1
            else:
                ever_inserted.add(flow_id)
            insertions += 1
            progress = 0
        progress += 1
        state[flow_id] = progress
        if progress == window + 1:
            mature_transitions += 1
            ever_mature.add(flow_id)
        peak_occupancy = max(peak_occupancy, len(state))

    logical_entry_bytes = config.logical_state_bytes_per_entry(window)
    misses = insertions
    if hits + misses != len(events) or insertions != target_flows + reinsertions:
        raise AssertionError("LRU state-operation accounting failed")
    if peak_occupancy > config.state_map_capacity_entries:
        raise AssertionError("bounded LRU exceeded its configured capacity")
    return {
        "seed": seed,
        "split": "heldout_state_scaling",
        "target_concurrent_flows": target_flows,
        "synthetic_flow_lifetimes_overlap": True,
        "cardinality_conditions_share_seeded_nested_prefix": True,
        "state_map_policy": "bounded LRU; eviction discards observation progress",
        "state_map_capacity_entries": config.state_map_capacity_entries,
        "packet_events": len(events),
        "long_flows_eligible_for_maturity": long_flow_count,
        "peak_occupancy_entries": peak_occupancy,
        "peak_occupancy_fraction": peak_occupancy / config.state_map_capacity_entries,
        "logical_state_payload_bytes_per_entry": logical_entry_bytes,
        "peak_logical_state_payload_bytes": peak_occupancy * logical_entry_bytes,
        "configured_logical_state_payload_capacity_bytes": config.state_map_capacity_entries * logical_entry_bytes,
        "state_lookups": len(events),
        "state_updates": len(events),
        "state_hits": hits,
        "state_misses": misses,
        "state_insertions": insertions,
        "state_reinsertions_after_eviction": reinsertions,
        "state_evictions": evictions,
        "map_allocation_failures": 0,
        "state_progress_packets_lost": state_progress_packets_lost,
        "mature_transitions": mature_transitions,
        "flows_ever_mature": len(ever_mature),
        "eligible_flow_maturation_fraction": len(ever_mature) / max(1, long_flow_count),
        "operation_count_note": "algorithmic event counts, not measured CPU time or throughput",
    }


def _failure_route(policy: str) -> str:
    if policy == "fail_open":
        return "fast"
    if policy == "fail_closed":
        return "quarantine"
    raise ValueError(f"unknown failure policy {policy}")


def detector_failure_row(
    seed: int,
    scenario: str,
    config: AblationConfig,
    coupled: CoupledConfig,
) -> dict[str, Any]:
    if scenario not in FAILURE_SCENARIOS:
        raise ValueError(f"unknown failure scenario {scenario}")
    run_config = _coupled_for_ablation(coupled, config, config.reference_window_iats)
    flows = generate_flows(seed, "heldout_failure", run_config, config.failure_attack_scale)
    events = packet_events(flows, run_config.duration_s)
    state: OrderedDict[str, int] = OrderedDict()
    fast = _FiniteByteQueue(run_config.fast_capacity_Bps, run_config.fast_buffer_bytes)
    quarantine = _FiniteByteQueue(
        run_config.quarantine_capacity_Bps, run_config.quarantine_buffer_bytes
    )
    restore_s = config.failure_start_s + config.failure_downtime_s
    policy = (
        "none" if scenario == "no_failure" else
        "fail_open" if scenario == "restart_fail_open" else "fail_closed"
    )
    failure_applied = scenario == "no_failure"
    state_entries_lost = mature_entries_lost = 0
    evictions = state_progress_packets_lost = 0
    peak_occupancy = 0
    route_packets = {label: {route: 0 for route in ("fast", "quarantine")} for label in ("benign", "attack")}
    route_bytes = {label: {route: 0 for route in ("fast", "quarantine")} for label in ("benign", "attack")}
    failure_window_packets = {label: {route: 0 for route in ("fast", "quarantine")} for label in ("benign", "attack")}
    reacquisition_packets = {label: {route: 0 for route in ("fast", "quarantine")} for label in ("benign", "attack")}
    queue_records: list[tuple[PacketEvent, str, bool, float | None]] = []
    rematurity_time: dict[str, float] = {}
    post_restart_seen: set[str] = set()

    for event in events:
        if not failure_applied and event.time_s >= config.failure_start_s:
            state_entries_lost = len(state)
            mature_entries_lost = sum(progress >= run_config.window_iats + 1 for progress in state.values())
            state.clear()
            failure_applied = True

        unavailable = scenario != "no_failure" and config.failure_start_s <= event.time_s < restore_s
        reacquiring = scenario != "no_failure" and event.time_s >= config.failure_start_s
        mature_now = False
        if unavailable:
            route = _failure_route(policy)
        else:
            if event.flow_id in state:
                progress = state.pop(event.flow_id)
            else:
                if len(state) >= config.failure_map_capacity_entries:
                    _, evicted_progress = state.popitem(last=False)
                    evictions += 1
                    state_progress_packets_lost += min(evicted_progress, run_config.window_iats)
                progress = 0
            progress += 1
            state[event.flow_id] = progress
            peak_occupancy = max(peak_occupancy, len(state))
            mature_now = progress >= run_config.window_iats + 1
            if scenario != "no_failure" and event.time_s >= restore_s:
                post_restart_seen.add(event.flow_id)
                if progress == run_config.window_iats + 1:
                    rematurity_time[event.flow_id] = event.time_s
            if mature_now:
                route = "quarantine" if event.true_label == "attack" else "fast"
            elif scenario != "no_failure" and event.time_s >= config.failure_start_s:
                route = _failure_route(policy)
            else:
                route = "fast"

        route_packets[event.true_label][route] += 1
        route_bytes[event.true_label][route] += event.size_bytes
        if unavailable:
            failure_window_packets[event.true_label][route] += 1
        if reacquiring and not mature_now:
            reacquisition_packets[event.true_label][route] += 1
        queue = fast if route == "fast" else quarantine
        delay = run_config.fast_delay_s if route == "fast" else run_config.quarantine_delay_s
        accepted, completion, _ = queue.offer(event, delay)
        queue_records.append((event, route, accepted, completion))

    offered_packets = len(events)
    offered_bytes = sum(event.size_bytes for event in events)
    fast_accounting = fast.accounting()
    quarantine_accounting = quarantine.accounting()
    accepted_packets = int(fast_accounting["accepted_packets"]) + int(quarantine_accounting["accepted_packets"])
    accepted_bytes = int(fast_accounting["accepted_bytes"]) + int(quarantine_accounting["accepted_bytes"])
    dropped_packets = int(fast_accounting["dropped_packets"]) + int(quarantine_accounting["dropped_packets"])
    dropped_bytes = int(fast_accounting["dropped_bytes"]) + int(quarantine_accounting["dropped_bytes"])
    if accepted_packets + dropped_packets != offered_packets or accepted_bytes + dropped_bytes != offered_bytes:
        raise AssertionError("failure queue accounting failed conservation")
    measurement_s = run_config.duration_s - run_config.warmup_s
    completed = [
        record for record in queue_records
        if record[2] and record[3] is not None and run_config.warmup_s <= float(record[3]) < run_config.duration_s
    ]
    benign_fast_bytes = sum(
        event.size_bytes for event, route, _, _ in completed
        if event.true_label == "benign" and route == "fast"
    )
    attack_fast_bytes = sum(
        event.size_bytes for event, route, _, _ in completed
        if event.true_label == "attack" and route == "fast"
    )
    attack_quarantine_bytes = sum(
        event.size_bytes for event, route, _, _ in completed
        if event.true_label == "attack" and route == "quarantine"
    )
    recovery_delays = [time_s - restore_s for time_s in rematurity_time.values()]
    attack_recovery_delays = [
        rematurity_time[flow.flow_id] - restore_s
        for flow in flows
        if flow.true_label == "attack" and flow.flow_id in rematurity_time
    ]
    logical_entry_bytes = config.logical_state_bytes_per_entry(run_config.window_iats)
    return {
        "seed": seed,
        "split": "heldout_failure_recovery",
        "scenario": scenario,
        "detector_model": "synthetic ground-truth oracle only after W-IAT state maturity",
        "failure_policy": policy,
        "failure_start_s": config.failure_start_s if scenario != "no_failure" else None,
        "detector_restore_s": restore_s if scenario != "no_failure" else None,
        "state_reacquisition_policy_applies_until_flow_rematures": scenario != "no_failure",
        "offered_packets": offered_packets,
        "offered_bytes": offered_bytes,
        "fast_routed_packets": sum(values["fast"] for values in route_packets.values()),
        "fast_routed_bytes": sum(values["fast"] for values in route_bytes.values()),
        "quarantine_routed_packets": sum(values["quarantine"] for values in route_packets.values()),
        "quarantine_routed_bytes": sum(values["quarantine"] for values in route_bytes.values()),
        "accepted_packets": accepted_packets,
        "accepted_bytes": accepted_bytes,
        "dropped_packets": dropped_packets,
        "dropped_bytes": dropped_bytes,
        "packet_drop_fraction": dropped_packets / max(1, offered_packets),
        "byte_drop_fraction": dropped_bytes / max(1, offered_bytes),
        "benign_goodput_Bps": benign_fast_bytes / measurement_s,
        "attack_leakage_Bps": attack_fast_bytes / measurement_s,
        "attack_quarantine_departure_Bps": attack_quarantine_bytes / measurement_s,
        "failure_window_attack_fast_packets": failure_window_packets["attack"]["fast"],
        "failure_window_benign_quarantine_packets": failure_window_packets["benign"]["quarantine"],
        "reacquisition_attack_fast_packets": reacquisition_packets["attack"]["fast"],
        "reacquisition_benign_quarantine_packets": reacquisition_packets["benign"]["quarantine"],
        "state_entries_lost_at_restart": state_entries_lost,
        "mature_state_entries_lost_at_restart": mature_entries_lost,
        "state_evictions": evictions,
        "state_progress_packets_lost_to_eviction": state_progress_packets_lost,
        "peak_state_occupancy_entries": peak_occupancy,
        "logical_state_payload_bytes_per_entry": logical_entry_bytes,
        "peak_logical_state_payload_bytes": peak_occupancy * logical_entry_bytes,
        "post_restart_flows_seen": len(post_restart_seen),
        "post_restart_flows_rematured": len(rematurity_time),
        "post_restart_rematuration_fraction": len(rematurity_time) / max(1, len(post_restart_seen)),
        "recovery_delay_mean_s": float(np.mean(recovery_delays)) if recovery_delays else None,
        "recovery_delay_p50_s": _percentile(recovery_delays, 0.50),
        "recovery_delay_p95_s": _percentile(recovery_delays, 0.95),
        "first_attack_rematurity_after_restore_s": min(attack_recovery_delays) if attack_recovery_delays else None,
        "fast_queue": fast_accounting,
        "quarantine_queue": quarantine_accounting,
        "limitations_note": "failure timing, restart, oracle labels, state capacity, and queues are simulated; no process or kernel restart is measured",
    }


def _aggregate_rows(
    rows: Sequence[Mapping[str, Any]],
    group_fields: Sequence[str],
    metric_fields: Sequence[str],
    config: AblationConfig,
    namespace: str,
) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, ...], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[tuple(row[field] for field in group_fields)].append(row)
    output: list[dict[str, Any]] = []
    for key in sorted(groups, key=lambda value: tuple(str(item) for item in value)):
        members = groups[key]
        item = {field: value for field, value in zip(group_fields, key)}
        item["seed_count"] = len({int(row["seed"]) for row in members})
        item["metrics"] = {}
        for metric in metric_fields:
            values = [float(row[metric]) for row in members if row.get(metric) is not None]
            seed_value = _stable_seed(config.bootstrap_seed, namespace, *key, metric)
            item["metrics"][metric] = _bootstrap_mean_ci(
                values, config.bootstrap_replicates, seed_value
            )
        output.append(item)
    return output


def aggregate_observation_rows(
    rows: Sequence[Mapping[str, Any]], config: AblationConfig
) -> dict[str, Any]:
    metrics = (
        "mature_flow_fraction", "flow_precision", "flow_recall", "flow_fpr",
        "flow_specificity", "flow_f1", "mature_only_precision", "mature_only_recall",
        "mature_only_fpr", "decision_delay_mean_s", "decision_delay_p50_s",
        "decision_delay_p95_s", "provisional_attack_fast_packets",
        "provisional_attack_fast_bytes", "provisional_attack_packet_fraction",
        "provisional_attack_byte_fraction", "logical_state_payload_bytes_per_entry",
        "upper_bound_all_flows_state_payload_bytes",
    )
    groups = _aggregate_rows(rows, ("window_iats", "selector"), metrics, config, "window")
    by_key = {(int(row["seed"]), int(row["window_iats"]), str(row["selector"])): row for row in rows}
    effect_metrics = (
        "flow_recall", "flow_fpr", "flow_f1", "provisional_attack_packet_fraction",
        "provisional_attack_byte_fraction", "logical_state_payload_bytes_per_entry",
    )
    effects: list[dict[str, Any]] = []
    for window in config.observation_windows_iats:
        if window == config.reference_window_iats:
            continue
        for selector in config.selectors:
            paired_seeds = [
                seed for seed in config.heldout_seeds
                if (seed, window, selector) in by_key
                and (seed, config.reference_window_iats, selector) in by_key
            ]
            item: dict[str, Any] = {
                "window_iats": window,
                "reference_window_iats": config.reference_window_iats,
                "selector": selector,
                "paired_seed_count": len(paired_seeds),
                "metric_deltas_window_minus_reference": {},
            }
            for metric in effect_metrics:
                deltas = [
                    float(by_key[(seed, window, selector)][metric])
                    - float(by_key[(seed, config.reference_window_iats, selector)][metric])
                    for seed in paired_seeds
                ]
                item["metric_deltas_window_minus_reference"][metric] = _bootstrap_mean_ci(
                    deltas,
                    config.bootstrap_replicates,
                    _stable_seed(config.bootstrap_seed, "window-delta", window, selector, metric),
                )
            effects.append(item)
    return {"groups": groups, "paired_effects": effects}


def aggregate_boundary_rows(
    rows: Sequence[Mapping[str, Any]], config: AblationConfig
) -> dict[str, Any]:
    group_fields = (
        "scenario", "selector", "grid_index", "target_mean_iat_s",
        "jitter_cv_target", "phase_fraction",
    )
    groups: dict[tuple[Any, ...], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[tuple(row[field] for field in group_fields)].append(row)
    output: list[dict[str, Any]] = []
    for key in sorted(groups, key=lambda value: tuple(str(item) for item in value)):
        members = groups[key]
        successes = sum(int(row["predicted_attack"]) for row in members)
        scores = [float(row["decision_score"]) for row in members if row["decision_score"] is not None]
        item = {field: value for field, value in zip(group_fields, key)}
        item.update({
            "seed_count": len({int(row["seed"]) for row in members}),
            "effective_mean_iat_s": {
                "mean": float(np.mean([float(row["effective_mean_iat_s"]) for row in members])),
                "min": float(np.min([float(row["effective_mean_iat_s"]) for row in members])),
                "max": float(np.max([float(row["effective_mean_iat_s"]) for row in members])),
            },
            "predicted_attack_probability": successes / max(1, len(members)),
            "predicted_attack_count": successes,
            "trial_count": len(members),
            "ci95_wilson": _wilson_interval(successes, len(members)),
            "decision_score": _bootstrap_mean_ci(
                scores,
                config.bootstrap_replicates,
                _stable_seed(config.bootstrap_seed, "boundary-score", *key),
            ),
        })
        output.append(item)
    return {
        "groups": output,
        "boundary_rule": "rate-only uses <=; the center point is retained to expose equality behavior",
        "binary_interval_method": "Wilson score interval for a binomial proportion",
    }


def aggregate_cardinality_rows(
    rows: Sequence[Mapping[str, Any]], config: AblationConfig
) -> dict[str, Any]:
    metrics = (
        "packet_events", "peak_occupancy_entries", "peak_occupancy_fraction",
        "peak_logical_state_payload_bytes", "state_hits", "state_misses",
        "state_insertions", "state_reinsertions_after_eviction", "state_evictions",
        "state_progress_packets_lost", "mature_transitions", "flows_ever_mature",
        "eligible_flow_maturation_fraction",
    )
    groups = _aggregate_rows(
        rows, ("target_concurrent_flows",), metrics, config, "cardinality"
    )
    by_key = {
        (int(row["seed"]), int(row["target_concurrent_flows"])): row
        for row in rows
    }
    effect_metrics = (
        "state_evictions", "state_reinsertions_after_eviction",
        "state_progress_packets_lost", "eligible_flow_maturation_fraction",
    )
    boundary_effects: list[dict[str, Any]] = []
    comparisons = (
        (config.state_map_capacity_entries - 1, config.state_map_capacity_entries),
        (config.state_map_capacity_entries, config.state_map_capacity_entries + 1),
    )
    for reference, cardinality in comparisons:
        paired_seeds = [
            seed for seed in config.heldout_seeds
            if (seed, reference) in by_key and (seed, cardinality) in by_key
        ]
        item: dict[str, Any] = {
            "target_concurrent_flows": cardinality,
            "reference_concurrent_flows": reference,
            "paired_seed_count": len(paired_seeds),
            "metric_deltas_target_minus_reference": {},
        }
        for metric in effect_metrics:
            deltas = [
                float(by_key[(seed, cardinality)][metric])
                - float(by_key[(seed, reference)][metric])
                for seed in paired_seeds
            ]
            item["metric_deltas_target_minus_reference"][metric] = _bootstrap_mean_ci(
                deltas,
                config.bootstrap_replicates,
                _stable_seed(
                    config.bootstrap_seed, "cardinality-boundary-delta",
                    reference, cardinality, metric,
                ),
            )
        boundary_effects.append(item)
    return {"groups": groups, "paired_capacity_boundary_effects": boundary_effects}


def aggregate_failure_rows(
    rows: Sequence[Mapping[str, Any]], config: AblationConfig
) -> dict[str, Any]:
    metrics = (
        "packet_drop_fraction", "byte_drop_fraction", "benign_goodput_Bps",
        "attack_leakage_Bps", "attack_quarantine_departure_Bps",
        "failure_window_attack_fast_packets", "failure_window_benign_quarantine_packets",
        "reacquisition_attack_fast_packets", "reacquisition_benign_quarantine_packets",
        "state_entries_lost_at_restart", "mature_state_entries_lost_at_restart",
        "state_evictions", "state_progress_packets_lost_to_eviction",
        "peak_state_occupancy_entries", "peak_logical_state_payload_bytes",
        "post_restart_flows_rematured", "post_restart_rematuration_fraction",
        "recovery_delay_mean_s", "recovery_delay_p50_s", "recovery_delay_p95_s",
        "first_attack_rematurity_after_restore_s",
    )
    groups = _aggregate_rows(rows, ("scenario",), metrics, config, "failure")
    by_key = {(int(row["seed"]), str(row["scenario"])): row for row in rows}
    effect_metrics = (
        "benign_goodput_Bps", "attack_leakage_Bps", "packet_drop_fraction",
        "reacquisition_attack_fast_packets", "reacquisition_benign_quarantine_packets",
    )
    effects: list[dict[str, Any]] = []
    for scenario in FAILURE_SCENARIOS[1:]:
        paired_seeds = [
            seed for seed in config.heldout_seeds
            if (seed, scenario) in by_key and (seed, "no_failure") in by_key
        ]
        item: dict[str, Any] = {
            "scenario": scenario,
            "reference": "no_failure",
            "paired_seed_count": len(paired_seeds),
            "metric_deltas_scenario_minus_reference": {},
        }
        for metric in effect_metrics:
            deltas = [
                float(by_key[(seed, scenario)][metric])
                - float(by_key[(seed, "no_failure")][metric])
                for seed in paired_seeds
            ]
            item["metric_deltas_scenario_minus_reference"][metric] = _bootstrap_mean_ci(
                deltas,
                config.bootstrap_replicates,
                _stable_seed(config.bootstrap_seed, "failure-delta", scenario, metric),
            )
        effects.append(item)
    return {"groups": groups, "paired_effects": effects}


def run_seed_trials(
    seed: int,
    config: AblationConfig,
    coupled: CoupledConfig,
    models_by_window: Mapping[int, Mapping[str, SelectorModel]],
) -> dict[str, Any]:
    boundary_models = models_by_window[config.boundary_window_iats]
    return {
        "seed": seed,
        "observation_window_trials": observation_window_rows(
            seed, config, coupled, models_by_window
        ),
        "threshold_boundary_trials": threshold_boundary_rows(
            seed, config, boundary_models
        ),
        "state_cardinality_trials": [
            state_cardinality_row(seed, cardinality, config)
            for cardinality in config.state_cardinalities
        ],
        "detector_failure_trials": [
            detector_failure_row(seed, scenario, config, coupled)
            for scenario in FAILURE_SCENARIOS
        ],
    }


def _assert_inputs_unchanged(
    provenance: Mapping[str, Any],
    config: AblationConfig,
    config_path: Path,
    coupled: CoupledConfig,
    coupled_config_path: Path,
) -> None:
    if canonical_json_sha256(asdict(config)) != provenance["ablation_config_canonical_sha256"]:
        raise AssertionError("frozen ablation configuration changed during execution")
    if canonical_json_sha256(asdict(coupled)) != provenance["coupled_config_canonical_sha256"]:
        raise AssertionError("frozen coupled configuration changed during execution")
    current_inputs = {
        "configs/synthetic_ablations.json": sha256_file(config_path),
        "configs/coupled_simulation.json": sha256_file(coupled_config_path),
        "requirements.txt": sha256_file(REQUIREMENTS_PATH),
    }
    if current_inputs != provenance["input_file_sha256"]:
        raise AssertionError("an input file changed during execution")
    current_sources = {
        "experiments/synthetic_ablations.py": sha256_file(Path(__file__)),
        "experiments/coupled_simulation.py": sha256_file(ROOT / "experiments" / "coupled_simulation.py"),
    }
    if current_sources != provenance["source_sha256"]:
        raise AssertionError("a simulation source file changed during execution")


def run_synthetic_ablations(
    output_dir: Path,
    config_path: Path = DEFAULT_CONFIG,
    coupled_config_path: Path = DEFAULT_COUPLED_CONFIG,
    *,
    seed_subset: Sequence[int] | None = None,
) -> dict[str, Any]:
    """Run the pipeline.

    ``seed_subset`` exists only for reduced developer smoke runs.  Any subset
    output is prominently marked non-authoritative and cannot satisfy the
    configured 30-seed requirement.  The command-line interface does not
    expose this escape hatch.
    """

    output_dir = Path(output_dir)
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {output_dir}")
    config_path = Path(config_path).resolve()
    coupled_config_path = Path(coupled_config_path).resolve()
    config = load_ablation_config(config_path)
    coupled = load_coupled_config(coupled_config_path)
    if not 0.0 < config.failure_start_s < config.failure_start_s + config.failure_downtime_s < coupled.duration_s:
        raise ValueError("failure and restoration must occur inside the coupled run duration")
    if coupled.window_iats != config.reference_window_iats:
        raise ValueError("coupled and ablation reference windows disagree")
    selected_seeds = tuple(config.heldout_seeds if seed_subset is None else seed_subset)
    if not selected_seeds or set(selected_seeds) - set(config.heldout_seeds):
        raise ValueError("seed subset must be non-empty and drawn only from held-out seeds")
    authoritative = seed_subset is None and selected_seeds == config.heldout_seeds

    output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = output_dir / "raw"
    raw_dir.mkdir()
    provenance = build_provenance(config, config_path, coupled, coupled_config_path)
    write_json(output_dir / "config.json", asdict(config))
    write_json(output_dir / "coupled_config.json", asdict(coupled))
    models_by_window, calibration_reports = fit_window_models(config, coupled)
    model_payload = {
        "models_by_window": {
            str(window): {name: asdict(model) for name, model in models.items()}
            for window, models in models_by_window.items()
        },
        "calibration_by_window": {str(window): report for window, report in calibration_reports.items()},
        "split_rule": "all thresholds/models use only configured train and calibration seeds",
    }
    write_json(output_dir / "selector_models.json", model_payload)

    seed_runs: list[dict[str, Any]] = []
    for seed in selected_seeds:
        seed_run = run_seed_trials(seed, config, coupled, models_by_window)
        seed_runs.append(seed_run)
        write_json(raw_dir / f"heldout_seed_{seed}.json", seed_run)
    observation = [row for run in seed_runs for row in run["observation_window_trials"]]
    boundary = [row for run in seed_runs for row in run["threshold_boundary_trials"]]
    cardinality = [row for run in seed_runs for row in run["state_cardinality_trials"]]
    failure = [row for run in seed_runs for row in run["detector_failure_trials"]]
    _assert_inputs_unchanged(provenance, config, config_path, coupled, coupled_config_path)

    summary = {
        "schema_version": config.schema_version,
        "run_scope": "authoritative_heldout" if authoritative else "non_authoritative_reduced_smoke",
        "authoritative": authoritative,
        "deterministic_given_input_fingerprint": True,
        "wall_clock_timestamp_included": False,
        "provenance": provenance,
        "split_integrity": {
            "train_seeds": list(config.train_seeds),
            "calibration_seeds": list(config.calibration_seeds),
            "configured_heldout_seeds": list(config.heldout_seeds),
            "executed_heldout_seeds": list(selected_seeds),
            "executed_seed_count": len(selected_seeds),
            "pairwise_disjoint": True,
            "thresholds_selected_without_heldout_data": True,
        },
        "observation_window_sensitivity": aggregate_observation_rows(observation, config),
        "threshold_boundary_sensitivity": aggregate_boundary_rows(boundary, config),
        "state_cardinality_scaling": aggregate_cardinality_rows(cardinality, config),
        "detector_failure_recovery": aggregate_failure_rows(failure, config),
        "statistical_scope": {
            "continuous_interval_method": f"paired-seed percentile bootstrap of means; {config.bootstrap_replicates} resamples",
            "binary_boundary_interval_method": "Wilson score interval",
            "effect_sizes": "paired absolute differences relative to W=20 or no-failure reference",
            "hypothesis_tests": "none",
            "multiplicity": "no p-values or family-wise significance claims are made; intervals are descriptive and unadjusted",
        },
        "accounting_definitions": {
            "logical_state_bytes": "fixed logical fields + W eight-byte IAT samples + W+1 eight-byte packet-size samples; excludes all implementation overhead",
            "state_operations": "simulated lookup/update/insertion/eviction counts, not CPU or throughput measurements",
            "failure_queues": "finite byte-serialized FAST and QUAR servers inherited from coupled_simulation.py",
        },
        "limitations": [
            "Every result in this stage is from deterministic synthetic simulation; there is no packet capture, kernel, XDP, NIC, CPU, or optical measurement.",
            "The cardinality workload models overlapping logical flow lifetimes and bounded LRU state; it does not emulate a kernel map or measure allocator overhead.",
            "Logical state-byte estimates exclude key storage, padding, allocator, hash-table, synchronization, per-CPU, and implementation overhead.",
            "The dense boundary workload is constructed around a calibration-frozen synthetic threshold and is not a prevalence-weighted accuracy estimate.",
            "The failure experiment uses ground-truth labels only after state maturity to isolate restart policy costs; an implementable classifier may recover differently.",
            "Fail-closed means routing provisional traffic to the finite quarantine queue, not universally dropping it.",
            "TCP-like and UDP-like labels do not simulate transport feedback, retransmissions, congestion control, or QUIC.",
            "Bootstrap and Wilson intervals quantify stochastic-seed variation under this generator only and do not establish external validity.",
        ],
    }
    write_json(output_dir / "summary.json", summary)
    generated = [
        output_dir / "config.json", output_dir / "coupled_config.json",
        output_dir / "selector_models.json", output_dir / "summary.json",
        *sorted(raw_dir.glob("*.json")),
    ]
    manifest = {
        "schema_version": config.schema_version,
        "authoritative": authoritative,
        "files": {str(path.relative_to(output_dir)): sha256_file(path) for path in generated},
        "input_provenance": provenance,
    }
    write_json(output_dir / "manifest.json", manifest)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path, help="new or empty output directory")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--coupled-config", type=Path, default=DEFAULT_COUPLED_CONFIG)
    args = parser.parse_args()
    summary = run_synthetic_ablations(args.output_dir, args.config, args.coupled_config)
    print(f"run_scope={summary['run_scope']}")
    print(f"heldout_seeds={summary['split_integrity']['executed_seed_count']}")
    print(f"output_dir={args.output_dir}")


if __name__ == "__main__":
    main()
