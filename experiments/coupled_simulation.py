#!/usr/bin/env python3
"""Deterministic coupled classification-and-queue simulation.

This module is intentionally separate from the manuscript's existing pipeline.
It models synthetic packet traces, a 20-IAT selector observation window, and
finite byte-capacity service domains in one event stream.  Transport labels are
workload annotations only: this is not a TCP or UDP stack implementation.

The CLI requires an explicit output directory and writes per-seed raw JSON,
aggregate JSON, and a content manifest there.  It never writes ``results/`` by
default.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import sys
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, fields, replace
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import numpy as np


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS_PATH = PROJECT_ROOT / "requirements.txt"


BENIGN_FAMILIES = (
    "benign_interactive",
    "benign_automation",
    "benign_paced",
    "benign_flash_crowd",
)
ATTACK_FAMILIES = (
    "attack_volumetric",
    "attack_low_rate",
    "attack_jitter",
    "attack_burst_phase",
    "attack_window_aware",
    "attack_short_flow",
    "attack_churn",
    "attack_flow_multiplication",
)
ALL_FAMILIES = BENIGN_FAMILIES + ATTACK_FAMILIES
SELECTOR_NAMES = (
    "rate_only",
    "variance_only",
    "current_or_timing",
    "multifeature",
    "oracle",
)
DEFENSES = (
    "shared_fifo",
    "shared_aggregate_limiter",
    "static_protocol_priority",
    "drop_on_detection",
    "shared_quarantine",
    "capacity_isolated_quarantine",
)


@dataclass(frozen=True)
class CoupledConfig:
    """Immutable experiment configuration.

    The default held-out split contains 30 independent stochastic seeds.  Test
    seeds are never used while fitting or calibrating a selector.
    """

    schema_version: str = "coupled-1.1"
    window_iats: int = 20
    train_seeds: tuple[int, ...] = (11, 23, 37, 41, 53, 67, 79, 83)
    calibration_seeds: tuple[int, ...] = (101, 211, 307, 401, 503, 601)
    heldout_seeds: tuple[int, ...] = (
        1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061,
        1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123,
        1151, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223,
    )
    flows_per_family: int = 4
    calibration_target_flow_fpr: float = 0.01
    current_rate_threshold_s: float = 0.020
    ridge_penalty: float = 1e-3
    duration_s: float = 12.0
    warmup_s: float = 2.0
    sla_latency_s: float = 0.050
    shared_capacity_Bps: float = 138_000.0
    shared_buffer_bytes: int = 96_000
    aggregate_limiter_capacity_Bps: float = 100_000.0
    fast_capacity_Bps: float = 110_000.0
    fast_buffer_bytes: int = 72_000
    fast_delay_s: float = 0.002
    quarantine_capacity_Bps: float = 28_000.0
    quarantine_buffer_bytes: int = 24_000
    quarantine_delay_s: float = 0.100
    priority_high_protocol: str = "TCP-like"
    attack_scale_sweep: tuple[float, ...] = (0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 12.0)
    quarantine_capacity_sweep_Bps: tuple[float, ...] = (14_000.0, 28_000.0, 56_000.0)
    quarantine_buffer_sweep_bytes: tuple[int, ...] = (12_000, 24_000, 48_000)
    quarantine_delay_sweep: tuple[float, ...] = (0.0, 0.100, 0.500)
    bootstrap_replicates: int = 2000
    bootstrap_seed: int = 884_211

    def __post_init__(self) -> None:
        tuple_fields = (
            "train_seeds", "calibration_seeds", "heldout_seeds",
            "attack_scale_sweep", "quarantine_capacity_sweep_Bps",
            "quarantine_buffer_sweep_bytes", "quarantine_delay_sweep",
        )
        if any(not isinstance(getattr(self, name), tuple) for name in tuple_fields):
            raise TypeError("seed and sweep collections must be tuples to keep the config immutable")
        splits = (set(self.train_seeds), set(self.calibration_seeds), set(self.heldout_seeds))
        if any(len(split) != len(values) for split, values in zip(
            splits, (self.train_seeds, self.calibration_seeds, self.heldout_seeds)
        )):
            raise ValueError("seeds must be unique within each split")
        if any(splits[i] & splits[j] for i in range(3) for j in range(i + 1, 3)):
            raise ValueError("train, calibration, and held-out seeds must be disjoint")
        if len(self.heldout_seeds) < 30:
            raise ValueError("at least 30 held-out stochastic seeds are required")
        if self.window_iats < 2:
            raise ValueError("window_iats must be at least two")
        if self.flows_per_family < 1:
            raise ValueError("flows_per_family must be positive")
        if not 0.0 <= self.calibration_target_flow_fpr < 1.0:
            raise ValueError("calibration FPR target must be in [0, 1)")
        if not 0.0 <= self.warmup_s < self.duration_s:
            raise ValueError("warmup must be inside the run interval")
        finite_scalars = (
            self.calibration_target_flow_fpr,
            self.current_rate_threshold_s,
            self.ridge_penalty,
            self.duration_s,
            self.warmup_s,
            self.sla_latency_s,
            self.shared_capacity_Bps,
            float(self.shared_buffer_bytes),
            self.aggregate_limiter_capacity_Bps,
            self.fast_capacity_Bps,
            float(self.fast_buffer_bytes),
            self.fast_delay_s,
            self.quarantine_capacity_Bps,
            float(self.quarantine_buffer_bytes),
            self.quarantine_delay_s,
            *(float(value) for value in self.attack_scale_sweep),
            *(float(value) for value in self.quarantine_capacity_sweep_Bps),
            *(float(value) for value in self.quarantine_buffer_sweep_bytes),
            *(float(value) for value in self.quarantine_delay_sweep),
        )
        if any(not math.isfinite(value) for value in finite_scalars):
            raise ValueError("all numeric configuration values must be finite")
        positive = (
            self.shared_capacity_Bps,
            self.shared_buffer_bytes,
            self.aggregate_limiter_capacity_Bps,
            self.fast_capacity_Bps,
            self.fast_buffer_bytes,
            self.quarantine_capacity_Bps,
            self.quarantine_buffer_bytes,
        )
        if any(value <= 0 for value in positive):
            raise ValueError("capacities and buffers must be positive")
        if self.current_rate_threshold_s <= 0 or self.ridge_penalty < 0:
            raise ValueError("selector threshold must be positive and ridge penalty nonnegative")
        if self.sla_latency_s <= 0 or self.fast_delay_s < 0 or self.quarantine_delay_s < 0:
            raise ValueError("SLA must be positive and delays must be nonnegative")
        if any(value <= 0 for value in self.attack_scale_sweep):
            raise ValueError("attack scales must be positive")
        if any(value <= 0 for value in self.quarantine_capacity_sweep_Bps):
            raise ValueError("quarantine capacity sweep values must be positive")
        if any(value <= 0 for value in self.quarantine_buffer_sweep_bytes):
            raise ValueError("quarantine buffer sweep values must be positive")
        if any(value < 0 for value in self.quarantine_delay_sweep):
            raise ValueError("quarantine delay sweep values must be nonnegative")
        if self.bootstrap_replicates < 1:
            raise ValueError("bootstrap replicates must be positive")
        if not math.isclose(
            self.shared_capacity_Bps,
            self.fast_capacity_Bps + self.quarantine_capacity_Bps,
            rel_tol=0.0,
            abs_tol=1e-12,
        ):
            raise ValueError("shared capacity must equal FAST + QUAR capacity")
        if self.shared_buffer_bytes != self.fast_buffer_bytes + self.quarantine_buffer_bytes:
            raise ValueError("shared buffer must equal FAST + QUAR buffers")
        if self.aggregate_limiter_capacity_Bps > self.shared_capacity_Bps:
            raise ValueError("aggregate limiter rate cannot exceed matched physical capacity")
        if self.priority_high_protocol not in ("TCP-like", "UDP-like"):
            raise ValueError("priority class must be TCP-like or UDP-like")
        if min(self.attack_scale_sweep) >= 1.0 or max(self.attack_scale_sweep) <= 1.0:
            raise ValueError("attack sweep must include scales below and above one")

    @property
    def maturity_packets(self) -> int:
        return self.window_iats + 1

    @property
    def provisional_packets_before_decision(self) -> int:
        # Packet index W creates IAT W and can use the matured decision.
        return self.window_iats


@dataclass(frozen=True)
class FlowTrace:
    flow_id: str
    split: str
    seed: int
    family: str
    true_label: str
    protocol: str
    start_time_s: float
    iats_s: tuple[float, ...]
    arrival_offsets_s: tuple[float, ...]
    packet_sizes_bytes: tuple[int, ...]

    def __post_init__(self) -> None:
        if self.family not in ALL_FAMILIES:
            raise ValueError(f"unknown family {self.family}")
        expected_label = "benign" if self.family in BENIGN_FAMILIES else "attack"
        if self.true_label != expected_label:
            raise ValueError("true label and family disagree")
        if self.protocol not in ("TCP-like", "UDP-like"):
            raise ValueError("protocol is an annotation: TCP-like or UDP-like")
        if len(self.arrival_offsets_s) != len(self.packet_sizes_bytes):
            raise ValueError("one packet size is required per arrival")
        if len(self.iats_s) + 1 != len(self.arrival_offsets_s):
            raise ValueError("N packets require exactly N-1 IATs")
        if not self.arrival_offsets_s or self.arrival_offsets_s[0] != 0.0:
            raise ValueError("the first packet offset must be zero")
        if any(value <= 0 for value in self.iats_s):
            raise ValueError("IATs must be positive")
        if any(size <= 0 for size in self.packet_sizes_bytes):
            raise ValueError("packet sizes must be positive")
        rebuilt = np.concatenate(([0.0], np.cumsum(np.asarray(self.iats_s))))
        if not np.allclose(rebuilt, self.arrival_offsets_s, rtol=0.0, atol=1e-12):
            raise ValueError("arrival offsets must exactly represent the retained IATs")


@dataclass(frozen=True)
class PacketEvent:
    time_s: float
    flow_id: str
    packet_index: int
    size_bytes: int
    true_label: str
    family: str
    protocol: str


@dataclass(frozen=True)
class SelectorDecision:
    selector: str
    flow_id: str
    mature: bool
    predicted_attack: bool
    decision_packet_index: int | None
    decision_offset_s: float | None
    score: float | None
    reason: str


@dataclass(frozen=True)
class SelectorModel:
    name: str
    window_iats: int
    rate_threshold_s: float | None = None
    variance_threshold_s2: float | None = None
    feature_mean: tuple[float, ...] = ()
    feature_scale: tuple[float, ...] = ()
    coefficients: tuple[float, ...] = ()
    intercept: float = 0.0
    score_threshold: float | None = None

    def decide(self, flow: FlowTrace) -> SelectorDecision:
        if len(flow.iats_s) < self.window_iats:
            return SelectorDecision(
                self.name, flow.flow_id, False, False, None, None, None,
                "flow ended before 20-IAT maturity; provisional FAST throughout",
            )
        window = np.asarray(flow.iats_s[: self.window_iats], dtype=float)
        mean_iat = float(np.mean(window))
        variance = float(np.var(window, ddof=1))
        score: float | None = None
        if self.name == "rate_only":
            predicted = self.rate_threshold_s is not None and mean_iat <= self.rate_threshold_s
            reason = (
                "rate branch disabled by calibration"
                if self.rate_threshold_s is None else
                "mean-IAT rate branch" if predicted else "rate branch not triggered"
            )
        elif self.name == "variance_only":
            predicted = self.variance_threshold_s2 is not None and variance <= self.variance_threshold_s2
            reason = (
                "variance branch disabled by calibration"
                if self.variance_threshold_s2 is None else
                "low-variance branch" if predicted else "variance branch not triggered"
            )
        elif self.name == "current_or_timing":
            rate_hit = self.rate_threshold_s is not None and mean_iat <= self.rate_threshold_s
            variance_hit = self.variance_threshold_s2 is not None and variance <= self.variance_threshold_s2
            predicted = rate_hit or variance_hit
            reason = (
                "rate-or-variance branch" if predicted else
                "variance branch disabled; rate branch not triggered"
                if self.variance_threshold_s2 is None else
                "neither timing branch triggered"
            )
        elif self.name == "multifeature":
            vector = feature_vector(flow, self.window_iats)
            mean = np.asarray(self.feature_mean)
            scale = np.asarray(self.feature_scale)
            score = float(np.dot((vector - mean) / scale, self.coefficients) + self.intercept)
            predicted = self.score_threshold is not None and score >= self.score_threshold
            reason = (
                "ridge branch disabled by calibration"
                if self.score_threshold is None else
                "ridge score at or above calibrated threshold" if predicted else
                "ridge score below calibrated threshold"
            )
        elif self.name == "oracle":
            predicted = flow.true_label == "attack"
            score = 1.0 if predicted else 0.0
            reason = "synthetic ground-truth oracle after maturity"
        else:
            raise ValueError(f"unknown selector {self.name}")
        return SelectorDecision(
            self.name,
            flow.flow_id,
            True,
            bool(predicted),
            self.window_iats,
            float(flow.arrival_offsets_s[self.window_iats]),
            score,
            reason,
        )


@dataclass(frozen=True)
class SweepPoint:
    name: str
    attack_scale: float
    quarantine_capacity_Bps: float
    quarantine_buffer_bytes: int
    quarantine_delay_s: float


@dataclass(frozen=True)
class PacketOutcome:
    event: PacketEvent
    destination: str
    status: str
    completion_s: float | None
    release_s: float | None
    latency_s: float | None
    provisional: bool


def _json_default(value: Any) -> Any:
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"cannot serialize {type(value)!r}")


def canonical_json_sha256(payload: Any) -> str:
    """Hash a finite, key-sorted JSON representation of an input object."""

    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=_json_default,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, allow_nan=False, default=_json_default) + "\n",
        encoding="utf-8",
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_config(path: Path) -> CoupledConfig:
    """Load a complete, immutable JSON configuration without silent defaults."""

    path = Path(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError("coupled configuration must be a JSON object")
    expected = {field.name for field in fields(CoupledConfig)}
    supplied = set(payload)
    if supplied != expected:
        missing = sorted(expected - supplied)
        unknown = sorted(supplied - expected)
        raise ValueError(
            f"configuration keys must exactly match CoupledConfig; missing={missing}, unknown={unknown}"
        )
    tuple_fields = {
        "train_seeds", "calibration_seeds", "heldout_seeds",
        "attack_scale_sweep", "quarantine_capacity_sweep_Bps",
        "quarantine_buffer_sweep_bytes", "quarantine_delay_sweep",
    }
    for name in tuple_fields:
        value = payload[name]
        if not isinstance(value, list):
            raise TypeError(f"configuration field {name!r} must be a JSON array")
        payload[name] = tuple(value)
    return CoupledConfig(**payload)


def runtime_provenance(
    config: CoupledConfig,
    config_source_path: Path | None = None,
) -> dict[str, Any]:
    """Return fixed-input, dependency, and runtime fingerprints.

    These hashes identify the execution context; they are not claims that two
    different numerical stacks will produce bit-identical floating-point
    outputs.
    """

    dependencies = {"numpy": np.__version__}
    runtime = {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_executable_name": Path(sys.executable).name,
        "platform_system": platform.system(),
        "platform_release": platform.release(),
        "machine": platform.machine(),
    }
    config_payload = asdict(config)
    source_hash = sha256_file(Path(__file__))
    provenance = {
        "config_is_frozen_dataclass": True,
        "config_canonical_sha256": canonical_json_sha256(config_payload),
        "source_sha256": source_hash,
        "dependencies": dependencies,
        "dependency_fingerprint_sha256": canonical_json_sha256(dependencies),
        "runtime": runtime,
        "runtime_fingerprint_sha256": canonical_json_sha256(runtime),
        "input_config_artifact": (
            {
                "path_as_invoked": str(config_source_path),
                "sha256": sha256_file(config_source_path),
            }
            if config_source_path is not None else None
        ),
        "requirements_artifact": {
            "path": "requirements.txt",
            "sha256": sha256_file(REQUIREMENTS_PATH),
        },
    }
    provenance["combined_input_fingerprint_sha256"] = canonical_json_sha256(
        {
            "config": provenance["config_canonical_sha256"],
            "source": source_hash,
            "dependencies": provenance["dependency_fingerprint_sha256"],
            "runtime": provenance["runtime_fingerprint_sha256"],
            "input_config_file": (
                provenance["input_config_artifact"]["sha256"]
                if provenance["input_config_artifact"] is not None else None
            ),
            "requirements_file": provenance["requirements_artifact"]["sha256"],
        }
    )
    return provenance


def flow_to_dict(flow: FlowTrace) -> dict[str, Any]:
    """Serialize without dropping or rounding any retained packet-level arrays."""

    return asdict(flow)


def _positive_clipped(values: np.ndarray, minimum: float = 1e-5) -> np.ndarray:
    # This is explicitly clipping, not a claim of sampling a truncated normal.
    return np.maximum(minimum, values)


def _packet_sizes(rng: np.random.Generator, family: str, count: int) -> np.ndarray:
    if family in ("benign_interactive", "benign_automation"):
        return rng.integers(96, 1201, size=count)
    if family in ("benign_paced", "benign_flash_crowd"):
        return rng.integers(700, 1501, size=count)
    if family in ("attack_low_rate", "attack_burst_phase", "attack_window_aware"):
        return rng.integers(500, 1501, size=count)
    if family in ("attack_short_flow", "attack_churn"):
        return rng.integers(64, 801, size=count)
    return rng.integers(64, 1501, size=count)


def _protocol_for_family(family: str, index: int) -> str:
    fixed = {
        "benign_interactive": "TCP-like",
        "benign_paced": "UDP-like",
        "benign_flash_crowd": "TCP-like",
        "attack_volumetric": "UDP-like",
        "attack_low_rate": "TCP-like",
        "attack_jitter": "UDP-like",
        "attack_burst_phase": "TCP-like",
        "attack_window_aware": "TCP-like",
        "attack_short_flow": "UDP-like",
        "attack_churn": "TCP-like",
        "attack_flow_multiplication": "UDP-like",
    }
    return fixed.get(family, "TCP-like" if index % 2 == 0 else "UDP-like")


def _family_iats(
    rng: np.random.Generator,
    family: str,
    attack_scale: float,
) -> np.ndarray:
    if family == "benign_interactive":
        count = int(rng.integers(28, 46))
        think = rng.random(count - 1) < rng.uniform(0.20, 0.40)
        values = np.where(
            think,
            rng.lognormal(math.log(0.75), 0.45, count - 1),
            rng.lognormal(math.log(0.055), 0.45, count - 1),
        )
    elif family == "benign_automation":
        count = int(rng.integers(28, 42))
        center = rng.uniform(0.20, 0.75)
        values = rng.normal(center, center * rng.uniform(0.04, 0.20), count - 1)
    elif family == "benign_paced":
        count = int(rng.integers(35, 56))
        center = rng.uniform(0.030, 0.120)
        values = rng.normal(center, center * rng.uniform(0.04, 0.25), count - 1)
    elif family == "benign_flash_crowd":
        count = int(rng.integers(50, 81))
        values = rng.exponential(rng.uniform(0.012, 0.035), count - 1)
    elif family == "attack_volumetric":
        count = int(rng.integers(70, 111))
        center = rng.uniform(0.001, 0.006) / attack_scale
        values = rng.normal(center, center * rng.uniform(0.02, 0.18), count - 1)
    elif family == "attack_low_rate":
        count = int(rng.integers(28, 46))
        center = rng.uniform(0.30, 0.90) / attack_scale
        values = rng.normal(center, rng.uniform(0.002, 0.025), count - 1)
    elif family == "attack_jitter":
        count = int(rng.integers(32, 51))
        center = rng.uniform(0.20, 0.70) / attack_scale
        values = rng.normal(center, rng.uniform(0.025, 0.20), count - 1)
    elif family == "attack_burst_phase":
        count = int(rng.integers(45, 71))
        phase = int(rng.integers(3, 9))
        values = np.asarray([
            rng.uniform(0.15, 0.45) / attack_scale if (i + 1) % phase == 0
            else rng.uniform(0.001, 0.008) / attack_scale
            for i in range(count - 1)
        ])
    elif family == "attack_window_aware":
        count = int(rng.integers(48, 76))
        prefix = rng.lognormal(math.log(0.18), 0.75, 20)
        suffix = rng.normal(0.004 / attack_scale, 0.0005 / attack_scale, count - 21)
        values = np.concatenate((prefix, suffix))
    elif family == "attack_short_flow":
        count = int(rng.integers(5, 19))  # deliberately never reaches 21 packets
        values = rng.exponential(0.008 / attack_scale, count - 1)
    elif family == "attack_churn":
        count = int(rng.integers(8, 27))
        values = rng.exponential(0.010 / attack_scale, count - 1)
    elif family == "attack_flow_multiplication":
        count = int(rng.integers(22, 39))
        center = rng.uniform(0.025, 0.090) / attack_scale
        values = rng.normal(center, center * 0.25, count - 1)
    else:
        raise ValueError(f"unknown family {family}")
    return _positive_clipped(np.asarray(values, dtype=float))


def _make_family_flows(
    rng: np.random.Generator,
    config: CoupledConfig,
    split: str,
    seed: int,
    family: str,
    count: int,
    attack_scale: float,
) -> list[FlowTrace]:
    result: list[FlowTrace] = []
    for index in range(count):
        iats = _family_iats(rng, family, attack_scale)
        packet_count = len(iats) + 1
        offsets = np.concatenate(([0.0], np.cumsum(iats)))
        if family == "benign_flash_crowd":
            start = float(config.duration_s * 0.25 + rng.uniform(0.0, config.duration_s * 0.08))
        else:
            start = float(rng.uniform(0.0, config.duration_s * 0.60))
        sizes = _packet_sizes(rng, family, packet_count)
        scale_tag = "benign" if family in BENIGN_FAMILIES else f"a{attack_scale:g}"
        result.append(
            FlowTrace(
                flow_id=f"{split}:{seed}:{scale_tag}:{family}:{index:04d}",
                split=split,
                seed=seed,
                family=family,
                true_label="benign" if family in BENIGN_FAMILIES else "attack",
                protocol=_protocol_for_family(family, index),
                start_time_s=start,
                iats_s=tuple(float(value) for value in iats),
                arrival_offsets_s=tuple(float(value) for value in offsets),
                packet_sizes_bytes=tuple(int(value) for value in sizes),
            )
        )
    return result


def generate_benign_flows(seed: int, split: str, config: CoupledConfig) -> list[FlowTrace]:
    rng = np.random.default_rng(seed * 1_000_003 + 17)
    flows: list[FlowTrace] = []
    for family in BENIGN_FAMILIES:
        flows.extend(_make_family_flows(rng, config, split, seed, family, config.flows_per_family, 1.0))
    return flows


def generate_attack_flows(
    seed: int,
    split: str,
    config: CoupledConfig,
    attack_scale: float,
) -> list[FlowTrace]:
    if attack_scale <= 0:
        raise ValueError("attack scale must be positive")
    scale_key = int(round(attack_scale * 10_000))
    rng = np.random.default_rng(seed * 2_000_003 + scale_key * 97 + 29)
    flows: list[FlowTrace] = []
    for family in ATTACK_FAMILIES:
        multiplier = 1.0
        if family == "attack_flow_multiplication":
            multiplier = max(1.0, 1.5 * attack_scale)
        elif family == "attack_churn":
            multiplier = max(1.0, attack_scale)
        count = max(1, int(math.ceil(config.flows_per_family * multiplier)))
        flows.extend(_make_family_flows(rng, config, split, seed, family, count, attack_scale))
    return flows


def generate_flows(
    seed: int,
    split: str,
    config: CoupledConfig,
    attack_scale: float = 1.0,
) -> list[FlowTrace]:
    return generate_benign_flows(seed, split, config) + generate_attack_flows(seed, split, config, attack_scale)


def packet_events(flows: Sequence[FlowTrace], duration_s: float) -> list[PacketEvent]:
    events: list[PacketEvent] = []
    for flow in flows:
        for index, (offset, size) in enumerate(zip(flow.arrival_offsets_s, flow.packet_sizes_bytes)):
            time_s = flow.start_time_s + offset
            if 0.0 <= time_s < duration_s:
                events.append(PacketEvent(time_s, flow.flow_id, index, size, flow.true_label, flow.family, flow.protocol))
    events.sort(key=lambda event: (event.time_s, event.flow_id, event.packet_index))
    return events


def feature_vector(flow: FlowTrace, window_iats: int) -> np.ndarray:
    if len(flow.iats_s) < window_iats:
        raise ValueError("features require a mature flow")
    iats = np.asarray(flow.iats_s[:window_iats], dtype=float)
    sizes = np.asarray(flow.packet_sizes_bytes[: window_iats + 1], dtype=float)
    mean = float(np.mean(iats))
    variance = float(np.var(iats, ddof=1))
    cv = math.sqrt(max(variance, 0.0)) / max(mean, 1e-12)
    return np.asarray(
        [
            math.log(max(mean, 1e-12)),
            math.log(max(variance, 1e-16)),
            math.log(max(cv, 1e-12)),
            math.log(max(float(np.quantile(iats, 0.10)), 1e-12)),
            math.log(max(float(np.quantile(iats, 0.90)), 1e-12)),
            float(np.mean(sizes) / 1500.0),
            float(np.std(sizes, ddof=1) / 1500.0),
            1.0 if flow.protocol == "UDP-like" else 0.0,
        ],
        dtype=float,
    )


def _fpr(predicted: np.ndarray, labels: np.ndarray) -> float:
    benign = labels == 0
    return float(np.mean(predicted[benign])) if np.any(benign) else 0.0


def _calibrate_low_threshold(
    values: np.ndarray,
    labels: np.ndarray,
    target_fpr: float,
    forced_attack: np.ndarray | None = None,
) -> float | None:
    candidates = np.unique(values)
    forced = np.zeros_like(labels, dtype=bool) if forced_attack is None else forced_attack
    # ``None`` is an explicit disabled branch.  It is the finite-JSON-safe
    # equivalent of a threshold below every possible observation.
    best: float | None = None
    best_recall = float(np.mean(forced[labels == 1]))
    for candidate in candidates:
        predicted = forced | (values <= candidate)
        if _fpr(predicted, labels) <= target_fpr + 1e-15:
            recall = float(np.mean(predicted[labels == 1]))
            if recall > best_recall + 1e-15 or (
                abs(recall - best_recall) <= 1e-15
                and (best is None or candidate > best)
            ):
                best, best_recall = float(candidate), recall
    return best


def _calibrate_high_threshold(
    values: np.ndarray, labels: np.ndarray, target_fpr: float
) -> float | None:
    candidates = np.unique(values)
    # ``None`` explicitly disables the branch and predicts no attacks.
    best: float | None = None
    best_recall = 0.0
    for candidate in candidates:
        predicted = values >= candidate
        if _fpr(predicted, labels) <= target_fpr + 1e-15:
            recall = float(np.mean(predicted[labels == 1]))
            if recall > best_recall + 1e-15 or (
                abs(recall - best_recall) <= 1e-15
                and (best is None or candidate < best)
            ):
                best, best_recall = float(candidate), recall
    return best


def fit_selectors(
    training_flows: Sequence[FlowTrace],
    calibration_flows: Sequence[FlowTrace],
    config: CoupledConfig,
) -> tuple[dict[str, SelectorModel], dict[str, Any]]:
    train = [flow for flow in training_flows if len(flow.iats_s) >= config.window_iats]
    calibration = [flow for flow in calibration_flows if len(flow.iats_s) >= config.window_iats]
    train_x = np.vstack([feature_vector(flow, config.window_iats) for flow in train])
    train_y01 = np.asarray([flow.true_label == "attack" for flow in train], dtype=int)
    train_y = np.where(train_y01 == 1, 1.0, -1.0)
    feature_mean = np.mean(train_x, axis=0)
    feature_scale = np.std(train_x, axis=0, ddof=1)
    feature_scale = np.where(feature_scale < 1e-12, 1.0, feature_scale)
    z = (train_x - feature_mean) / feature_scale
    design = np.column_stack((np.ones(len(z)), z))
    class_counts = np.bincount(train_y01, minlength=2)
    weights = np.asarray([len(train_y01) / (2.0 * class_counts[value]) for value in train_y01])
    weighted = design * np.sqrt(weights[:, None])
    target = train_y * np.sqrt(weights)
    penalty = np.eye(design.shape[1]) * config.ridge_penalty
    penalty[0, 0] = 0.0
    solution = np.linalg.solve(weighted.T @ weighted + penalty, weighted.T @ target)

    cal_labels = np.asarray([flow.true_label == "attack" for flow in calibration], dtype=int)
    cal_means = np.asarray([np.mean(flow.iats_s[: config.window_iats]) for flow in calibration])
    cal_variances = np.asarray([np.var(flow.iats_s[: config.window_iats], ddof=1) for flow in calibration])
    rate_threshold = _calibrate_low_threshold(cal_means, cal_labels, config.calibration_target_flow_fpr)
    variance_threshold = _calibrate_low_threshold(cal_variances, cal_labels, config.calibration_target_flow_fpr)
    forced_rate = cal_means <= config.current_rate_threshold_s
    current_variance_threshold = _calibrate_low_threshold(
        cal_variances, cal_labels, config.calibration_target_flow_fpr, forced_rate
    )
    cal_x = np.vstack([feature_vector(flow, config.window_iats) for flow in calibration])
    cal_scores = ((cal_x - feature_mean) / feature_scale) @ solution[1:] + solution[0]
    score_threshold = _calibrate_high_threshold(cal_scores, cal_labels, config.calibration_target_flow_fpr)

    models = {
        "rate_only": SelectorModel("rate_only", config.window_iats, rate_threshold_s=rate_threshold),
        "variance_only": SelectorModel("variance_only", config.window_iats, variance_threshold_s2=variance_threshold),
        "current_or_timing": SelectorModel(
            "current_or_timing", config.window_iats,
            rate_threshold_s=config.current_rate_threshold_s,
            variance_threshold_s2=current_variance_threshold,
        ),
        "multifeature": SelectorModel(
            "multifeature", config.window_iats,
            feature_mean=tuple(float(value) for value in feature_mean),
            feature_scale=tuple(float(value) for value in feature_scale),
            coefficients=tuple(float(value) for value in solution[1:]),
            intercept=float(solution[0]),
            score_threshold=score_threshold,
        ),
        "oracle": SelectorModel("oracle", config.window_iats),
    }
    calibration_report: dict[str, Any] = {
        "train_flow_count_mature": len(train),
        "calibration_flow_count_mature": len(calibration),
        "target_flow_fpr": config.calibration_target_flow_fpr,
        "thresholds_selected_without_heldout_data": True,
        "null_threshold_semantics": (
            "JSON null means calibration disabled that branch; it predicts no "
            "attacks rather than encoding an infinite threshold"
        ),
        "models": {},
    }
    for name, model in models.items():
        decisions = [model.decide(flow) for flow in calibration]
        predicted = np.asarray([decision.predicted_attack for decision in decisions])
        calibration_report["models"][name] = {
            "flow_fpr": _fpr(predicted, cal_labels),
            "flow_recall": float(np.mean(predicted[cal_labels == 1])),
        }
    return models, calibration_report


def decisions_for_flows(
    flows: Sequence[FlowTrace], models: Mapping[str, SelectorModel]
) -> dict[str, dict[str, SelectorDecision]]:
    return {
        name: {flow.flow_id: model.decide(flow) for flow in flows}
        for name, model in models.items()
    }


class _FiniteByteQueue:
    def __init__(self, capacity_Bps: float, buffer_bytes: int) -> None:
        if capacity_Bps <= 0 or buffer_bytes <= 0:
            raise ValueError("queue capacity and buffer must be positive")
        self.capacity_Bps = float(capacity_Bps)
        self.buffer_bytes = int(buffer_bytes)
        self._pending: deque[tuple[float, int]] = deque()
        self._bytes_in_system = 0
        self._last_completion = 0.0
        self.accepted_packets = 0
        self.accepted_bytes = 0
        self.dropped_packets = 0
        self.dropped_bytes = 0

    def offer(self, event: PacketEvent, propagation_delay_s: float) -> tuple[bool, float | None, float | None]:
        while self._pending and self._pending[0][0] <= event.time_s:
            _, size = self._pending.popleft()
            self._bytes_in_system -= size
        if self._bytes_in_system + event.size_bytes > self.buffer_bytes:
            self.dropped_packets += 1
            self.dropped_bytes += event.size_bytes
            return False, None, None
        completion = max(event.time_s, self._last_completion) + event.size_bytes / self.capacity_Bps
        self._last_completion = completion
        self._pending.append((completion, event.size_bytes))
        self._bytes_in_system += event.size_bytes
        self.accepted_packets += 1
        self.accepted_bytes += event.size_bytes
        return True, completion, completion + propagation_delay_s

    def accounting(self) -> dict[str, int | float]:
        return {
            "capacity_Bps": self.capacity_Bps,
            "buffer_bytes": self.buffer_bytes,
            "accepted_packets": self.accepted_packets,
            "accepted_bytes": self.accepted_bytes,
            "dropped_packets": self.dropped_packets,
            "dropped_bytes": self.dropped_bytes,
        }


class _StrictPriorityByteQueue:
    """Finite, non-preemptive, work-conserving strict-priority server.

    Priority is assigned only from the declared TCP-like/UDP-like annotation.
    Neither the learned selector nor synthetic benign/attack ground truth is
    consulted.  Both classes share one matched physical capacity and buffer.
    """

    def __init__(self, capacity_Bps: float, buffer_bytes: int, high_protocol: str) -> None:
        if capacity_Bps <= 0 or buffer_bytes <= 0:
            raise ValueError("queue capacity and buffer must be positive")
        if high_protocol not in ("TCP-like", "UDP-like"):
            raise ValueError("high-priority protocol must be TCP-like or UDP-like")
        self.capacity_Bps = float(capacity_Bps)
        self.buffer_bytes = int(buffer_bytes)
        self.high_protocol = high_protocol

    def run(
        self,
        events: Sequence[PacketEvent],
        propagation_delay_s: float,
    ) -> tuple[dict[tuple[str, int], tuple[bool, float | None, float | None]], dict[str, Any]]:
        high: deque[PacketEvent] = deque()
        low: deque[PacketEvent] = deque()
        in_service: PacketEvent | None = None
        completion_s: float | None = None
        bytes_in_system = 0
        results: dict[tuple[str, int], tuple[bool, float | None, float | None]] = {}
        accepted_packets = accepted_bytes = dropped_packets = dropped_bytes = 0
        per_class = {
            "high": {"accepted_packets": 0, "accepted_bytes": 0, "dropped_packets": 0, "dropped_bytes": 0},
            "low": {"accepted_packets": 0, "accepted_bytes": 0, "dropped_packets": 0, "dropped_bytes": 0},
        }

        def class_name(event: PacketEvent) -> str:
            return "high" if event.protocol == self.high_protocol else "low"

        def begin_next(start_s: float) -> None:
            nonlocal in_service, completion_s
            if high:
                in_service = high.popleft()
            elif low:
                in_service = low.popleft()
            else:
                in_service = None
                completion_s = None
                return
            completion_s = start_s + in_service.size_bytes / self.capacity_Bps

        def complete_through(time_s: float) -> None:
            nonlocal in_service, completion_s, bytes_in_system
            while in_service is not None and completion_s is not None and completion_s <= time_s:
                finished = in_service
                finished_completion = completion_s
                bytes_in_system -= finished.size_bytes
                results[(finished.flow_id, finished.packet_index)] = (
                    True,
                    finished_completion,
                    finished_completion + propagation_delay_s,
                )
                begin_next(finished_completion)

        for event in events:
            complete_through(event.time_s)
            class_key = class_name(event)
            if bytes_in_system + event.size_bytes > self.buffer_bytes:
                results[(event.flow_id, event.packet_index)] = (False, None, None)
                dropped_packets += 1
                dropped_bytes += event.size_bytes
                per_class[class_key]["dropped_packets"] += 1
                per_class[class_key]["dropped_bytes"] += event.size_bytes
                continue
            bytes_in_system += event.size_bytes
            accepted_packets += 1
            accepted_bytes += event.size_bytes
            per_class[class_key]["accepted_packets"] += 1
            per_class[class_key]["accepted_bytes"] += event.size_bytes
            if in_service is None:
                in_service = event
                completion_s = event.time_s + event.size_bytes / self.capacity_Bps
            elif class_key == "high":
                high.append(event)
            else:
                low.append(event)

        complete_through(math.inf)
        if bytes_in_system != 0 or in_service is not None or high or low:
            raise AssertionError("strict-priority queue failed to drain")
        if len(results) != len(events):
            raise AssertionError("strict-priority queue lost an event")
        accounting: dict[str, Any] = {
            "capacity_Bps": self.capacity_Bps,
            "buffer_bytes": self.buffer_bytes,
            "discipline": "non-preemptive work-conserving strict priority",
            "high_protocol": self.high_protocol,
            "low_protocol": "UDP-like" if self.high_protocol == "TCP-like" else "TCP-like",
            "accepted_packets": accepted_packets,
            "accepted_bytes": accepted_bytes,
            "dropped_packets": dropped_packets,
            "dropped_bytes": dropped_bytes,
            "per_class": per_class,
        }
        return results, accounting


def classification_accounting(
    flows: Sequence[FlowTrace],
    events: Sequence[PacketEvent],
    decisions: Mapping[str, SelectorDecision],
    window_iats: int,
) -> dict[str, Any]:
    flow_counts = {key: 0 for key in ("tp", "fp", "tn", "fn")}
    for flow in flows:
        decision = decisions[flow.flow_id]
        predicted = decision.mature and decision.predicted_attack
        key = (
            "tp" if flow.true_label == "attack" and predicted else
            "fn" if flow.true_label == "attack" else
            "fp" if predicted else "tn"
        )
        flow_counts[key] += 1

    mature_packet = {key: 0 for key in ("tp", "fp", "tn", "fn")}
    mature_byte = {key: 0 for key in ("tp", "fp", "tn", "fn")}
    total = {label: {"packets": 0, "bytes": 0} for label in ("benign", "attack")}
    provisional = {label: {"packets": 0, "bytes": 0} for label in ("benign", "attack")}
    routed = {
        label: {"fast_packets": 0, "fast_bytes": 0, "detected_packets": 0, "detected_bytes": 0}
        for label in ("benign", "attack")
    }
    for event in events:
        label = event.true_label
        total[label]["packets"] += 1
        total[label]["bytes"] += event.size_bytes
        decision = decisions[event.flow_id]
        is_provisional = event.packet_index < window_iats or not decision.mature
        if is_provisional:
            provisional[label]["packets"] += 1
            provisional[label]["bytes"] += event.size_bytes
            routed[label]["fast_packets"] += 1
            routed[label]["fast_bytes"] += event.size_bytes
            continue
        predicted = decision.predicted_attack
        key = (
            "tp" if label == "attack" and predicted else
            "fn" if label == "attack" else
            "fp" if predicted else "tn"
        )
        mature_packet[key] += 1
        mature_byte[key] += event.size_bytes
        destination = "detected" if predicted else "fast"
        routed[label][f"{destination}_packets"] += 1
        routed[label][f"{destination}_bytes"] += event.size_bytes

    def rates(counts: Mapping[str, int]) -> dict[str, float]:
        return {
            "fpr": counts["fp"] / max(1, counts["fp"] + counts["tn"]),
            "fnr": counts["fn"] / max(1, counts["fn"] + counts["tp"]),
            "recall": counts["tp"] / max(1, counts["tp"] + counts["fn"]),
        }

    formulas: dict[str, Any] = {}
    for unit, suffix in (("packet", "packets"), ("byte", "bytes")):
        benign_total = total["benign"][suffix]
        attack_total = total["attack"][suffix]
        p_b = provisional["benign"][suffix] / max(1, benign_total)
        p_a = provisional["attack"][suffix] / max(1, attack_total)
        counts = mature_packet if unit == "packet" else mature_byte
        alpha_v = counts["fp"] / max(1, counts["fp"] + counts["tn"])
        beta_v = counts["fn"] / max(1, counts["fn"] + counts["tp"])
        formulas[unit] = {
            "p_b": p_b,
            "p_a": p_a,
            "alpha_v_mature_volume_weighted": alpha_v,
            "beta_v_mature_volume_weighted": beta_v,
            "benign_fast_fraction_formula": p_b + (1.0 - p_b) * (1.0 - alpha_v),
            "benign_detected_fraction_formula": (1.0 - p_b) * alpha_v,
            "attack_fast_fraction_formula": p_a + (1.0 - p_a) * beta_v,
            "attack_detected_fraction_formula": (1.0 - p_a) * (1.0 - beta_v),
            "benign_fast_fraction_observed": routed["benign"][f"fast_{suffix}"] / max(1, benign_total),
            "attack_fast_fraction_observed": routed["attack"][f"fast_{suffix}"] / max(1, attack_total),
        }
    return {
        "flow_confusion": flow_counts,
        "flow_rates": rates(flow_counts),
        "mature_packet_confusion": mature_packet,
        "mature_packet_rates": rates(mature_packet),
        "mature_byte_confusion": mature_byte,
        "mature_byte_rates": rates(mature_byte),
        "offered": total,
        "provisional_fast": provisional,
        "routed_by_selector": routed,
        "load_accounting": formulas,
    }


def _route_kind(event: PacketEvent, decision: SelectorDecision | None, window_iats: int) -> tuple[str, bool]:
    if decision is None:
        return "fast", False
    provisional = event.packet_index < window_iats or not decision.mature
    if provisional:
        return "fast", True
    return ("detected" if decision.predicted_attack else "fast"), False


def simulate_defense(
    flows: Sequence[FlowTrace],
    events: Sequence[PacketEvent],
    decisions: Mapping[str, SelectorDecision] | None,
    config: CoupledConfig,
    sweep: SweepPoint,
    defense: str,
    selector_name: str | None,
) -> dict[str, Any]:
    if defense not in DEFENSES:
        raise ValueError(f"unknown defense {defense}")
    if defense in ("drop_on_detection", "shared_quarantine", "capacity_isolated_quarantine") and decisions is None:
        raise ValueError("this defense requires selector decisions")
    if defense == "static_protocol_priority" and decisions is not None:
        raise ValueError("static protocol priority is a detector-free baseline")
    matched_capacity = config.fast_capacity_Bps + sweep.quarantine_capacity_Bps
    matched_buffer = config.fast_buffer_bytes + sweep.quarantine_buffer_bytes
    shared_capacity = (
        min(config.aggregate_limiter_capacity_Bps, matched_capacity)
        if defense == "shared_aggregate_limiter" else matched_capacity
    )
    shared = _FiniteByteQueue(shared_capacity, matched_buffer)
    fast = _FiniteByteQueue(config.fast_capacity_Bps, config.fast_buffer_bytes)
    quarantine = _FiniteByteQueue(sweep.quarantine_capacity_Bps, sweep.quarantine_buffer_bytes)
    priority_results: dict[tuple[str, int], tuple[bool, float | None, float | None]] | None = None
    priority_accounting: dict[str, Any] | None = None
    if defense == "static_protocol_priority":
        priority_results, priority_accounting = _StrictPriorityByteQueue(
            matched_capacity, matched_buffer, config.priority_high_protocol
        ).run(events, config.fast_delay_s)
    outcomes: list[PacketOutcome] = []

    for event in events:
        decision = decisions[event.flow_id] if decisions is not None else None
        route, provisional = _route_kind(event, decision, config.window_iats)
        destination = "protected"
        if defense in ("shared_fifo", "shared_aggregate_limiter"):
            accepted, completion, release = shared.offer(event, config.fast_delay_s)
            status = "protected" if accepted else "drop_queue"
        elif defense == "static_protocol_priority":
            if priority_results is None:
                raise AssertionError("priority results were not initialized")
            accepted, completion, release = priority_results[(event.flow_id, event.packet_index)]
            status = "protected" if accepted else "drop_queue"
        elif defense == "drop_on_detection":
            if route == "detected":
                accepted, completion, release = False, None, None
                status, destination = "drop_detected", "drop"
            else:
                accepted, completion, release = fast.offer(event, config.fast_delay_s)
                status = "protected" if accepted else "drop_queue"
        elif defense == "shared_quarantine":
            destination = "quarantine" if route == "detected" else "protected"
            delay = sweep.quarantine_delay_s if destination == "quarantine" else config.fast_delay_s
            accepted, completion, release = shared.offer(event, delay)
            status = destination if accepted else "drop_queue"
        elif defense == "capacity_isolated_quarantine":
            if route == "detected":
                destination = "quarantine"
                accepted, completion, release = quarantine.offer(event, sweep.quarantine_delay_s)
            else:
                destination = "protected"
                accepted, completion, release = fast.offer(event, config.fast_delay_s)
            status = destination if accepted else "drop_queue"
        else:
            raise AssertionError(f"unhandled defense {defense}")
        latency = release - event.time_s if release is not None else None
        outcomes.append(PacketOutcome(event, destination, status, completion, release, latency, provisional))

    offered_packets = len(outcomes)
    offered_bytes = sum(outcome.event.size_bytes for outcome in outcomes)
    protected = [outcome for outcome in outcomes if outcome.status == "protected"]
    quarantined = [outcome for outcome in outcomes if outcome.status == "quarantine"]
    dropped = [outcome for outcome in outcomes if outcome.status.startswith("drop")]
    if len(protected) + len(quarantined) + len(dropped) != offered_packets:
        raise AssertionError("packet conservation failed")
    if sum(outcome.event.size_bytes for outcome in protected + quarantined + dropped) != offered_bytes:
        raise AssertionError("byte conservation failed")

    measurement_duration = config.duration_s - config.warmup_s
    protected_in_window = [
        outcome for outcome in protected
        if outcome.completion_s is not None and config.warmup_s <= outcome.completion_s < config.duration_s
    ]
    quarantine_in_window = [
        outcome for outcome in quarantined
        if outcome.completion_s is not None and config.warmup_s <= outcome.completion_s < config.duration_s
    ]
    benign_offered = [outcome for outcome in outcomes if outcome.event.true_label == "benign" and outcome.event.time_s >= config.warmup_s]
    benign_protected = [outcome for outcome in protected if outcome.event.true_label == "benign" and outcome.event.time_s >= config.warmup_s]
    benign_latencies = [float(outcome.latency_s) for outcome in benign_protected if outcome.latency_s is not None]
    attack_provisional = [outcome for outcome in outcomes if outcome.event.true_label == "attack" and outcome.provisional]
    attack_provisional_delivered = [outcome for outcome in attack_provisional if outcome.status == "protected"]
    offered_arrival_Bps = offered_bytes / config.duration_s
    offered_arrival_pps = offered_packets / config.duration_s
    offered_measurement = [
        outcome for outcome in outcomes if config.warmup_s <= outcome.event.time_s < config.duration_s
    ]
    offered_measurement_Bps = (
        sum(outcome.event.size_bytes for outcome in offered_measurement) / measurement_duration
    )
    offered_measurement_pps = len(offered_measurement) / measurement_duration

    def percentile(values: Sequence[float], q: float) -> float | None:
        return float(np.quantile(values, q)) if values else None

    sla_violations = sum(
        outcome.status != "protected" or outcome.latency_s is None or outcome.latency_s > config.sla_latency_s
        for outcome in benign_offered
    )
    metrics = {
        "offered_packets": offered_packets,
        "offered_bytes": offered_bytes,
        "offered_arrival_pps": offered_arrival_pps,
        "offered_arrival_Bps": offered_arrival_Bps,
        "offered_measurement_pps": offered_measurement_pps,
        "offered_measurement_Bps": offered_measurement_Bps,
        "matched_total_capacity_Bps": matched_capacity,
        "offered_load_to_matched_capacity": offered_arrival_Bps / matched_capacity,
        "measurement_load_to_matched_capacity": offered_measurement_Bps / matched_capacity,
        "protected_packets": len(protected),
        "protected_bytes": sum(outcome.event.size_bytes for outcome in protected),
        "quarantine_packets": len(quarantined),
        "quarantine_bytes": sum(outcome.event.size_bytes for outcome in quarantined),
        "dropped_packets": len(dropped),
        "dropped_bytes": sum(outcome.event.size_bytes for outcome in dropped),
        "packet_drop_fraction": len(dropped) / max(1, offered_packets),
        "byte_drop_fraction": sum(outcome.event.size_bytes for outcome in dropped) / max(1, offered_bytes),
        "benign_goodput_pps": sum(outcome.event.true_label == "benign" for outcome in protected_in_window) / measurement_duration,
        "benign_goodput_Bps": sum(outcome.event.size_bytes for outcome in protected_in_window if outcome.event.true_label == "benign") / measurement_duration,
        "attack_leakage_pps": sum(outcome.event.true_label == "attack" for outcome in protected_in_window) / measurement_duration,
        "attack_leakage_Bps": sum(outcome.event.size_bytes for outcome in protected_in_window if outcome.event.true_label == "attack") / measurement_duration,
        "quarantine_departure_pps": len(quarantine_in_window) / measurement_duration,
        "quarantine_departure_Bps": sum(outcome.event.size_bytes for outcome in quarantine_in_window) / measurement_duration,
        "benign_latency_p50_s": percentile(benign_latencies, 0.50),
        "benign_latency_p95_s": percentile(benign_latencies, 0.95),
        "benign_latency_p99_s": percentile(benign_latencies, 0.99),
        "benign_protected_loss_fraction": 1.0 - len(benign_protected) / max(1, len(benign_offered)),
        "benign_protected_byte_loss_fraction": 1.0 - (
            sum(outcome.event.size_bytes for outcome in benign_protected)
            / max(1, sum(outcome.event.size_bytes for outcome in benign_offered))
        ),
        "benign_sla_violation_fraction": sla_violations / max(1, len(benign_offered)),
        "provisional_attack_fast_packets": len(attack_provisional),
        "provisional_attack_fast_bytes": sum(outcome.event.size_bytes for outcome in attack_provisional),
        "provisional_attack_delivered_packets": len(attack_provisional_delivered),
        "provisional_attack_delivered_bytes": sum(outcome.event.size_bytes for outcome in attack_provisional_delivered),
    }
    queue_accounting: dict[str, Any]
    if defense == "static_protocol_priority":
        if priority_accounting is None:
            raise AssertionError("priority accounting was not initialized")
        queue_accounting = {"priority_shared": priority_accounting}
    else:
        queue_accounting = {
            "shared": shared.accounting(),
            "fast": fast.accounting(),
            "quarantine": quarantine.accounting(),
        }
    queue_accepted = sum(int(queue["accepted_packets"]) for queue in queue_accounting.values())
    detected_drops = sum(outcome.status == "drop_detected" for outcome in outcomes)
    if queue_accepted + sum(int(queue["dropped_packets"]) for queue in queue_accounting.values()) + detected_drops != offered_packets:
        raise AssertionError("queue and policy accounting failed")
    return {
        "defense": defense,
        "selector": selector_name,
        "sweep": asdict(sweep),
        "metrics": metrics,
        "queue_accounting": queue_accounting,
        "resource_equivalence": {
            "shared_physical_capacity_Bps": matched_capacity,
            "isolated_fast_plus_quarantine_capacity_Bps": (
                config.fast_capacity_Bps + sweep.quarantine_capacity_Bps
            ),
            "capacity_equal": math.isclose(
                matched_capacity,
                config.fast_capacity_Bps + sweep.quarantine_capacity_Bps,
                rel_tol=0.0,
                abs_tol=1e-12,
            ),
            "shared_buffer_bytes": matched_buffer,
            "isolated_fast_plus_quarantine_buffer_bytes": (
                config.fast_buffer_bytes + sweep.quarantine_buffer_bytes
            ),
            "buffer_equal": matched_buffer == config.fast_buffer_bytes + sweep.quarantine_buffer_bytes,
            "aggregate_limiter_policy_rate_Bps": (
                shared_capacity if defense == "shared_aggregate_limiter" else None
            ),
        },
        "invariants": [
            "protected + quarantine + dropped = offered packets and bytes",
            "serialization uses packet bytes / capacity_Bps",
            "propagation/dwell delay is added after service and does not consume queue service",
            "packets before index W use provisional FAST; packet index W uses the 20-IAT decision",
            "shared capacity and buffer equal FAST plus QUAR resources at each sweep point",
            "static protocol priority uses no selector and never reads benign/attack ground truth",
        ],
    }


def build_sweep_points(config: CoupledConfig) -> list[SweepPoint]:
    points: list[SweepPoint] = []
    for scale in config.attack_scale_sweep:
        points.append(SweepPoint(f"attack_scale_{scale:g}", scale, config.quarantine_capacity_Bps, config.quarantine_buffer_bytes, config.quarantine_delay_s))
    for capacity in config.quarantine_capacity_sweep_Bps:
        if capacity != config.quarantine_capacity_Bps:
            points.append(SweepPoint(f"cq_{capacity:g}", 1.0, capacity, config.quarantine_buffer_bytes, config.quarantine_delay_s))
    for buffer_bytes in config.quarantine_buffer_sweep_bytes:
        if buffer_bytes != config.quarantine_buffer_bytes:
            points.append(SweepPoint(f"kq_{buffer_bytes}", 1.0, config.quarantine_capacity_Bps, buffer_bytes, config.quarantine_delay_s))
    for delay in config.quarantine_delay_sweep:
        if delay != config.quarantine_delay_s:
            points.append(SweepPoint(f"dq_{delay:g}", 1.0, config.quarantine_capacity_Bps, config.quarantine_buffer_bytes, delay))
    names = [point.name for point in points]
    if len(names) != len(set(names)):
        raise AssertionError("sweep names must be unique")
    return points


def defense_plan() -> tuple[tuple[str, str | None], ...]:
    return (
        ("shared_fifo", None),
        ("shared_aggregate_limiter", None),
        ("static_protocol_priority", None),
        ("drop_on_detection", "current_or_timing"),
        ("drop_on_detection", "multifeature"),
        ("drop_on_detection", "oracle"),
        ("shared_quarantine", "current_or_timing"),
        ("shared_quarantine", "multifeature"),
        ("shared_quarantine", "oracle"),
        ("capacity_isolated_quarantine", "rate_only"),
        ("capacity_isolated_quarantine", "variance_only"),
        ("capacity_isolated_quarantine", "current_or_timing"),
        ("capacity_isolated_quarantine", "multifeature"),
        ("capacity_isolated_quarantine", "oracle"),
    )


def _bootstrap_mean_ci(values: Sequence[float], replicates: int, seed: int) -> dict[str, Any]:
    array = np.asarray(values, dtype=float)
    if not len(array):
        return {"n": 0, "mean": None, "median": None, "ci95_bootstrap": [None, None]}
    rng = np.random.default_rng(seed)
    indices = rng.integers(0, len(array), size=(replicates, len(array)))
    samples = np.mean(array[indices], axis=1)
    return {
        "n": len(array),
        "mean": float(np.mean(array)),
        "median": float(np.median(array)),
        "ci95_bootstrap": [float(np.quantile(samples, 0.025)), float(np.quantile(samples, 0.975))],
    }


def summarize_seed_runs(seed_runs: Sequence[dict[str, Any]], config: CoupledConfig) -> dict[str, Any]:
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for seed_run in seed_runs:
        for run in seed_run["runs"]:
            groups[(run["sweep"]["name"], run["defense"], run["selector"] or "none")].append(run)
    metric_names = (
        "benign_goodput_pps", "benign_goodput_Bps", "attack_leakage_pps",
        "attack_leakage_Bps", "quarantine_departure_Bps", "packet_drop_fraction",
        "benign_latency_p50_s", "benign_latency_p95_s", "benign_latency_p99_s",
        "benign_protected_loss_fraction", "benign_protected_byte_loss_fraction",
        "benign_sla_violation_fraction",
        "provisional_attack_delivered_packets", "provisional_attack_delivered_bytes",
        "offered_arrival_pps", "offered_arrival_Bps",
        "offered_measurement_pps", "offered_measurement_Bps",
        "offered_load_to_matched_capacity", "measurement_load_to_matched_capacity",
    )
    groups_out = []
    for key in sorted(groups):
        runs = groups[key]
        stable_seed = int(hashlib.sha256("|".join(key).encode()).hexdigest()[:8], 16) + config.bootstrap_seed
        aggregated = {}
        for metric in metric_names:
            values = [run["metrics"][metric] for run in runs if run["metrics"][metric] is not None]
            aggregated[metric] = _bootstrap_mean_ci(values, config.bootstrap_replicates, stable_seed)
        groups_out.append({"sweep_name": key[0], "defense": key[1], "selector": key[2], "seed_count": len(runs), "metrics": aggregated})
    return {"groups": groups_out, "ci_method": f"paired-seed percentile bootstrap of means; {config.bootstrap_replicates} resamples"}


def summarize_attack_load_coverage(seed_runs: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Summarize the paired attack sweep independently of defense behavior."""

    by_scale: dict[float, list[float]] = defaultdict(list)
    for seed_run in seed_runs:
        for run in seed_run["runs"]:
            if run["defense"] != "shared_fifo" or not run["sweep"]["name"].startswith("attack_scale_"):
                continue
            by_scale[float(run["sweep"]["attack_scale"])].append(
                float(run["metrics"]["offered_load_to_matched_capacity"])
            )
    points = []
    for scale in sorted(by_scale):
        ratios = by_scale[scale]
        points.append({
            "attack_scale": scale,
            "seed_count": len(ratios),
            "mean_offered_load_to_capacity": float(np.mean(ratios)),
            "min_offered_load_to_capacity": float(np.min(ratios)),
            "max_offered_load_to_capacity": float(np.max(ratios)),
            "seeds_below_capacity": sum(value < 1.0 for value in ratios),
            "seeds_above_capacity": sum(value > 1.0 for value in ratios),
        })
    means = [point["mean_offered_load_to_capacity"] for point in points]
    coverage = {
        "basis": "all packet arrivals during the finite run divided by matched physical byte capacity",
        "points": points,
        "mean_sweep_crosses_capacity": bool(means and min(means) < 1.0 < max(means)),
        "mean_sweep_reaches_clear_overload": bool(means and max(means) >= 1.5),
    }
    if not coverage["mean_sweep_crosses_capacity"]:
        raise AssertionError("configured attack sweep does not cross matched capacity")
    if not coverage["mean_sweep_reaches_clear_overload"]:
        raise AssertionError("configured attack sweep does not reach at least 1.5x matched capacity")
    return coverage


def _sum_confusions(items: Sequence[Mapping[str, int]]) -> dict[str, int]:
    return {key: sum(int(item[key]) for item in items) for key in ("tp", "fp", "tn", "fn")}


def summarize_selector_accounting(seed_runs: Sequence[dict[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for selector in SELECTOR_NAMES:
        records = [seed_run["classification_scale_1"][selector] for seed_run in seed_runs]
        flow = _sum_confusions([record["flow_confusion"] for record in records])
        packet = _sum_confusions([record["mature_packet_confusion"] for record in records])
        byte = _sum_confusions([record["mature_byte_confusion"] for record in records])
        def rates(counts: Mapping[str, int]) -> dict[str, float]:
            return {
                "fpr": counts["fp"] / max(1, counts["fp"] + counts["tn"]),
                "fnr": counts["fn"] / max(1, counts["fn"] + counts["tp"]),
                "recall": counts["tp"] / max(1, counts["tp"] + counts["fn"]),
                "precision": counts["tp"] / max(1, counts["tp"] + counts["fp"]),
            }
        output[selector] = {
            "flow_confusion": flow,
            "flow_rates": rates(flow),
            "mature_packet_confusion": packet,
            "mature_packet_rates": rates(packet),
            "mature_byte_confusion": byte,
            "mature_byte_rates": rates(byte),
            "note": "packet/byte rates weight only decision-eligible events; provisional leakage is reported separately",
        }
    return output


def run_one_seed(
    seed: int,
    config: CoupledConfig,
    models: Mapping[str, SelectorModel],
    sweeps: Sequence[SweepPoint],
) -> dict[str, Any]:
    benign = generate_benign_flows(seed, "heldout", config)
    # Scale 1 is always retained for the frozen held-out classification report,
    # even when a caller requests only a reduced queue smoke sweep.
    scales = sorted({1.0, *(point.attack_scale for point in sweeps)})
    attacks_by_scale = {scale: generate_attack_flows(seed, "heldout", config, scale) for scale in scales}
    cache: dict[float, tuple[list[FlowTrace], list[PacketEvent], dict[str, dict[str, SelectorDecision]]]] = {}
    for scale in scales:
        flows = benign + attacks_by_scale[scale]
        events = packet_events(flows, config.duration_s)
        cache[scale] = (flows, events, decisions_for_flows(flows, models))
    flows_one, events_one, decisions_one = cache[1.0]
    classification = {
        name: classification_accounting(flows_one, events_one, decisions_one[name], config.window_iats)
        for name in SELECTOR_NAMES
    }
    runs = []
    for sweep in sweeps:
        flows, events, decisions = cache[sweep.attack_scale]
        for defense, selector in defense_plan():
            selected = decisions[selector] if selector is not None else None
            runs.append(simulate_defense(flows, events, selected, config, sweep, defense, selector))
    return {
        "seed": seed,
        "split": "heldout",
        "benign_flows": [flow_to_dict(flow) for flow in benign],
        "attack_flows_by_scale": {
            f"{scale:g}": [flow_to_dict(flow) for flow in attacks_by_scale[scale]] for scale in scales
        },
        "classification_scale_1": classification,
        "runs": runs,
    }


def run_coupled_experiment(
    output_dir: Path,
    config: CoupledConfig | None = None,
    config_source_path: Path | None = None,
) -> dict[str, Any]:
    config = config or CoupledConfig()
    output_dir = Path(output_dir)
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = output_dir / "raw"
    raw_dir.mkdir()
    config_path = output_dir / "config.json"
    models_path = output_dir / "selector_models.json"
    summary_path = output_dir / "summary.json"
    input_provenance = runtime_provenance(config, config_source_path)
    write_json(config_path, asdict(config))
    input_provenance["config_file_sha256"] = sha256_file(config_path)

    training: list[FlowTrace] = []
    for seed in config.train_seeds:
        flows = generate_flows(seed, "train", config, 1.0)
        training.extend(flows)
        write_json(raw_dir / f"train_seed_{seed}.json", {"seed": seed, "split": "train", "flows": [flow_to_dict(flow) for flow in flows]})
    calibration: list[FlowTrace] = []
    for seed in config.calibration_seeds:
        flows = generate_flows(seed, "calibration", config, 1.0)
        calibration.extend(flows)
        write_json(raw_dir / f"calibration_seed_{seed}.json", {"seed": seed, "split": "calibration", "flows": [flow_to_dict(flow) for flow in flows]})
    models, calibration_report = fit_selectors(training, calibration, config)
    sweeps = build_sweep_points(config)
    seed_runs = []
    for seed in config.heldout_seeds:
        seed_run = run_one_seed(seed, config, models, sweeps)
        seed_runs.append(seed_run)
        write_json(raw_dir / f"heldout_seed_{seed}.json", seed_run)

    load_coverage = summarize_attack_load_coverage(seed_runs)
    if canonical_json_sha256(asdict(config)) != input_provenance["config_canonical_sha256"]:
        raise AssertionError("immutable experiment configuration changed during execution")
    if sha256_file(Path(__file__)) != input_provenance["source_sha256"]:
        raise AssertionError("simulation source changed during execution")
    if sha256_file(REQUIREMENTS_PATH) != input_provenance["requirements_artifact"]["sha256"]:
        raise AssertionError("requirements lockfile changed during execution")
    summary = {
        "schema_version": config.schema_version,
        "deterministic": True,
        "wall_clock_timestamp_included": False,
        "provenance": input_provenance,
        "split_integrity": {
            "train_seeds": list(config.train_seeds),
            "calibration_seeds": list(config.calibration_seeds),
            "heldout_seeds": list(config.heldout_seeds),
            "heldout_seed_count": len(config.heldout_seeds),
            "pairwise_disjoint": True,
        },
        "maturity_semantics": {
            "window_iats": config.window_iats,
            "maturity_packets": config.maturity_packets,
            "provisional_fast_packet_indices": [0, config.window_iats - 1],
            "first_packet_using_mature_decision_index": config.window_iats,
        },
        "calibration": calibration_report,
        "selector_models": {name: asdict(model) for name, model in models.items()},
        "sweep_points": [asdict(point) for point in sweeps],
        "attack_load_coverage": load_coverage,
        "classification": summarize_selector_accounting(seed_runs),
        "coupled_evaluation": summarize_seed_runs(seed_runs, config),
        "limitations": [
            "All workloads are synthetic and are not fitted to public or production traces.",
            "TCP-like and UDP-like are labels only; no transport stack, ACKs, congestion control, retransmission, or QUIC is simulated.",
            "The multifeature selector is a compact deterministic ridge baseline, not a claim of state-of-the-art accuracy or eBPF feasibility.",
            "CPU cost, map memory, verifier acceptance, NIC behavior, optical hardware, and shared-ingress saturation are not measured.",
            "The finite queues are byte-serialized discrete-event models; results validate only their explicit configuration.",
            "Oracle routing becomes available only at the same 21st-packet maturity point, so it retains provisional leakage.",
            "The detector-free priority baseline uses only the TCP-like/UDP-like annotation; this static class mapping is illustrative, not application-aware QoS.",
            "Dependency and runtime hashes fingerprint version metadata; they do not hash installed binary contents or guarantee cross-platform bit identity.",
        ],
    }
    write_json(models_path, {"models": {name: asdict(model) for name, model in models.items()}, "calibration": calibration_report})
    write_json(summary_path, summary)
    generated = [config_path, models_path, summary_path, *sorted(raw_dir.glob("*.json"))]
    manifest = {
        "schema_version": config.schema_version,
        "deterministic": True,
        "files": {str(path.relative_to(output_dir)): sha256_file(path) for path in generated},
        "input_provenance": input_provenance,
    }
    write_json(output_dir / "manifest.json", manifest)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True, help="new or empty directory for coupled-simulation output")
    parser.add_argument(
        "--config",
        type=Path,
        required=True,
        help="complete immutable JSON input configuration",
    )
    args = parser.parse_args()
    config = load_config(args.config)
    summary = run_coupled_experiment(args.output_dir, config, args.config)
    print(f"heldout_seeds={summary['split_integrity']['heldout_seed_count']}")
    print(f"output_dir={args.output_dir}")


if __name__ == "__main__":
    main()
