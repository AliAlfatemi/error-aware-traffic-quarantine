#!/usr/bin/env python3
"""Pre-specified paired inference for the coupled and loopback studies.

This stage consumes seed-level records.  It never treats packets, flows, or
public-dataset rows as independent replicates.  The analysis plan lives in an
exact JSON artifact, all comparisons are declared before output is inspected,
and every emitted number is finite JSON (or an explicit null with a reason).

The CLI intentionally refuses to write into a non-empty output directory::

    venv/bin/python experiments/statistical_analysis.py \
        --config configs/statistical_analysis.json \
        --output-dir results/statistical_analysis
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
from importlib import metadata as importlib_metadata
import json
import math
from pathlib import Path
import platform
import sys
from typing import Any, Iterable, Mapping, Sequence

import numpy as np


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = Path(__file__).resolve()


class AnalysisError(RuntimeError):
    """Raised when an input, pairing, or provenance invariant is violated."""


def _reject_json_constant(token: str) -> None:
    raise ValueError(f"non-finite JSON constant is forbidden: {token}")


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError(f"duplicate JSON object key: {key}")
        output[key] = value
    return output


def load_json_strict(path: Path) -> Any:
    """Load JSON while rejecting NaN/Infinity and duplicate object keys."""

    try:
        return json.loads(
            Path(path).read_text(encoding="utf-8"),
            parse_constant=_reject_json_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise AnalysisError(f"invalid strict JSON in {path}: {exc}") from exc


def _assert_finite_json(value: Any, location: str = "root") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise AnalysisError(f"non-finite number at {location}")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AnalysisError(f"non-string JSON key at {location}")
            _assert_finite_json(item, f"{location}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _assert_finite_json(item, f"{location}[{index}]")
        return
    raise AnalysisError(f"non-JSON value of type {type(value).__name__} at {location}")


def write_json_strict(path: Path, value: Any) -> None:
    _assert_finite_json(value)
    Path(path).write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_sha256(value: Any) -> str:
    _assert_finite_json(value)
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _stable_seed(base_seed: int, *parts: object) -> int:
    label = "|".join(str(part) for part in parts)
    offset = int(hashlib.sha256(label.encode("utf-8")).hexdigest()[:16], 16)
    return (int(base_seed) + offset) % (2**63 - 1)


def _require_exact_keys(
    value: Mapping[str, Any], expected: set[str], location: str
) -> None:
    actual = set(value)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing or unknown:
        raise AnalysisError(
            f"{location} keys differ from the frozen schema; "
            f"missing={missing}, unknown={unknown}"
        )


def _as_mapping(value: Any, location: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AnalysisError(f"{location} must be a JSON object")
    return value


def _as_string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value:
        raise AnalysisError(f"{location} must be a non-empty string")
    return value


def _as_finite_float(value: Any, location: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AnalysisError(f"{location} must be numeric")
    output = float(value)
    if not math.isfinite(output):
        raise AnalysisError(f"{location} must be finite")
    return output


def _as_positive_int(value: Any, location: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise AnalysisError(f"{location} must be a positive integer")
    return value


@dataclass(frozen=True)
class BootstrapSpec:
    replicates: int
    seed: int
    confidence_level: float


@dataclass(frozen=True)
class InferenceSpec:
    alpha: float
    paired_test: str
    multiplicity_method: str
    effect_definition: str
    practical_threshold_semantics: str


@dataclass(frozen=True)
class MetricSpec:
    id: str
    path: str
    unit: str
    better: str
    practical_threshold: float
    relative_denominator_min_abs: float
    tie_tolerance: float


@dataclass(frozen=True)
class DefenseSpec:
    defense: str
    selector: str | None


@dataclass(frozen=True)
class CoupledFamilySpec:
    id: str
    treatment: DefenseSpec
    comparator: DefenseSpec
    metric_ids: tuple[str, ...]


@dataclass(frozen=True)
class CoupledStudySpec:
    input_dir: str
    expected_schema_version: str
    expected_seed_count: int
    attack_load_points: tuple[float, ...]
    relative_denominator_max_cv: float
    metrics: tuple[MetricSpec, ...]
    families: tuple[CoupledFamilySpec, ...]


@dataclass(frozen=True)
class LoopbackFamilySpec:
    id: str
    treatment_mode: str
    comparator_mode: str
    loads: str
    metric_ids: tuple[str, ...]


@dataclass(frozen=True)
class LoopbackStudySpec:
    input_dir: str
    expected_schema_version: str
    expected_seed_count: int
    protocols: tuple[str, ...]
    suspicious_offered_pps: tuple[float, ...]
    relative_denominator_max_cv: float
    metrics: tuple[MetricSpec, ...]
    families: tuple[LoopbackFamilySpec, ...]


@dataclass(frozen=True)
class PublicDatasetScope:
    dataset: str
    included_in_paired_hypothesis_tests: bool
    statement: str
    permitted_use: str


@dataclass(frozen=True)
class AnalysisConfig:
    schema_version: str
    requirements_file: str
    bootstrap: BootstrapSpec
    inference: InferenceSpec
    coupled: CoupledStudySpec
    loopback: LoopbackStudySpec
    public_dataset_scope: PublicDatasetScope


def _parse_metric(value: Any, location: str) -> MetricSpec:
    item = _as_mapping(value, location)
    _require_exact_keys(
        item,
        {
            "id",
            "path",
            "unit",
            "better",
            "practical_threshold",
            "relative_denominator_min_abs",
            "tie_tolerance",
        },
        location,
    )
    better = _as_string(item["better"], f"{location}.better")
    if better not in {"higher", "lower"}:
        raise AnalysisError(f"{location}.better must be 'higher' or 'lower'")
    practical = _as_finite_float(
        item["practical_threshold"], f"{location}.practical_threshold"
    )
    denominator_floor = _as_finite_float(
        item["relative_denominator_min_abs"],
        f"{location}.relative_denominator_min_abs",
    )
    tolerance = _as_finite_float(item["tie_tolerance"], f"{location}.tie_tolerance")
    if practical < 0 or denominator_floor <= 0 or tolerance < 0:
        raise AnalysisError(
            f"{location} requires a non-negative practical threshold/tie tolerance "
            "and positive relative denominator floor"
        )
    return MetricSpec(
        id=_as_string(item["id"], f"{location}.id"),
        path=_as_string(item["path"], f"{location}.path"),
        unit=_as_string(item["unit"], f"{location}.unit"),
        better=better,
        practical_threshold=practical,
        relative_denominator_min_abs=denominator_floor,
        tie_tolerance=tolerance,
    )


def _parse_defense(value: Any, location: str) -> DefenseSpec:
    item = _as_mapping(value, location)
    _require_exact_keys(item, {"defense", "selector"}, location)
    selector = item["selector"]
    if selector is not None:
        selector = _as_string(selector, f"{location}.selector")
    return DefenseSpec(
        defense=_as_string(item["defense"], f"{location}.defense"),
        selector=selector,
    )


def _parse_metric_ids(value: Any, location: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise AnalysisError(f"{location} must be a non-empty list")
    output = tuple(_as_string(item, f"{location}[]") for item in value)
    if len(output) != len(set(output)):
        raise AnalysisError(f"{location} contains duplicates")
    return output


def load_config(path: Path) -> AnalysisConfig:
    root = _as_mapping(load_json_strict(path), "config")
    _require_exact_keys(
        root,
        {
            "schema_version",
            "requirements_file",
            "bootstrap",
            "inference",
            "coupled",
            "loopback",
            "public_dataset_scope",
        },
        "config",
    )

    bootstrap_raw = _as_mapping(root["bootstrap"], "config.bootstrap")
    _require_exact_keys(
        bootstrap_raw,
        {"replicates", "seed", "confidence_level"},
        "config.bootstrap",
    )
    bootstrap = BootstrapSpec(
        replicates=_as_positive_int(
            bootstrap_raw["replicates"], "config.bootstrap.replicates"
        ),
        seed=_as_positive_int(bootstrap_raw["seed"], "config.bootstrap.seed"),
        confidence_level=_as_finite_float(
            bootstrap_raw["confidence_level"],
            "config.bootstrap.confidence_level",
        ),
    )
    if bootstrap.replicates < 100 or not 0.5 < bootstrap.confidence_level < 1.0:
        raise AnalysisError(
            "bootstrap requires at least 100 replicates and confidence in (0.5, 1)"
        )

    inference_raw = _as_mapping(root["inference"], "config.inference")
    _require_exact_keys(
        inference_raw,
        {
            "alpha",
            "paired_test",
            "multiplicity_method",
            "effect_definition",
            "practical_threshold_semantics",
        },
        "config.inference",
    )
    inference = InferenceSpec(
        alpha=_as_finite_float(inference_raw["alpha"], "config.inference.alpha"),
        paired_test=_as_string(
            inference_raw["paired_test"], "config.inference.paired_test"
        ),
        multiplicity_method=_as_string(
            inference_raw["multiplicity_method"],
            "config.inference.multiplicity_method",
        ),
        effect_definition=_as_string(
            inference_raw["effect_definition"],
            "config.inference.effect_definition",
        ),
        practical_threshold_semantics=_as_string(
            inference_raw["practical_threshold_semantics"],
            "config.inference.practical_threshold_semantics",
        ),
    )
    if not 0 < inference.alpha < 1:
        raise AnalysisError("config.inference.alpha must be in (0, 1)")
    if (
        inference.paired_test != "exact_two_sided_sign_test"
        or inference.multiplicity_method != "holm"
        or inference.effect_definition != "treatment_minus_comparator"
    ):
        raise AnalysisError("the frozen analysis supports only its declared inferential plan")

    coupled_raw = _as_mapping(root["coupled"], "config.coupled")
    _require_exact_keys(
        coupled_raw,
        {
            "input_dir",
            "expected_schema_version",
            "expected_seed_count",
            "attack_load_points",
            "relative_denominator_max_cv",
            "metrics",
            "families",
        },
        "config.coupled",
    )
    coupled_metrics = tuple(
        _parse_metric(item, f"config.coupled.metrics[{index}]")
        for index, item in enumerate(coupled_raw["metrics"])
    )
    coupled_metric_ids = {item.id for item in coupled_metrics}
    if len(coupled_metric_ids) != len(coupled_metrics):
        raise AnalysisError("config.coupled.metrics contains duplicate ids")
    coupled_families: list[CoupledFamilySpec] = []
    for index, raw_family in enumerate(coupled_raw["families"]):
        location = f"config.coupled.families[{index}]"
        family = _as_mapping(raw_family, location)
        _require_exact_keys(
            family, {"id", "treatment", "comparator", "metric_ids"}, location
        )
        metric_ids = _parse_metric_ids(family["metric_ids"], f"{location}.metric_ids")
        if not set(metric_ids) <= coupled_metric_ids:
            raise AnalysisError(f"{location} references an unknown metric id")
        coupled_families.append(
            CoupledFamilySpec(
                id=_as_string(family["id"], f"{location}.id"),
                treatment=_parse_defense(family["treatment"], f"{location}.treatment"),
                comparator=_parse_defense(
                    family["comparator"], f"{location}.comparator"
                ),
                metric_ids=metric_ids,
            )
        )
    if len({family.id for family in coupled_families}) != len(coupled_families):
        raise AnalysisError("config.coupled.families contains duplicate ids")
    raw_loads = coupled_raw["attack_load_points"]
    if not isinstance(raw_loads, list) or not raw_loads:
        raise AnalysisError("config.coupled.attack_load_points must be non-empty")
    coupled_loads = tuple(
        _as_finite_float(item, "config.coupled.attack_load_points[]")
        for item in raw_loads
    )
    if any(item <= 0 for item in coupled_loads) or len(set(coupled_loads)) != len(
        coupled_loads
    ):
        raise AnalysisError("coupled attack-load points must be positive and unique")
    coupled = CoupledStudySpec(
        input_dir=_as_string(coupled_raw["input_dir"], "config.coupled.input_dir"),
        expected_schema_version=_as_string(
            coupled_raw["expected_schema_version"],
            "config.coupled.expected_schema_version",
        ),
        expected_seed_count=_as_positive_int(
            coupled_raw["expected_seed_count"],
            "config.coupled.expected_seed_count",
        ),
        attack_load_points=coupled_loads,
        relative_denominator_max_cv=_as_finite_float(
            coupled_raw["relative_denominator_max_cv"],
            "config.coupled.relative_denominator_max_cv",
        ),
        metrics=coupled_metrics,
        families=tuple(coupled_families),
    )
    if coupled.relative_denominator_max_cv <= 0:
        raise AnalysisError("coupled relative denominator max CV must be positive")

    loopback_raw = _as_mapping(root["loopback"], "config.loopback")
    _require_exact_keys(
        loopback_raw,
        {
            "input_dir",
            "expected_schema_version",
            "expected_seed_count",
            "protocols",
            "suspicious_offered_pps",
            "relative_denominator_max_cv",
            "metrics",
            "families",
        },
        "config.loopback",
    )
    if not isinstance(loopback_raw["protocols"], list) or not loopback_raw["protocols"]:
        raise AnalysisError("config.loopback.protocols must be a non-empty list")
    protocols = tuple(
        _as_string(item, "config.loopback.protocols[]")
        for item in loopback_raw["protocols"]
    )
    if len(set(protocols)) != len(protocols):
        raise AnalysisError("config.loopback.protocols contains duplicates")
    raw_loopback_loads = loopback_raw["suspicious_offered_pps"]
    if not isinstance(raw_loopback_loads, list) or not raw_loopback_loads:
        raise AnalysisError("loopback suspicious loads must be a non-empty list")
    loopback_loads = tuple(
        _as_finite_float(item, "config.loopback.suspicious_offered_pps[]")
        for item in raw_loopback_loads
    )
    if any(item < 0 for item in loopback_loads) or len(set(loopback_loads)) != len(
        loopback_loads
    ):
        raise AnalysisError("loopback loads must be non-negative and unique")
    loopback_metrics = tuple(
        _parse_metric(item, f"config.loopback.metrics[{index}]")
        for index, item in enumerate(loopback_raw["metrics"])
    )
    loopback_metric_ids = {item.id for item in loopback_metrics}
    if len(loopback_metric_ids) != len(loopback_metrics):
        raise AnalysisError("config.loopback.metrics contains duplicate ids")
    loopback_families: list[LoopbackFamilySpec] = []
    for index, raw_family in enumerate(loopback_raw["families"]):
        location = f"config.loopback.families[{index}]"
        family = _as_mapping(raw_family, location)
        _require_exact_keys(
            family,
            {"id", "treatment_mode", "comparator_mode", "loads", "metric_ids"},
            location,
        )
        loads = _as_string(family["loads"], f"{location}.loads")
        if loads not in {"all", "positive_only"}:
            raise AnalysisError(f"{location}.loads must be all or positive_only")
        metric_ids = _parse_metric_ids(family["metric_ids"], f"{location}.metric_ids")
        if not set(metric_ids) <= loopback_metric_ids:
            raise AnalysisError(f"{location} references an unknown metric id")
        loopback_families.append(
            LoopbackFamilySpec(
                id=_as_string(family["id"], f"{location}.id"),
                treatment_mode=_as_string(
                    family["treatment_mode"], f"{location}.treatment_mode"
                ),
                comparator_mode=_as_string(
                    family["comparator_mode"], f"{location}.comparator_mode"
                ),
                loads=loads,
                metric_ids=metric_ids,
            )
        )
    if len({family.id for family in loopback_families}) != len(loopback_families):
        raise AnalysisError("config.loopback.families contains duplicate ids")
    loopback = LoopbackStudySpec(
        input_dir=_as_string(loopback_raw["input_dir"], "config.loopback.input_dir"),
        expected_schema_version=_as_string(
            loopback_raw["expected_schema_version"],
            "config.loopback.expected_schema_version",
        ),
        expected_seed_count=_as_positive_int(
            loopback_raw["expected_seed_count"],
            "config.loopback.expected_seed_count",
        ),
        protocols=protocols,
        suspicious_offered_pps=loopback_loads,
        relative_denominator_max_cv=_as_finite_float(
            loopback_raw["relative_denominator_max_cv"],
            "config.loopback.relative_denominator_max_cv",
        ),
        metrics=loopback_metrics,
        families=tuple(loopback_families),
    )
    if loopback.relative_denominator_max_cv <= 0:
        raise AnalysisError("loopback relative denominator max CV must be positive")

    public_raw = _as_mapping(root["public_dataset_scope"], "config.public_dataset_scope")
    _require_exact_keys(
        public_raw,
        {
            "dataset",
            "included_in_paired_hypothesis_tests",
            "statement",
            "permitted_use",
        },
        "config.public_dataset_scope",
    )
    if not isinstance(public_raw["included_in_paired_hypothesis_tests"], bool):
        raise AnalysisError("public hypothesis-test scope must be boolean")
    if public_raw["included_in_paired_hypothesis_tests"]:
        raise AnalysisError("public rows must remain excluded from paired hypothesis tests")
    public_scope = PublicDatasetScope(
        dataset=_as_string(public_raw["dataset"], "public dataset"),
        included_in_paired_hypothesis_tests=False,
        statement=_as_string(public_raw["statement"], "public scope statement"),
        permitted_use=_as_string(public_raw["permitted_use"], "public permitted use"),
    )

    schema = _as_string(root["schema_version"], "config.schema_version")
    if schema != "statistical-analysis-1.0":
        raise AnalysisError(f"unsupported statistical-analysis schema: {schema}")
    return AnalysisConfig(
        schema_version=schema,
        requirements_file=_as_string(
            root["requirements_file"], "config.requirements_file"
        ),
        bootstrap=bootstrap,
        inference=inference,
        coupled=coupled,
        loopback=loopback,
        public_dataset_scope=public_scope,
    )


def resolve_project_path(value: str) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def _safe_manifest_member(root: Path, relative_name: str) -> Path:
    relative = Path(relative_name)
    if relative.is_absolute():
        raise AnalysisError(f"upstream manifest contains an absolute path: {relative_name}")
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise AnalysisError(
            f"upstream manifest path escapes its result directory: {relative_name}"
        ) from exc
    return candidate


def verify_upstream_manifest(
    input_dir: Path, expected_schema_version: str
) -> dict[str, Any]:
    """Verify every file bound by an upstream result manifest."""

    input_dir = Path(input_dir).resolve()
    manifest_path = input_dir / "manifest.json"
    manifest = _as_mapping(load_json_strict(manifest_path), str(manifest_path))
    if manifest.get("schema_version") != expected_schema_version:
        raise AnalysisError(
            f"{manifest_path} schema {manifest.get('schema_version')!r} != "
            f"expected {expected_schema_version!r}"
        )
    files = _as_mapping(manifest.get("files"), f"{manifest_path}.files")
    if not files:
        raise AnalysisError(f"{manifest_path} binds no files")
    verified: dict[str, str] = {}
    for relative_name in sorted(files):
        expected_hash = files[relative_name]
        if not isinstance(expected_hash, str) or len(expected_hash) != 64:
            raise AnalysisError(f"invalid SHA-256 for {relative_name} in {manifest_path}")
        member = _safe_manifest_member(input_dir, relative_name)
        if not member.is_file():
            raise AnalysisError(f"manifest-bound input is missing: {member}")
        actual_hash = sha256_file(member)
        if actual_hash != expected_hash:
            raise AnalysisError(
                f"manifest hash mismatch for {member}: {actual_hash} != {expected_hash}"
            )
        verified[relative_name] = actual_hash
    declared_fingerprint = canonical_json_sha256(verified)
    return {
        "manifest_path": str(manifest_path.relative_to(PROJECT_ROOT))
        if manifest_path.is_relative_to(PROJECT_ROOT)
        else str(manifest_path),
        "manifest_sha256": sha256_file(manifest_path),
        "schema_version": expected_schema_version,
        "verified_file_count": len(verified),
        "verified_files_fingerprint_sha256": declared_fingerprint,
        "verified_files": verified,
    }


def verify_output_manifest(output_dir: Path) -> dict[str, str]:
    """Verify all generated files declared by this stage's manifest."""

    output_dir = Path(output_dir).resolve()
    manifest_path = output_dir / "manifest.json"
    manifest = _as_mapping(load_json_strict(manifest_path), str(manifest_path))
    if manifest.get("schema_version") != "statistical-analysis-1.0":
        raise AnalysisError("unexpected statistical-analysis output schema")
    files = _as_mapping(manifest.get("files"), f"{manifest_path}.files")
    verified: dict[str, str] = {}
    for relative_name, expected_hash in sorted(files.items()):
        member = _safe_manifest_member(output_dir, relative_name)
        if not member.is_file():
            raise AnalysisError(f"generated manifest member is missing: {member}")
        actual_hash = sha256_file(member)
        if actual_hash != expected_hash:
            raise AnalysisError(f"generated manifest hash mismatch: {member}")
        verified[relative_name] = actual_hash
    return verified


def _extract_numeric(value: Any, dotted_path: str, location: str) -> float:
    current = value
    for component in dotted_path.split("."):
        if not isinstance(current, Mapping) or component not in current:
            raise AnalysisError(f"missing metric {dotted_path} at {location}")
        current = current[component]
    return _as_finite_float(current, f"{location}.{dotted_path}")


def bootstrap_paired_effects(
    differences: Sequence[float],
    replicates: int,
    confidence_level: float,
    seed: int,
) -> dict[str, Any]:
    """Bootstrap paired blocks and return CIs for the mean and median effect."""

    values = np.asarray(differences, dtype=float)
    if values.ndim != 1 or not len(values) or not np.all(np.isfinite(values)):
        raise AnalysisError("paired bootstrap requires a non-empty finite vector")
    rng = np.random.default_rng(seed)
    indices = rng.integers(0, len(values), size=(replicates, len(values)))
    samples = values[indices]
    means = np.mean(samples, axis=1)
    medians = np.median(samples, axis=1)
    tail = (1.0 - confidence_level) / 2.0
    quantiles = [tail, 1.0 - tail]
    return {
        "method": "nonparametric percentile bootstrap over paired seed blocks",
        "replicates": replicates,
        "confidence_level": confidence_level,
        "mean": {
            "estimate": float(np.mean(values)),
            "ci": [float(item) for item in np.quantile(means, quantiles)],
        },
        "median": {
            "estimate": float(np.median(values)),
            "ci": [float(item) for item in np.quantile(medians, quantiles)],
        },
    }


def exact_two_sided_sign_test(wins: int, losses: int) -> float:
    """Exact binomial sign test conditional on non-tied pairs."""

    if wins < 0 or losses < 0:
        raise AnalysisError("win/loss counts cannot be negative")
    sample_count = wins + losses
    if sample_count == 0:
        return 1.0
    tail_count = min(wins, losses)
    tail_numerator = sum(math.comb(sample_count, index) for index in range(tail_count + 1))
    return min(1.0, 2.0 * tail_numerator / (2**sample_count))


def holm_adjust(p_values: Sequence[float]) -> list[float]:
    """Return Holm step-down adjusted p-values in original order."""

    if any(not math.isfinite(value) or not 0 <= value <= 1 for value in p_values):
        raise AnalysisError("Holm adjustment requires finite p-values in [0, 1]")
    count = len(p_values)
    order = sorted(range(count), key=lambda index: (p_values[index], index))
    adjusted = [0.0] * count
    running = 0.0
    for rank, index in enumerate(order):
        candidate = min(1.0, (count - rank) * p_values[index])
        running = max(running, candidate)
        adjusted[index] = running
    return adjusted


def _denominator_diagnostics(values: Sequence[float]) -> dict[str, float]:
    array = np.abs(np.asarray(values, dtype=float))
    mean_abs = float(np.mean(array))
    cv = float(np.std(array, ddof=1) / mean_abs) if len(array) > 1 and mean_abs else 0.0
    return {
        "minimum_absolute_comparator": float(np.min(array)),
        "mean_absolute_comparator": mean_abs,
        "coefficient_of_variation_absolute_comparator": cv,
    }


def _relative_effect(
    treatment: Sequence[float],
    comparator: Sequence[float],
    metric: MetricSpec,
    maximum_cv: float,
    bootstrap: BootstrapSpec,
    seed: int,
) -> dict[str, Any]:
    diagnostics = _denominator_diagnostics(comparator)
    reasons: list[str] = []
    if diagnostics["minimum_absolute_comparator"] < metric.relative_denominator_min_abs:
        reasons.append("at_least_one_comparator_is_below_the_frozen_absolute_floor")
    if diagnostics["coefficient_of_variation_absolute_comparator"] > maximum_cv:
        reasons.append("comparator_coefficient_of_variation_exceeds_the_frozen_limit")
    if reasons:
        return {
            "available": False,
            "reason": reasons,
            "denominator_stability": {
                **diagnostics,
                "minimum_absolute_floor": metric.relative_denominator_min_abs,
                "maximum_coefficient_of_variation": maximum_cv,
            },
        }
    treatment_values = np.asarray(treatment, dtype=float)
    comparator_values = np.asarray(comparator, dtype=float)
    raw_percent = 100.0 * (treatment_values - comparator_values) / np.abs(
        comparator_values
    )
    direction = 1.0 if metric.better == "higher" else -1.0
    benefit_percent = direction * raw_percent
    raw_summary = bootstrap_paired_effects(
        raw_percent,
        bootstrap.replicates,
        bootstrap.confidence_level,
        seed,
    )
    benefit_summary = bootstrap_paired_effects(
        benefit_percent,
        bootstrap.replicates,
        bootstrap.confidence_level,
        seed,
    )
    return {
        "available": True,
        "unit": "percent_of_absolute_comparator",
        "raw_treatment_minus_comparator_percent": raw_summary,
        "oriented_benefit_percent": benefit_summary,
        "denominator_stability": {
            **diagnostics,
            "minimum_absolute_floor": metric.relative_denominator_min_abs,
            "maximum_coefficient_of_variation": maximum_cv,
        },
    }


def summarize_paired_comparison(
    *,
    treatment: Sequence[float],
    comparator: Sequence[float],
    seeds: Sequence[int],
    metric: MetricSpec,
    maximum_denominator_cv: float,
    bootstrap: BootstrapSpec,
    stable_seed: int,
) -> dict[str, Any]:
    if not (len(treatment) == len(comparator) == len(seeds)) or not seeds:
        raise AnalysisError("paired inputs must have equal, non-zero lengths")
    if len(set(seeds)) != len(seeds):
        raise AnalysisError("paired seed ids must be unique")
    treatment_values = np.asarray(treatment, dtype=float)
    comparator_values = np.asarray(comparator, dtype=float)
    if not np.all(np.isfinite(treatment_values)) or not np.all(
        np.isfinite(comparator_values)
    ):
        raise AnalysisError("paired inputs must be finite")
    raw_differences = treatment_values - comparator_values
    direction = 1.0 if metric.better == "higher" else -1.0
    benefits = direction * raw_differences
    wins = int(np.sum(benefits > metric.tie_tolerance))
    losses = int(np.sum(benefits < -metric.tie_tolerance))
    ties = len(benefits) - wins - losses
    native = bootstrap_paired_effects(
        raw_differences,
        bootstrap.replicates,
        bootstrap.confidence_level,
        stable_seed,
    )
    benefit_ci = (
        list(native["mean"]["ci"])
        if direction > 0
        else [-native["mean"]["ci"][1], -native["mean"]["ci"][0]]
    )
    mean_benefit = direction * native["mean"]["estimate"]
    threshold = metric.practical_threshold
    if mean_benefit >= threshold:
        practical_class = "beneficial_at_or_above_threshold"
    elif mean_benefit <= -threshold:
        practical_class = "harmful_at_or_above_threshold"
    else:
        practical_class = "below_frozen_practical_threshold"
    p_value = exact_two_sided_sign_test(wins, losses)
    return {
        "pair_count": len(seeds),
        "seed_ids": [int(seed) for seed in seeds],
        "metric": {
            "id": metric.id,
            "unit": metric.unit,
            "better": metric.better,
        },
        "effect_native": {
            "definition": "treatment_minus_comparator",
            **native,
        },
        "paired_outcomes_oriented_by_better_direction": {
            "wins": wins,
            "ties": ties,
            "losses": losses,
            "tie_tolerance_native_units": metric.tie_tolerance,
        },
        "relative_effect": _relative_effect(
            treatment_values,
            comparator_values,
            metric,
            maximum_denominator_cv,
            bootstrap,
            stable_seed,
        ),
        "practical_significance": {
            "classification_from_mean_native_effect": practical_class,
            "threshold_native_units": threshold,
            "oriented_mean_benefit": mean_benefit,
            "oriented_mean_benefit_ci": benefit_ci,
            "ci_entirely_at_or_above_benefit_threshold": benefit_ci[0] >= threshold,
            "ci_entirely_at_or_below_harm_threshold": benefit_ci[1] <= -threshold,
            "scope": "reporting threshold only; independent of the hypothesis test",
        },
        "nonparametric_test": {
            "name": "exact two-sided paired sign test",
            "null": "conditional probability of an oriented win among non-tied pairs is 0.5",
            "pairing_unit": "stochastic seed block",
            "non_tied_pair_count": wins + losses,
            "ties_omitted_from_test": ties,
            "p_value_unadjusted": p_value,
            "p_value_holm": None,
            "statistically_significant_after_holm": None,
        },
    }


def apply_holm_to_family(results: list[dict[str, Any]], alpha: float) -> None:
    p_values = [item["nonparametric_test"]["p_value_unadjusted"] for item in results]
    adjusted = holm_adjust(p_values)
    for item, adjusted_value in zip(results, adjusted, strict=True):
        test = item["nonparametric_test"]
        test["p_value_holm"] = adjusted_value
        test["holm_family_hypothesis_count"] = len(results)
        test["familywise_alpha"] = alpha
        test["statistically_significant_after_holm"] = adjusted_value <= alpha
        item["interpretation_boundary"] = {
            "statistical": (
                "reject_equal_win_probability_after_familywise_Holm_correction"
                if adjusted_value <= alpha
                else "do_not_reject_equal_win_probability_after_familywise_Holm_correction"
            ),
            "practical": item["practical_significance"][
                "classification_from_mean_native_effect"
            ],
            "warning": "statistical significance and practical significance are separate judgments",
        }


def _manifest_contains(verification: Mapping[str, Any], path: Path, root: Path) -> None:
    relative_name = str(Path(path).resolve().relative_to(Path(root).resolve()))
    files = verification["verified_files"]
    if relative_name not in files:
        raise AnalysisError(f"consumed input is not bound by its upstream manifest: {path}")


def _reverify_snapshot(root: Path, verification: Mapping[str, Any]) -> None:
    current_manifest_hash = sha256_file(Path(root) / "manifest.json")
    if current_manifest_hash != verification["manifest_sha256"]:
        raise AnalysisError(f"upstream manifest changed during analysis: {root}")
    for relative_name, expected_hash in verification["verified_files"].items():
        path = _safe_manifest_member(Path(root), relative_name)
        if sha256_file(path) != expected_hash:
            raise AnalysisError(f"upstream input changed during analysis: {path}")


def _coupled_index(
    input_dir: Path,
    study: CoupledStudySpec,
    verification: Mapping[str, Any],
) -> tuple[dict[int, dict[tuple[float, str, str | None], Mapping[str, Any]]], list[int]]:
    raw_paths = sorted((Path(input_dir) / "raw").glob("heldout_seed_*.json"))
    if len(raw_paths) != study.expected_seed_count:
        raise AnalysisError(
            f"coupled held-out file count {len(raw_paths)} != "
            f"expected {study.expected_seed_count}"
        )
    index: dict[int, dict[tuple[float, str, str | None], Mapping[str, Any]]] = {}
    for path in raw_paths:
        _manifest_contains(verification, path, input_dir)
        document = _as_mapping(load_json_strict(path), str(path))
        if document.get("split") != "heldout":
            raise AnalysisError(f"non-held-out record in coupled input: {path}")
        seed_raw = document.get("seed")
        if isinstance(seed_raw, bool) or not isinstance(seed_raw, int):
            raise AnalysisError(f"invalid coupled seed in {path}")
        seed = int(seed_raw)
        if seed in index:
            raise AnalysisError(f"duplicate coupled held-out seed: {seed}")
        runs = document.get("runs")
        if not isinstance(runs, list) or not runs:
            raise AnalysisError(f"coupled seed has no runs: {path}")
        seed_index: dict[tuple[float, str, str | None], Mapping[str, Any]] = {}
        for run_number, raw_run in enumerate(runs):
            run = _as_mapping(raw_run, f"{path}.runs[{run_number}]")
            sweep = _as_mapping(run.get("sweep"), f"{path}.runs[{run_number}].sweep")
            sweep_name = sweep.get("name")
            if not isinstance(sweep_name, str) or not sweep_name.startswith("attack_scale_"):
                continue
            load = _as_finite_float(
                sweep.get("attack_scale"), f"{path}.runs[{run_number}].attack_scale"
            )
            defense = _as_string(
                run.get("defense"), f"{path}.runs[{run_number}].defense"
            )
            selector = run.get("selector")
            if selector is not None:
                selector = _as_string(
                    selector, f"{path}.runs[{run_number}].selector"
                )
            key = (load, defense, selector)
            if key in seed_index:
                raise AnalysisError(f"duplicate coupled condition {key} for seed {seed}")
            seed_index[key] = run
        index[seed] = seed_index
    seeds = sorted(index)
    if len(seeds) != study.expected_seed_count:
        raise AnalysisError("coupled held-out seeds are not unique")
    return index, seeds


def _assert_coupled_pair_matched(
    treatment: Mapping[str, Any], comparator: Mapping[str, Any], location: str
) -> None:
    if canonical_json_sha256(treatment.get("sweep")) != canonical_json_sha256(
        comparator.get("sweep")
    ):
        raise AnalysisError(f"coupled pair has mismatched sweep resources at {location}")
    for role, run in (("treatment", treatment), ("comparator", comparator)):
        resource = _as_mapping(
            run.get("resource_equivalence"), f"{location}.{role}.resource_equivalence"
        )
        if resource.get("capacity_equal") is not True or resource.get("buffer_equal") is not True:
            raise AnalysisError(f"coupled {role} is not resource matched at {location}")
    treatment_metrics = _as_mapping(treatment.get("metrics"), f"{location}.treatment.metrics")
    comparator_metrics = _as_mapping(
        comparator.get("metrics"), f"{location}.comparator.metrics"
    )
    workload_fields = (
        "offered_packets",
        "offered_bytes",
        "offered_arrival_Bps",
        "offered_load_to_matched_capacity",
        "matched_total_capacity_Bps",
    )
    for field in workload_fields:
        left = _as_finite_float(treatment_metrics.get(field), f"{location}.treatment.{field}")
        right = _as_finite_float(comparator_metrics.get(field), f"{location}.comparator.{field}")
        if left != right:
            raise AnalysisError(f"coupled pair workload mismatch for {field} at {location}")


def analyze_coupled(
    input_dir: Path,
    study: CoupledStudySpec,
    bootstrap: BootstrapSpec,
    alpha: float,
    verification: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    index, seeds = _coupled_index(input_dir, study, verification)
    metrics = {metric.id: metric for metric in study.metrics}
    families_output: list[dict[str, Any]] = []
    for family in study.families:
        results: list[dict[str, Any]] = []
        for load in study.attack_load_points:
            treatment_key = (
                load,
                family.treatment.defense,
                family.treatment.selector,
            )
            comparator_key = (
                load,
                family.comparator.defense,
                family.comparator.selector,
            )
            pairs: list[tuple[int, Mapping[str, Any], Mapping[str, Any]]] = []
            for seed in seeds:
                if treatment_key not in index[seed] or comparator_key not in index[seed]:
                    raise AnalysisError(
                        f"missing pre-specified coupled pair for seed={seed}, load={load}, "
                        f"family={family.id}"
                    )
                treatment_run = index[seed][treatment_key]
                comparator_run = index[seed][comparator_key]
                _assert_coupled_pair_matched(
                    treatment_run,
                    comparator_run,
                    f"seed={seed},load={load},family={family.id}",
                )
                pairs.append((seed, treatment_run, comparator_run))
            if len(pairs) != study.expected_seed_count:
                raise AnalysisError(f"incomplete coupled pairing for {family.id} at {load}")
            for metric_id in family.metric_ids:
                metric = metrics[metric_id]
                treatment_values = [
                    _extract_numeric(run, metric.path, f"coupled seed {seed}")
                    for seed, run, _ in pairs
                ]
                comparator_values = [
                    _extract_numeric(run, metric.path, f"coupled seed {seed}")
                    for seed, _, run in pairs
                ]
                result = summarize_paired_comparison(
                    treatment=treatment_values,
                    comparator=comparator_values,
                    seeds=[seed for seed, _, _ in pairs],
                    metric=metric,
                    maximum_denominator_cv=study.relative_denominator_max_cv,
                    bootstrap=bootstrap,
                    stable_seed=_stable_seed(
                        bootstrap.seed, "coupled", family.id, load, metric.id
                    ),
                )
                result.update(
                    {
                        "hypothesis_id": (
                            f"{family.id}|attack_scale={load:g}|metric={metric.id}"
                        ),
                        "condition": {"attack_scale": load},
                        "comparison": {
                            "treatment": asdict(family.treatment),
                            "comparator": asdict(family.comparator),
                        },
                    }
                )
                results.append(result)
        apply_holm_to_family(results, alpha)
        families_output.append(
            {
                "family_id": family.id,
                "study": "coupled_synthetic_simulation",
                "holm_scope": "all frozen metrics and attack-load points in this contrast family",
                "hypothesis_count": len(results),
                "results": results,
            }
        )
    return families_output, {
        "heldout_seed_count": len(seeds),
        "heldout_seed_ids": seeds,
        "raw_heldout_file_count": len(seeds),
        "pairing_unit": "held-out stochastic seed",
        "matched_workload_and_resource_checks": True,
    }


def _loopback_common_condition(document: Mapping[str, Any]) -> dict[str, Any]:
    config = dict(_as_mapping(document.get("config"), "loopback.config"))
    config.pop("mode", None)
    return config


def _loopback_index(
    input_dir: Path,
    study: LoopbackStudySpec,
    verification: Mapping[str, Any],
) -> tuple[
    dict[tuple[int, str, float, str], Mapping[str, Any]],
    dict[tuple[str, float], list[int]],
]:
    raw_paths = sorted((Path(input_dir) / "raw").glob("*.summary.json"))
    expected_files = (
        study.expected_seed_count
        * len(study.protocols)
        * len(study.suspicious_offered_pps)
        * 2
    )
    if len(raw_paths) != expected_files:
        raise AnalysisError(
            f"loopback summary file count {len(raw_paths)} != expected {expected_files}"
        )
    index: dict[tuple[int, str, float, str], Mapping[str, Any]] = {}
    seeds_by_condition: dict[tuple[str, float], set[int]] = {}
    for path in raw_paths:
        _manifest_contains(verification, path, input_dir)
        document = _as_mapping(load_json_strict(path), str(path))
        if document.get("schema_version") != study.expected_schema_version:
            raise AnalysisError(f"unexpected loopback trial schema in {path}")
        if document.get("valid_for_publication_aggregation") is not True:
            raise AnalysisError(f"invalid loopback trial cannot enter analysis: {path}")
        integrity = _as_mapping(document.get("integrity"), f"{path}.integrity")
        if (
            integrity.get("exact_received_metadata_valid") is not True
            or integrity.get("exact_sequence_integrity_valid") is not True
            or integrity.get("sequence_partition_valid") is not True
        ):
            raise AnalysisError(f"loopback trial fails integrity checks: {path}")
        config = _as_mapping(document.get("config"), f"{path}.config")
        seed_raw = config.get("seed")
        if isinstance(seed_raw, bool) or not isinstance(seed_raw, int):
            raise AnalysisError(f"invalid loopback seed in {path}")
        seed = int(seed_raw)
        protocol = _as_string(config.get("protocol"), f"{path}.protocol")
        mode = _as_string(config.get("mode"), f"{path}.mode")
        load = _as_finite_float(
            config.get("suspicious_offered_pps"), f"{path}.suspicious_offered_pps"
        )
        if protocol not in study.protocols or load not in study.suspicious_offered_pps:
            raise AnalysisError(f"undeclared loopback condition in {path}")
        if mode not in {"shared", "isolated"}:
            raise AnalysisError(f"unsupported loopback mode in {path}")
        key = (seed, protocol, load, mode)
        if key in index:
            raise AnalysisError(f"duplicate loopback condition: {key}")
        index[key] = document
        seeds_by_condition.setdefault((protocol, load), set()).add(seed)
    sorted_seeds: dict[tuple[str, float], list[int]] = {}
    for condition, seeds in seeds_by_condition.items():
        if len(seeds) != study.expected_seed_count:
            raise AnalysisError(
                f"loopback condition {condition} has {len(seeds)} seeds, "
                f"expected {study.expected_seed_count}"
            )
        sorted_seeds[condition] = sorted(seeds)
    expected_condition_count = len(study.protocols) * len(study.suspicious_offered_pps)
    if len(sorted_seeds) != expected_condition_count:
        raise AnalysisError("loopback protocol/load condition grid is incomplete")
    return index, sorted_seeds


def _assert_loopback_pair_matched(
    treatment: Mapping[str, Any], comparator: Mapping[str, Any], location: str
) -> None:
    if canonical_json_sha256(_loopback_common_condition(treatment)) != canonical_json_sha256(
        _loopback_common_condition(comparator)
    ):
        raise AnalysisError(f"loopback pair configuration mismatch at {location}")
    treatment_block = _as_mapping(treatment.get("execution"), f"{location}.execution")
    comparator_block = _as_mapping(comparator.get("execution"), f"{location}.execution")
    if treatment_block.get("paired_block_id") != comparator_block.get("paired_block_id"):
        raise AnalysisError(f"loopback paired-block id mismatch at {location}")
    if treatment.get("offered_schedule_sha256") != comparator.get("offered_schedule_sha256"):
        raise AnalysisError(f"loopback offered schedule mismatch at {location}")
    for role, document in (("treatment", treatment), ("comparator", comparator)):
        accounting = _as_mapping(
            document.get("resource_accounting"), f"{location}.{role}.resource_accounting"
        )
        capacity = _as_mapping(
            accounting.get("capacity_pps"), f"{location}.{role}.capacity_pps"
        )
        buffer = _as_mapping(
            accounting.get("waiting_buffer_frames"),
            f"{location}.{role}.waiting_buffer_frames",
        )
        if capacity.get("equal_total") is not True or buffer.get("equal_total") is not True:
            raise AnalysisError(f"loopback {role} is not resource matched at {location}")
        if _as_finite_float(
            capacity.get("shared"), f"{location}.{role}.capacity.shared"
        ) != _as_finite_float(
            capacity.get("isolated_fast_plus_quarantine"),
            f"{location}.{role}.capacity.isolated",
        ):
            raise AnalysisError(f"loopback {role} capacity totals differ at {location}")
        if _as_finite_float(
            buffer.get("shared"), f"{location}.{role}.buffer.shared"
        ) != _as_finite_float(
            buffer.get("isolated_fast_plus_quarantine"),
            f"{location}.{role}.buffer.isolated",
        ):
            raise AnalysisError(f"loopback {role} waiting-buffer totals differ at {location}")


def analyze_loopback(
    input_dir: Path,
    study: LoopbackStudySpec,
    bootstrap: BootstrapSpec,
    alpha: float,
    verification: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    index, seeds_by_condition = _loopback_index(input_dir, study, verification)
    metrics = {metric.id: metric for metric in study.metrics}
    families_output: list[dict[str, Any]] = []
    for family in study.families:
        if {family.treatment_mode, family.comparator_mode} != {"isolated", "shared"}:
            raise AnalysisError(f"loopback family {family.id} is not isolated-vs-shared")
        loads = (
            study.suspicious_offered_pps
            if family.loads == "all"
            else tuple(load for load in study.suspicious_offered_pps if load > 0)
        )
        results: list[dict[str, Any]] = []
        for protocol in study.protocols:
            for load in loads:
                seeds = seeds_by_condition[(protocol, load)]
                treatment_documents: list[Mapping[str, Any]] = []
                comparator_documents: list[Mapping[str, Any]] = []
                for seed in seeds:
                    treatment_key = (seed, protocol, load, family.treatment_mode)
                    comparator_key = (seed, protocol, load, family.comparator_mode)
                    if treatment_key not in index or comparator_key not in index:
                        raise AnalysisError(
                            f"missing loopback pair for seed={seed}, protocol={protocol}, "
                            f"load={load}, family={family.id}"
                        )
                    treatment_document = index[treatment_key]
                    comparator_document = index[comparator_key]
                    _assert_loopback_pair_matched(
                        treatment_document,
                        comparator_document,
                        f"seed={seed},protocol={protocol},load={load}",
                    )
                    treatment_documents.append(treatment_document)
                    comparator_documents.append(comparator_document)
                for metric_id in family.metric_ids:
                    metric = metrics[metric_id]
                    treatment_values = [
                        _extract_numeric(document, metric.path, "loopback treatment")
                        for document in treatment_documents
                    ]
                    comparator_values = [
                        _extract_numeric(document, metric.path, "loopback comparator")
                        for document in comparator_documents
                    ]
                    result = summarize_paired_comparison(
                        treatment=treatment_values,
                        comparator=comparator_values,
                        seeds=seeds,
                        metric=metric,
                        maximum_denominator_cv=study.relative_denominator_max_cv,
                        bootstrap=bootstrap,
                        stable_seed=_stable_seed(
                            bootstrap.seed,
                            "loopback",
                            family.id,
                            protocol,
                            load,
                            metric.id,
                        ),
                    )
                    result.update(
                        {
                            "hypothesis_id": (
                                f"{family.id}|protocol={protocol}|"
                                f"suspicious_offered_pps={load:g}|metric={metric.id}"
                            ),
                            "condition": {
                                "protocol": protocol,
                                "suspicious_offered_pps": load,
                            },
                            "comparison": {
                                "treatment_mode": family.treatment_mode,
                                "comparator_mode": family.comparator_mode,
                                "routing_policy": "oracle_ground_truth_label",
                            },
                        }
                    )
                    results.append(result)
        apply_holm_to_family(results, alpha)
        families_output.append(
            {
                "family_id": family.id,
                "study": "localhost_packet_level_testbed",
                "holm_scope": "all frozen metrics, protocols, and selected load points in this claim family",
                "hypothesis_count": len(results),
                "results": results,
            }
        )
    all_seed_ids = sorted({seed for seeds in seeds_by_condition.values() for seed in seeds})
    return families_output, {
        "seed_count_per_protocol_load_condition": study.expected_seed_count,
        "seed_ids_union": all_seed_ids,
        "protocols": list(study.protocols),
        "suspicious_offered_pps": list(study.suspicious_offered_pps),
        "raw_summary_file_count": len(index),
        "pairing_unit": "seed within identical protocol/load block",
        "matched_schedule_configuration_and_resource_checks": True,
        "claim_boundary": (
            "unprivileged user-space oracle-routed localhost TCP/UDP testbed; "
            "not XDP/eBPF, kernel forwarding, optical hardware, physical-link, "
            "or line-rate evidence"
        ),
    }


def _runtime_provenance() -> dict[str, Any]:
    dependencies = {
        "numpy": importlib_metadata.version("numpy"),
    }
    runtime = {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_executable_name": Path(sys.executable).name,
        "platform_system": platform.system(),
        "platform_release": platform.release(),
        "machine": platform.machine(),
    }
    return {
        "dependencies": dependencies,
        "dependency_fingerprint_sha256": canonical_json_sha256(dependencies),
        "runtime": runtime,
        "runtime_fingerprint_sha256": canonical_json_sha256(runtime),
    }


def _verification_summary(verification: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in verification.items()
        if key != "verified_files"
    }


def run_analysis(
    output_dir: Path,
    config: AnalysisConfig,
    config_source_path: Path,
) -> dict[str, Any]:
    """Execute the frozen analysis into a new or empty directory."""

    output_dir = Path(output_dir)
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError(
            f"refusing to overwrite non-empty output directory: {output_dir}"
        )
    output_dir.mkdir(parents=True, exist_ok=True)

    config_source_path = Path(config_source_path).resolve()
    config_bytes = config_source_path.read_bytes()
    if load_config(config_source_path) != config:
        raise AnalysisError(
            "supplied frozen config object does not match the exact config artifact"
        )
    config_file_hash = hashlib.sha256(config_bytes).hexdigest()
    config_mapping = asdict(config)
    config_canonical_hash = canonical_json_sha256(config_mapping)
    source_hash = sha256_file(SOURCE_PATH)
    requirements_path = resolve_project_path(config.requirements_file)
    if not requirements_path.is_file():
        raise AnalysisError(f"requirements artifact is missing: {requirements_path}")
    requirements_hash = sha256_file(requirements_path)

    coupled_dir = resolve_project_path(config.coupled.input_dir)
    loopback_dir = resolve_project_path(config.loopback.input_dir)
    coupled_verification = verify_upstream_manifest(
        coupled_dir, config.coupled.expected_schema_version
    )
    loopback_verification = verify_upstream_manifest(
        loopback_dir, config.loopback.expected_schema_version
    )

    coupled_families, coupled_design = analyze_coupled(
        coupled_dir,
        config.coupled,
        config.bootstrap,
        config.inference.alpha,
        coupled_verification,
    )
    loopback_families, loopback_design = analyze_loopback(
        loopback_dir,
        config.loopback,
        config.bootstrap,
        config.inference.alpha,
        loopback_verification,
    )

    _reverify_snapshot(coupled_dir, coupled_verification)
    _reverify_snapshot(loopback_dir, loopback_verification)
    if sha256_file(config_source_path) != config_file_hash:
        raise AnalysisError("analysis configuration changed during execution")
    if canonical_json_sha256(asdict(config)) != config_canonical_hash:
        raise AnalysisError("frozen in-memory analysis configuration changed")
    if sha256_file(SOURCE_PATH) != source_hash:
        raise AnalysisError("statistical-analysis source changed during execution")
    if sha256_file(requirements_path) != requirements_hash:
        raise AnalysisError("requirements lockfile changed during execution")

    runtime = _runtime_provenance()
    inputs = {
        "coupled_simulation": _verification_summary(coupled_verification),
        "loopback_testbed": _verification_summary(loopback_verification),
    }
    provenance = {
        "source_artifact": {
            "path": "experiments/statistical_analysis.py",
            "sha256": source_hash,
        },
        "config_artifact": {
            "path": str(config_source_path.relative_to(PROJECT_ROOT))
            if config_source_path.is_relative_to(PROJECT_ROOT)
            else str(config_source_path),
            "sha256": config_file_hash,
            "canonical_sha256": config_canonical_hash,
            "copied_byte_for_byte_to_output": True,
        },
        "requirements_artifact": {
            "path": str(requirements_path.relative_to(PROJECT_ROOT))
            if requirements_path.is_relative_to(PROJECT_ROOT)
            else str(requirements_path),
            "sha256": requirements_hash,
        },
        **runtime,
        "input_manifests": inputs,
        "combined_input_fingerprint_sha256": canonical_json_sha256(inputs),
    }
    summary = {
        "schema_version": config.schema_version,
        "deterministic_given_bound_inputs_and_runtime": True,
        "wall_clock_timestamp_included": False,
        "analysis_plan": {
            "effect_definition": config.inference.effect_definition,
            "bootstrap": asdict(config.bootstrap),
            "paired_test": config.inference.paired_test,
            "multiplicity_method": config.inference.multiplicity_method,
            "familywise_alpha": config.inference.alpha,
            "practical_threshold_semantics": (
                config.inference.practical_threshold_semantics
            ),
            "relative_effect_guard": (
                "relative effects are emitted only when every absolute comparator "
                "exceeds its metric-specific floor and comparator absolute-value CV "
                "does not exceed the study-specific limit"
            ),
        },
        "public_dataset_scope": asdict(config.public_dataset_scope),
        "coupled_design_verification": coupled_design,
        "loopback_design_verification": loopback_design,
        "comparison_families": coupled_families + loopback_families,
        "provenance": provenance,
        "limitations": [
            "The exact sign test uses only the direction of non-tied paired effects; magnitudes are summarized separately by paired mean/median effects and bootstrap intervals.",
            "Bootstrap intervals quantify variation across the finite stochastic seed blocks, not uncertainty over deployment populations or unmeasured environments.",
            "Holm correction controls familywise error only within each explicitly named family, not across every quantity reported by the project.",
            "Practical thresholds are frozen reporting thresholds, not externally validated service-level objectives; crossing one does not establish deployment utility.",
            "Loopback inference is conditional on the measured host, user-space implementation, oracle routing, protocols, loads, and configuration.",
            "Synthetic coupled-simulation inference is conditional on the declared generator, selector, queue model, and held-out seeds.",
            "No public RT-IoT2022 row-level hypothesis test is performed because independent sampling units are not established.",
        ],
    }
    _assert_finite_json(summary)

    config_copy = output_dir / "config.json"
    config_copy.write_bytes(config_bytes)
    summary_path = output_dir / "summary.json"
    write_json_strict(summary_path, summary)
    generated_files = {
        "config.json": sha256_file(config_copy),
        "summary.json": sha256_file(summary_path),
    }
    manifest = {
        "schema_version": config.schema_version,
        "deterministic_given_bound_inputs_and_runtime": True,
        "files": generated_files,
        "provenance": provenance,
    }
    write_json_strict(output_dir / "manifest.json", manifest)
    verify_output_manifest(output_dir)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", type=Path, required=True, help="exact immutable JSON analysis plan"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="new or empty output directory",
    )
    args = parser.parse_args()
    config = load_config(args.config)
    summary = run_analysis(args.output_dir, config, args.config)
    print(f"comparison_families={len(summary['comparison_families'])}")
    print(
        "hypotheses="
        + str(sum(item["hypothesis_count"] for item in summary["comparison_families"]))
    )
    print(f"output_dir={args.output_dir}")


if __name__ == "__main__":
    main()
