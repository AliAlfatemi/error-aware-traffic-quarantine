#!/usr/bin/env python3
"""Verify or explicitly reproduce the complete evaluation artifact.

The safe default is verification of already-generated authoritative results.
No experiment, and especially no live socket experiment, is started unless an
explicit reproduction subcommand and acknowledgement flag are supplied.

This module is deliberately an orchestrator, not another experiment.  It
normalizes the six independently versioned result manifests, verifies every
declared byte, verifies their source/configuration/data bindings, and writes a
small top-level ``summary.json`` and ``manifest.json``.  It never edits an
authoritative sub-result directory.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from importlib import metadata as importlib_metadata
import json
import math
from pathlib import Path
import platform
import re
import subprocess
import sys
from typing import Any, Iterable, Mapping, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS_ROOT = PROJECT_ROOT / "results"
SCHEMA_VERSION = "top-level-reproducibility-1.0"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class VerificationError(RuntimeError):
    """Raised when an artifact or provenance invariant is violated."""


@dataclass(frozen=True)
class StageSpec:
    name: str
    directory: str
    schema_version: str
    manifest_files_key: str
    summary_required: bool
    canonical_config: str
    required_by_default: bool = True


STAGE_SPECS: tuple[StageSpec, ...] = (
    StageSpec(
        "timing_baseline_v1",
        "timing_baseline_v1",
        "timing-baseline-1.0",
        "generated_files",
        True,
        "configs/timing_baseline.json",
    ),
    StageSpec(
        "public_rt_iot2022",
        "public_rt_iot2022",
        "public-rt-iot2022-2.0",
        "generated_files",
        True,
        "configs/public_rt_iot2022.json",
    ),
    StageSpec(
        "coupled_simulation",
        "coupled_simulation",
        "coupled-1.1",
        "files",
        True,
        "configs/coupled_simulation.json",
    ),
    StageSpec(
        "synthetic_ablations",
        "synthetic_ablations",
        "synthetic-ablations-1.0",
        "files",
        True,
        "configs/synthetic_ablations.json",
    ),
    StageSpec(
        "loopback_testbed",
        "loopback_testbed",
        "loopback-2.0",
        "files",
        False,
        "configs/loopback_testbed.json",
    ),
    StageSpec(
        "statistical_analysis",
        "statistical_analysis",
        "statistical-analysis-1.0",
        "files",
        True,
        "configs/statistical_analysis.json",
        required_by_default=False,
    ),
)
SPEC_BY_NAME = {spec.name: spec for spec in STAGE_SPECS}
COMPUTATIONAL_STAGE_NAMES = tuple(spec.name for spec in STAGE_SPECS[:4])
AUTHORITATIVE_STAGE_NAMES = tuple(spec.name for spec in STAGE_SPECS)


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
    if isinstance(value, float):
        if not math.isfinite(value):
            raise VerificationError(f"non-finite number at {location}")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise VerificationError(f"non-string JSON key at {location}")
            _assert_finite_json(item, f"{location}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _assert_finite_json(item, f"{location}[{index}]")
        return
    raise VerificationError(
        f"non-JSON value of type {type(value).__name__} at {location}"
    )


def load_json_strict(path: Path) -> Any:
    """Load JSON while rejecting duplicate keys and all non-finite numbers."""

    try:
        payload = json.loads(
            Path(path).read_text(encoding="utf-8"),
            parse_constant=_reject_json_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise VerificationError(f"invalid strict JSON at {path}: {exc}") from exc
    _assert_finite_json(payload, str(path))
    return payload


def _encoded_json(value: Any, *, pretty: bool) -> bytes:
    _assert_finite_json(value)
    if pretty:
        text = json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    else:
        text = json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
    return text.encode("utf-8")


def write_json_strict(path: Path, value: Any) -> None:
    """Atomically write finite, deterministic JSON."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(_encoded_json(value, pretty=True))
    temporary.replace(path)


def canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(_encoded_json(value, pretty=False)).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _mapping(value: Any, location: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise VerificationError(f"expected JSON object at {location}")
    return value


def _sequence(value: Any, location: str) -> Sequence[Any]:
    if not isinstance(value, list):
        raise VerificationError(f"expected JSON array at {location}")
    return value


def _valid_sha256(value: Any, location: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise VerificationError(f"invalid SHA-256 at {location}: {value!r}")
    return value


def _project_relative(path: Path, project_root: Path) -> str:
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(project_root.resolve()).as_posix()
    except ValueError as exc:
        raise VerificationError(
            f"artifact path is outside the project and is not portable: {resolved}"
        ) from exc


def _safe_member(root: Path, relative_name: str, location: str) -> Path:
    relative = Path(relative_name)
    if relative.is_absolute():
        raise VerificationError(f"absolute path forbidden at {location}: {relative_name}")
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise VerificationError(
            f"path escapes its declared root at {location}: {relative_name}"
        ) from exc
    return candidate


def _safe_project_member(
    project_root: Path, relative_name: str, location: str
) -> Path:
    return _safe_member(project_root, relative_name, location)


def _merge_binding(
    bindings: dict[str, str], relative_name: str, sha256: str, location: str
) -> None:
    previous = bindings.get(relative_name)
    if previous is not None and previous != sha256:
        raise VerificationError(
            f"conflicting hashes for {relative_name} at {location}: "
            f"{previous} != {sha256}"
        )
    bindings[relative_name] = sha256


def _verify_project_binding(
    project_root: Path,
    relative_name: Any,
    expected_hash: Any,
    location: str,
    bindings: dict[str, str],
) -> Path:
    if not isinstance(relative_name, str) or not relative_name:
        raise VerificationError(f"missing relative artifact path at {location}")
    expected = _valid_sha256(expected_hash, f"{location}.sha256")
    path = _safe_project_member(project_root, relative_name, location)
    if not path.is_file():
        raise VerificationError(f"manifest-bound project artifact is missing: {path}")
    actual = file_sha256(path)
    if actual != expected:
        raise VerificationError(
            f"project artifact hash mismatch for {relative_name}: {actual} != {expected}"
        )
    normalized_name = _project_relative(path, project_root)
    _merge_binding(bindings, normalized_name, actual, location)
    return path


def _verify_artifact_record(
    project_root: Path,
    record: Any,
    location: str,
    bindings: dict[str, str],
    *,
    path_keys: Iterable[str] = ("artifact_path", "path"),
) -> Path:
    item = _mapping(record, location)
    relative_name: Any = None
    for key in path_keys:
        if key in item:
            relative_name = item[key]
            break
    return _verify_project_binding(
        project_root, relative_name, item.get("sha256"), location, bindings
    )


def _verify_declared_files(
    result_dir: Path, mapping: Any, location: str
) -> dict[str, str]:
    records = _mapping(mapping, location)
    if not records:
        raise VerificationError(f"manifest binds no generated files at {location}")
    verified: dict[str, str] = {}
    for relative_name, expected_hash in sorted(records.items()):
        if not isinstance(relative_name, str) or not relative_name:
            raise VerificationError(f"invalid generated path at {location}")
        expected = _valid_sha256(
            expected_hash, f"{location}.{relative_name}"
        )
        path = _safe_member(result_dir, relative_name, location)
        if not path.is_file():
            raise VerificationError(f"manifest-bound result is missing: {path}")
        actual = file_sha256(path)
        if actual != expected:
            raise VerificationError(
                f"generated artifact hash mismatch for {path}: {actual} != {expected}"
            )
        verified[Path(relative_name).as_posix()] = actual
    actual_files = {
        path.relative_to(result_dir).as_posix()
        for path in result_dir.rglob("*")
        if path.is_file() and path.name != "manifest.json"
    }
    declared_files = set(verified)
    if actual_files != declared_files:
        undeclared = sorted(actual_files - declared_files)
        absent = sorted(declared_files - actual_files)
        raise VerificationError(
            f"declared-file set mismatch at {location}; "
            f"undeclared={undeclared}, absent={absent}"
        )
    return verified


def _verify_canonical_file_hash(path: Path, expected: Any, location: str) -> None:
    expected_hash = _valid_sha256(expected, location)
    actual = canonical_json_sha256(load_json_strict(path))
    if actual != expected_hash:
        raise VerificationError(
            f"canonical JSON hash mismatch at {location}: {actual} != {expected_hash}"
        )


def _verify_canonical_record_hash(
    record: Any, expected: Any, location: str
) -> None:
    expected_hash = _valid_sha256(expected, location)
    actual = canonical_json_sha256(record)
    if actual != expected_hash:
        raise VerificationError(
            f"canonical provenance hash mismatch at {location}: {actual} != {expected_hash}"
        )


def _verify_timing_provenance(
    manifest: Mapping[str, Any], project_root: Path, bindings: dict[str, str]
) -> dict[str, Any]:
    if manifest.get("deterministic") is not True:
        raise VerificationError("timing baseline must declare deterministic=true")
    inputs = _mapping(manifest.get("inputs"), "timing.inputs")
    generator = _verify_artifact_record(
        project_root, inputs.get("generator"), "timing.inputs.generator", bindings
    )
    config_record = _mapping(
        inputs.get("immutable_config"), "timing.inputs.immutable_config"
    )
    config = _verify_artifact_record(
        project_root,
        config_record,
        "timing.inputs.immutable_config",
        bindings,
    )
    _verify_canonical_file_hash(
        config,
        config_record.get("effective_config_sha256"),
        "timing.inputs.immutable_config.effective_config_sha256",
    )
    _verify_artifact_record(
        project_root, inputs.get("requirements"), "timing.inputs.requirements", bindings
    )
    runtime = _mapping(inputs.get("runtime"), "timing.inputs.runtime")
    record = _mapping(runtime.get("record"), "timing.inputs.runtime.record")
    _verify_canonical_record_hash(
        record, runtime.get("sha256"), "timing.inputs.runtime.sha256"
    )
    return {
        "generator": _project_relative(generator, project_root),
        "config": _project_relative(config, project_root),
        "runtime": dict(record),
    }


def _verify_public_provenance(
    manifest: Mapping[str, Any], project_root: Path, bindings: dict[str, str]
) -> dict[str, Any]:
    inputs = _mapping(
        manifest.get("reproducibility_inputs"), "public.reproducibility_inputs"
    )
    generator = _verify_artifact_record(
        project_root, inputs.get("generator"), "public.inputs.generator", bindings
    )
    config_record = _mapping(
        inputs.get("immutable_config"), "public.inputs.immutable_config"
    )
    config = _verify_artifact_record(
        project_root,
        config_record,
        "public.inputs.immutable_config",
        bindings,
    )
    _verify_canonical_file_hash(
        config,
        config_record.get("effective_config_sha256"),
        "public.inputs.immutable_config.effective_config_sha256",
    )
    _verify_artifact_record(
        project_root, inputs.get("requirements"), "public.inputs.requirements", bindings
    )
    sources = _mapping(manifest.get("source_files"), "public.source_files")
    if not sources:
        raise VerificationError("public dataset manifest binds no source data")
    for name, digest in sorted(sources.items()):
        _verify_project_binding(
            project_root, name, digest, f"public.source_files.{name}", bindings
        )
    runtime = _mapping(inputs.get("runtime"), "public.inputs.runtime")
    return {
        "generator": _project_relative(generator, project_root),
        "config": _project_relative(config, project_root),
        "runtime": dict(runtime),
        "determinism_scope": inputs.get("determinism_scope"),
    }


def _verify_coupled_provenance(
    manifest: Mapping[str, Any], project_root: Path, bindings: dict[str, str]
) -> dict[str, Any]:
    if manifest.get("deterministic") is not True:
        raise VerificationError("coupled simulation must declare deterministic=true")
    provenance = _mapping(manifest.get("input_provenance"), "coupled.input_provenance")
    source = _verify_project_binding(
        project_root,
        "experiments/coupled_simulation.py",
        provenance.get("source_sha256"),
        "coupled.input_provenance.source_sha256",
        bindings,
    )
    config_record = _mapping(
        provenance.get("input_config_artifact"), "coupled.input_config_artifact"
    )
    config = _verify_project_binding(
        project_root,
        config_record.get("path_as_invoked"),
        config_record.get("sha256"),
        "coupled.input_config_artifact",
        bindings,
    )
    _verify_canonical_file_hash(
        config,
        provenance.get("config_canonical_sha256"),
        "coupled.config_canonical_sha256",
    )
    _verify_artifact_record(
        project_root,
        provenance.get("requirements_artifact"),
        "coupled.requirements_artifact",
        bindings,
    )
    runtime = _mapping(provenance.get("runtime"), "coupled.runtime")
    _verify_canonical_record_hash(
        runtime,
        provenance.get("runtime_fingerprint_sha256"),
        "coupled.runtime_fingerprint_sha256",
    )
    dependencies = _mapping(provenance.get("dependencies"), "coupled.dependencies")
    _verify_canonical_record_hash(
        dependencies,
        provenance.get("dependency_fingerprint_sha256"),
        "coupled.dependency_fingerprint_sha256",
    )
    return {
        "generator": _project_relative(source, project_root),
        "config": _project_relative(config, project_root),
        "runtime": dict(runtime),
        "dependencies": dict(dependencies),
    }


def _verify_synthetic_provenance(
    manifest: Mapping[str, Any], project_root: Path, bindings: dict[str, str]
) -> dict[str, Any]:
    if manifest.get("authoritative") is not True:
        raise VerificationError("synthetic ablations must declare authoritative=true")
    provenance = _mapping(manifest.get("input_provenance"), "ablations.input_provenance")
    source_map = _mapping(provenance.get("source_sha256"), "ablations.source_sha256")
    for name, digest in sorted(source_map.items()):
        _verify_project_binding(
            project_root, name, digest, f"ablations.source_sha256.{name}", bindings
        )
    input_map = _mapping(
        provenance.get("input_file_sha256"), "ablations.input_file_sha256"
    )
    input_paths: dict[str, Path] = {}
    for name, digest in sorted(input_map.items()):
        input_paths[name] = _verify_project_binding(
            project_root, name, digest, f"ablations.input_file_sha256.{name}", bindings
        )
    if "configs/synthetic_ablations.json" in input_paths:
        _verify_canonical_file_hash(
            input_paths["configs/synthetic_ablations.json"],
            provenance.get("ablation_config_canonical_sha256"),
            "ablations.ablation_config_canonical_sha256",
        )
    if "configs/coupled_simulation.json" in input_paths:
        _verify_canonical_file_hash(
            input_paths["configs/coupled_simulation.json"],
            provenance.get("coupled_config_canonical_sha256"),
            "ablations.coupled_config_canonical_sha256",
        )
    runtime = _mapping(provenance.get("runtime"), "ablations.runtime")
    _verify_canonical_record_hash(
        runtime,
        provenance.get("runtime_fingerprint_sha256"),
        "ablations.runtime_fingerprint_sha256",
    )
    dependencies = _mapping(provenance.get("dependencies"), "ablations.dependencies")
    _verify_canonical_record_hash(
        dependencies,
        provenance.get("dependency_fingerprint_sha256"),
        "ablations.dependency_fingerprint_sha256",
    )
    return {"runtime": dict(runtime), "dependencies": dict(dependencies)}


def _verify_loopback_provenance(
    manifest: Mapping[str, Any], project_root: Path, bindings: dict[str, str]
) -> dict[str, Any]:
    if manifest.get("authoritative_design") is not True:
        raise VerificationError("loopback manifest is not the authoritative design")
    trial_count = manifest.get("trial_count")
    valid_count = manifest.get("valid_trial_count")
    if not isinstance(trial_count, int) or trial_count <= 0 or valid_count != trial_count:
        raise VerificationError(
            "loopback authoritative trials must all be valid and non-empty"
        )
    provenance = _mapping(manifest.get("provenance"), "loopback.provenance")
    source = _mapping(provenance.get("source"), "loopback.provenance.source")
    source_files = _mapping(source.get("files"), "loopback.provenance.source.files")
    for name, digest in sorted(source_files.items()):
        _verify_project_binding(
            project_root, name, digest, f"loopback.source.files.{name}", bindings
        )
    if canonical_json_sha256(dict(sorted(source_files.items()))) != source.get(
        "source_set_sha256"
    ):
        raise VerificationError("loopback source-set fingerprint mismatch")
    configuration = _mapping(
        provenance.get("configuration"), "loopback.provenance.configuration"
    )
    input_config = _mapping(
        configuration.get("input_configuration"),
        "loopback.configuration.input_configuration",
    )
    config = _verify_project_binding(
        project_root,
        input_config.get("path"),
        input_config.get("file_sha256"),
        "loopback.configuration.input_configuration",
        bindings,
    )
    _verify_canonical_file_hash(
        config,
        input_config.get("parsed_config_sha256"),
        "loopback.configuration.input_configuration.parsed_config_sha256",
    )
    runtime_outer = _mapping(
        provenance.get("host_runtime"), "loopback.provenance.host_runtime"
    )
    runtime = _mapping(runtime_outer.get("metadata"), "loopback.host_runtime.metadata")
    _verify_canonical_record_hash(
        runtime, runtime_outer.get("sha256"), "loopback.host_runtime.sha256"
    )
    dependencies_outer = _mapping(
        provenance.get("dependencies"), "loopback.provenance.dependencies"
    )
    dependencies = _mapping(
        dependencies_outer.get("metadata"), "loopback.dependencies.metadata"
    )
    _verify_canonical_record_hash(
        dependencies,
        dependencies_outer.get("sha256"),
        "loopback.dependencies.sha256",
    )
    return {
        "config": _project_relative(config, project_root),
        "runtime": dict(runtime),
        "dependencies": dict(dependencies),
        "trial_count": trial_count,
    }


def _verify_statistics_provenance(
    manifest: Mapping[str, Any],
    project_root: Path,
    bindings: dict[str, str],
    previous: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    if manifest.get("deterministic_given_bound_inputs_and_runtime") is not True:
        raise VerificationError("statistical analysis must bind deterministic inputs")
    provenance = _mapping(manifest.get("provenance"), "statistics.provenance")
    source = _verify_artifact_record(
        project_root,
        provenance.get("source_artifact"),
        "statistics.source_artifact",
        bindings,
    )
    config_record = _mapping(
        provenance.get("config_artifact"), "statistics.config_artifact"
    )
    config = _verify_artifact_record(
        project_root, config_record, "statistics.config_artifact", bindings
    )
    _verify_canonical_file_hash(
        config,
        config_record.get("canonical_sha256"),
        "statistics.config_artifact.canonical_sha256",
    )
    _verify_artifact_record(
        project_root,
        provenance.get("requirements_artifact"),
        "statistics.requirements_artifact",
        bindings,
    )
    runtime = _mapping(provenance.get("runtime"), "statistics.runtime")
    _verify_canonical_record_hash(
        runtime,
        provenance.get("runtime_fingerprint_sha256"),
        "statistics.runtime_fingerprint_sha256",
    )
    dependencies = _mapping(provenance.get("dependencies"), "statistics.dependencies")
    _verify_canonical_record_hash(
        dependencies,
        provenance.get("dependency_fingerprint_sha256"),
        "statistics.dependency_fingerprint_sha256",
    )
    upstream = _mapping(
        provenance.get("input_manifests"), "statistics.input_manifests"
    )
    for upstream_name in ("coupled_simulation", "loopback_testbed"):
        if upstream_name not in previous:
            raise VerificationError(
                f"statistics requires verified upstream stage {upstream_name}"
            )
        record = _mapping(upstream.get(upstream_name), f"statistics.{upstream_name}")
        expected = previous[upstream_name]
        comparisons = {
            "manifest_path": expected["manifest_path"],
            "manifest_sha256": expected["manifest_sha256"],
            "schema_version": expected["schema_version"],
            "verified_file_count": expected["declared_file_count"],
            "verified_files_fingerprint_sha256": expected[
                "declared_files_fingerprint_sha256"
            ],
        }
        for key, expected_value in comparisons.items():
            if record.get(key) != expected_value:
                raise VerificationError(
                    f"statistics upstream binding mismatch for {upstream_name}.{key}: "
                    f"{record.get(key)!r} != {expected_value!r}"
                )
    return {
        "generator": _project_relative(source, project_root),
        "config": _project_relative(config, project_root),
        "runtime": dict(runtime),
        "dependencies": dict(dependencies),
    }


def verify_stage(
    spec: StageSpec,
    results_root: Path,
    project_root: Path,
    previous: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, Any], Any | None, Mapping[str, Any]]:
    """Verify one independently versioned sub-result manifest."""

    result_dir = _safe_member(results_root, spec.directory, f"stage {spec.name}")
    manifest_path = result_dir / "manifest.json"
    if not manifest_path.is_file():
        raise VerificationError(f"required stage manifest is missing: {manifest_path}")
    manifest = _mapping(load_json_strict(manifest_path), str(manifest_path))
    if manifest.get("schema_version") != spec.schema_version:
        raise VerificationError(
            f"unexpected schema for {spec.name}: {manifest.get('schema_version')!r} "
            f"!= {spec.schema_version!r}"
        )
    files = _verify_declared_files(
        result_dir,
        manifest.get(spec.manifest_files_key),
        f"{spec.name}.{spec.manifest_files_key}",
    )
    if spec.name == "loopback_testbed":
        aggregate_files = _mapping(
            manifest.get("aggregate_files"), "loopback.aggregate_files"
        )
        for name, digest in aggregate_files.items():
            if files.get(Path(name).as_posix()) != digest:
                raise VerificationError(
                    f"loopback aggregate binding is absent or inconsistent: {name}"
                )
    summary: Any | None = None
    summary_hash: str | None = None
    if spec.summary_required:
        if "summary.json" not in files:
            raise VerificationError(f"{spec.name} manifest does not bind summary.json")
        summary_path = result_dir / "summary.json"
        summary = load_json_strict(summary_path)
        summary_hash = files["summary.json"]

    bindings: dict[str, str] = {}
    if spec.name == "timing_baseline_v1":
        stage_provenance = _verify_timing_provenance(
            manifest, project_root, bindings
        )
    elif spec.name == "public_rt_iot2022":
        stage_provenance = _verify_public_provenance(
            manifest, project_root, bindings
        )
    elif spec.name == "coupled_simulation":
        stage_provenance = _verify_coupled_provenance(
            manifest, project_root, bindings
        )
    elif spec.name == "synthetic_ablations":
        stage_provenance = _verify_synthetic_provenance(
            manifest, project_root, bindings
        )
    elif spec.name == "loopback_testbed":
        stage_provenance = _verify_loopback_provenance(
            manifest, project_root, bindings
        )
    elif spec.name == "statistical_analysis":
        stage_provenance = _verify_statistics_provenance(
            manifest, project_root, bindings, previous
        )
    else:  # pragma: no cover - StageSpec is closed above.
        raise AssertionError(spec.name)

    normalized = {
        "result_directory": _project_relative(result_dir, project_root),
        "manifest_path": _project_relative(manifest_path, project_root),
        "manifest_sha256": file_sha256(manifest_path),
        "schema_version": spec.schema_version,
        "declared_file_count": len(files),
        "declared_files_fingerprint_sha256": canonical_json_sha256(files),
        "summary_sha256": summary_hash,
        "project_input_count": len(bindings),
        "project_inputs_fingerprint_sha256": canonical_json_sha256(bindings),
        "project_inputs": dict(sorted(bindings.items())),
        "stage_provenance": stage_provenance,
    }
    return normalized, summary, manifest


def _metric_estimate(value: Any) -> Any:
    if isinstance(value, Mapping) and "estimate" in value:
        return value["estimate"]
    return value


def _compact_timing(summary: Any) -> dict[str, Any]:
    root = _mapping(summary, "timing summary")
    classification = _mapping(root.get("classification"), "timing.classification")
    metrics = _mapping(
        classification.get("aggregate_metrics"), "timing.aggregate_metrics"
    )
    return {
        "artifact_role": root.get("artifact_role"),
        "claim_scope": root.get("claim_scope"),
        "test_seed_count": classification.get("test_seed_count"),
        "confusion": classification.get("aggregate_confusion"),
        "metrics": {
            name: _metric_estimate(metrics.get(name))
            for name in ("precision", "recall_tpr", "false_positive_rate", "f1")
        },
        "decision_after_packets": classification.get("decision_after_packets"),
    }


def _compact_public(summary: Any) -> dict[str, Any]:
    root = _mapping(summary, "public summary")
    selectors = _mapping(root.get("selectors"), "public.selectors")
    compact_selectors: dict[str, Any] = {}
    for name, raw in sorted(selectors.items()):
        selector = _mapping(raw, f"public.selectors.{name}")
        metrics = _mapping(selector.get("metrics"), f"public.{name}.metrics")
        compact_selectors[name] = {
            "metrics": {
                metric: _metric_estimate(metrics.get(metric))
                for metric in (
                    "precision",
                    "recall_tpr",
                    "false_positive_rate",
                    "f1",
                    "balanced_accuracy",
                    "average_precision",
                    "roc_auc",
                )
            },
            "macro_family_averages": selector.get("macro_family_averages"),
            "retrospective_whole_flow_mass_association": selector.get(
                "retrospective_whole_flow_mass_association"
            ),
        }
    audit = _mapping(root.get("dataset_audit"), "public.dataset_audit")
    return {
        "claim_boundary": root.get("claim_boundary"),
        "dataset": {
            "source": audit.get("source"),
            "rows_retained": audit.get("rows_retained"),
            "split_counts": audit.get("split_counts"),
            "learned_input_overlap_audits": audit.get(
                "learned_input_overlap_audits"
            ),
            "global_grouping": audit.get("global_grouping"),
            "dispersion_feature_degeneracy": audit.get(
                "dispersion_feature_degeneracy"
            ),
        },
        "selectors": compact_selectors,
    }


def _means(metrics: Any, names: Iterable[str], location: str) -> dict[str, Any]:
    records = _mapping(metrics, location)
    result: dict[str, Any] = {}
    for name in names:
        value = records.get(name)
        if isinstance(value, Mapping):
            result[name] = value.get("mean")
        else:
            result[name] = value
    return result


def _compact_coupled(summary: Any) -> dict[str, Any]:
    root = _mapping(summary, "coupled summary")
    classification = _mapping(root.get("classification"), "coupled.classification")
    compact_classification: dict[str, Any] = {}
    for name, raw in sorted(classification.items()):
        selector = _mapping(raw, f"coupled.classification.{name}")
        compact_classification[name] = {
            "flow_rates": selector.get("flow_rates"),
            "mature_packet_rates": selector.get("mature_packet_rates"),
            "mature_byte_rates": selector.get("mature_byte_rates"),
        }
    evaluation = _mapping(root.get("coupled_evaluation"), "coupled.evaluation")
    groups = _sequence(evaluation.get("groups"), "coupled.evaluation.groups")
    compact_groups: list[dict[str, Any]] = []
    metric_names = (
        "offered_load_to_matched_capacity",
        "benign_goodput_Bps",
        "benign_latency_p99_s",
        "benign_protected_byte_loss_fraction",
        "attack_leakage_Bps",
    )
    for index, raw in enumerate(groups):
        group = _mapping(raw, f"coupled.evaluation.groups[{index}]")
        sweep_name = group.get("sweep_name")
        if not isinstance(sweep_name, str) or not sweep_name.startswith("attack_scale_"):
            continue
        compact_groups.append(
            {
                "sweep_name": sweep_name,
                "defense": group.get("defense"),
                "selector": group.get("selector"),
                "seed_count": group.get("seed_count"),
                "metric_means": _means(
                    group.get("metrics"), metric_names, f"coupled group {index}"
                ),
            }
        )
    return {
        "heldout_seed_count": _mapping(
            root.get("split_integrity"), "coupled.split_integrity"
        ).get("heldout_seed_count"),
        "classification": compact_classification,
        "attack_load_sweep": compact_groups,
    }


def _compact_group_section(
    section: Any,
    identity_names: Iterable[str],
    metric_names: Iterable[str],
    location: str,
) -> list[dict[str, Any]]:
    container = _mapping(section, location)
    groups = _sequence(container.get("groups"), f"{location}.groups")
    compact: list[dict[str, Any]] = []
    for index, raw in enumerate(groups):
        group = _mapping(raw, f"{location}.groups[{index}]")
        row = {name: group.get(name) for name in identity_names}
        row["metric_means"] = _means(
            group.get("metrics"), metric_names, f"{location}.groups[{index}].metrics"
        )
        compact.append(row)
    return compact


def _compact_ablations(summary: Any) -> dict[str, Any]:
    root = _mapping(summary, "ablation summary")
    windows = _compact_group_section(
        root.get("observation_window_sensitivity"),
        ("window_iats", "selector", "seed_count"),
        (
            "flow_recall",
            "flow_fpr",
            "flow_f1",
            "decision_delay_mean_s",
            "provisional_attack_packet_fraction",
            "logical_state_payload_bytes_per_entry",
        ),
        "ablations.observation_window_sensitivity",
    )
    state = _compact_group_section(
        root.get("state_cardinality_scaling"),
        ("target_concurrent_flows", "seed_count"),
        (
            "peak_occupancy_entries",
            "peak_logical_state_payload_bytes",
            "state_evictions",
            "state_progress_packets_lost",
            "eligible_flow_maturation_fraction",
        ),
        "ablations.state_cardinality_scaling",
    )
    failures = _compact_group_section(
        root.get("detector_failure_recovery"),
        ("scenario", "seed_count"),
        (
            "benign_goodput_Bps",
            "attack_leakage_Bps",
            "failure_window_attack_fast_packets",
            "failure_window_benign_quarantine_packets",
            "reacquisition_attack_fast_packets",
            "reacquisition_benign_quarantine_packets",
            "recovery_delay_mean_s",
            "recovery_delay_p95_s",
        ),
        "ablations.detector_failure_recovery",
    )
    return {
        "run_scope": root.get("run_scope"),
        "observation_window_sensitivity": windows,
        "state_cardinality_scaling": state,
        "detector_failure_recovery": failures,
    }


def _compact_loopback(result_dir: Path, manifest: Mapping[str, Any]) -> dict[str, Any]:
    aggregate_files = _mapping(
        manifest.get("aggregate_files"), "loopback.aggregate_files"
    )
    conditions: list[dict[str, Any]] = []
    for name in sorted(aggregate_files):
        payload = _mapping(
            load_json_strict(_safe_member(result_dir, name, "loopback aggregate")),
            f"loopback aggregate {name}",
        )
        metrics = _mapping(payload.get("metrics"), f"loopback aggregate {name}.metrics")
        by_label: dict[str, Any] = {}
        for label in ("benign", "attack"):
            label_metrics = _mapping(metrics.get(label), f"{name}.metrics.{label}")
            by_label[label] = _means(
                label_metrics,
                (
                    "application_frame_rate_fps",
                    "application_payload_Bps",
                    "end_to_end_loss_fraction",
                    "p99_latency_ms",
                ),
                f"{name}.metrics.{label}",
            )
        conditions.append(
            {
                "aggregate_file": name,
                "condition_identity": payload.get("condition_identity"),
                "seed_sample_count": payload.get("seed_sample_count"),
                "metric_means": by_label,
            }
        )
    return {
        "claim_boundary": manifest.get("claim_boundary"),
        "study_id": manifest.get("study_id"),
        "trial_count": manifest.get("trial_count"),
        "valid_trial_count": manifest.get("valid_trial_count"),
        "conditions": conditions,
    }


def _compact_statistics(summary: Any) -> dict[str, Any]:
    root = _mapping(summary, "statistical summary")
    families = _sequence(root.get("comparison_families"), "statistics.families")
    compact_families: list[dict[str, Any]] = []
    for family_index, raw_family in enumerate(families):
        family = _mapping(raw_family, f"statistics.families[{family_index}]")
        results = _sequence(
            family.get("results"), f"statistics.families[{family_index}].results"
        )
        compact_results: list[dict[str, Any]] = []
        for result_index, raw_result in enumerate(results):
            result = _mapping(
                raw_result,
                f"statistics.families[{family_index}].results[{result_index}]",
            )
            test = _mapping(result.get("nonparametric_test"), "statistical test")
            practical = _mapping(
                result.get("practical_significance"), "practical significance"
            )
            effect = _mapping(result.get("effect_native"), "native effect")
            mean = _mapping(effect.get("mean"), "native effect mean")
            relative = result.get("relative_effect")
            relative_mean: Any = None
            if isinstance(relative, Mapping) and relative.get("available") is True:
                oriented = relative.get("oriented_benefit_percent")
                if isinstance(oriented, Mapping) and isinstance(
                    oriented.get("mean"), Mapping
                ):
                    relative_mean = oriented["mean"]
            compact_results.append(
                {
                    "hypothesis_id": result.get("hypothesis_id"),
                    "condition": result.get("condition"),
                    "metric": result.get("metric"),
                    "pair_count": result.get("pair_count"),
                    "native_mean_effect": mean,
                    "holm_adjusted_p_value": test.get("p_value_holm"),
                    "statistically_significant_after_holm": test.get(
                        "statistically_significant_after_holm"
                    ),
                    "practical_classification": practical.get(
                        "classification_from_mean_native_effect"
                    ),
                    "relative_oriented_benefit_percent_mean": relative_mean,
                }
            )
        compact_families.append(
            {
                "family_id": family.get("family_id"),
                "study": family.get("study"),
                "holm_scope": family.get("holm_scope"),
                "hypothesis_count": family.get("hypothesis_count"),
                "results": compact_results,
            }
        )
    return {
        "analysis_plan": root.get("analysis_plan"),
        "public_dataset_scope": root.get("public_dataset_scope"),
        "comparison_families": compact_families,
        "limitations": root.get("limitations"),
    }


def _parse_requirements(path: Path) -> dict[str, str]:
    pinned: dict[str, str] = {}
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "==" not in line:
            raise VerificationError(
                f"requirement is not exactly pinned at {path}:{line_number}: {line!r}"
            )
        name, version = line.split("==", 1)
        if not name or not version or name in pinned:
            raise VerificationError(f"invalid pinned requirement at {path}:{line_number}")
        pinned[name] = version
    return pinned


def runtime_provenance(requirements_path: Path) -> dict[str, Any]:
    pinned = _parse_requirements(requirements_path)
    packages: dict[str, dict[str, str]] = {}
    mismatches: list[str] = []
    for name, expected in sorted(pinned.items()):
        try:
            observed = importlib_metadata.version(name)
        except importlib_metadata.PackageNotFoundError:
            observed = "NOT_INSTALLED"
        packages[name] = {"expected": expected, "observed": observed}
        if observed != expected:
            mismatches.append(f"{name}: expected {expected}, observed {observed}")
    if mismatches:
        raise VerificationError(
            "runtime does not satisfy pinned requirements: " + "; ".join(mismatches)
        )
    return {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_executable_name": Path(sys.executable).name,
        "platform_system": platform.system(),
        "platform_release": platform.release(),
        "machine": platform.machine(),
        "pinned_packages": packages,
        "all_pinned_requirements_satisfied": True,
    }


def _orchestrator_provenance(
    project_root: Path, stage_names: Sequence[str]
) -> dict[str, Any]:
    source_names = (
        "experiments/reproducible_pipeline.py",
        "run_reproducible_experiments.py",
    )
    source_files: dict[str, str] = {}
    for name in source_names:
        path = _safe_project_member(project_root, name, "orchestrator source")
        if not path.is_file():
            raise VerificationError(f"orchestrator source is missing: {path}")
        source_files[name] = file_sha256(path)
    config_files: dict[str, str] = {}
    for name in stage_names:
        config_name = SPEC_BY_NAME[name].canonical_config
        path = _safe_project_member(project_root, config_name, "canonical config")
        if not path.is_file():
            raise VerificationError(f"canonical config is missing: {path}")
        load_json_strict(path)
        config_files[config_name] = file_sha256(path)
    requirements_path = _safe_project_member(
        project_root, "requirements.txt", "requirements"
    )
    if not requirements_path.is_file():
        raise VerificationError(f"requirements artifact is missing: {requirements_path}")
    requirements_hash = file_sha256(requirements_path)
    runtime = runtime_provenance(requirements_path)
    return {
        "source_files": source_files,
        "source_set_sha256": canonical_json_sha256(source_files),
        "canonical_config_files": config_files,
        "canonical_config_set_sha256": canonical_json_sha256(config_files),
        "requirements": {
            "path": "requirements.txt",
            "sha256": requirements_hash,
        },
        "runtime": {
            "record": runtime,
            "sha256": canonical_json_sha256(runtime),
        },
    }


def _claim_boundaries(
    summaries: Mapping[str, Any], manifests: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    boundaries: dict[str, Any] = {
        "overall": (
            "Evidence supports capacity-isolated quarantine under the documented "
            "simulation and user-space localhost conditions; it does not establish "
            "XDP/eBPF, kernel-forwarding, NIC, physical-link, optical-hardware, or "
            "line-rate performance."
        )
    }
    if "timing_baseline_v1" in summaries:
        boundaries["timing_baseline_v1"] = _mapping(
            summaries["timing_baseline_v1"], "timing summary"
        ).get("claim_scope")
    if "public_rt_iot2022" in summaries:
        boundaries["public_rt_iot2022"] = _mapping(
            summaries["public_rt_iot2022"], "public summary"
        ).get("claim_boundary")
    if "coupled_simulation" in summaries:
        boundaries["coupled_simulation"] = _mapping(
            summaries["coupled_simulation"], "coupled summary"
        ).get("limitations")
    if "synthetic_ablations" in summaries:
        boundaries["synthetic_ablations"] = _mapping(
            summaries["synthetic_ablations"], "ablation summary"
        ).get("limitations")
    if "loopback_testbed" in manifests:
        boundaries["loopback_testbed"] = manifests["loopback_testbed"].get(
            "claim_boundary"
        )
    if "statistical_analysis" in summaries:
        statistical = _mapping(
            summaries["statistical_analysis"], "statistical summary"
        )
        boundaries["statistical_analysis"] = {
            "public_dataset_scope": statistical.get("public_dataset_scope"),
            "limitations": statistical.get("limitations"),
        }
    return boundaries


def _key_results(
    results_root: Path,
    summaries: Mapping[str, Any],
    manifests: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    compactors = {
        "timing_baseline_v1": _compact_timing,
        "public_rt_iot2022": _compact_public,
        "coupled_simulation": _compact_coupled,
        "synthetic_ablations": _compact_ablations,
        "statistical_analysis": _compact_statistics,
    }
    output: dict[str, Any] = {}
    for name, summary in summaries.items():
        output[name] = compactors[name](summary)
    if "loopback_testbed" in manifests:
        output["loopback_testbed"] = _compact_loopback(
            results_root / SPEC_BY_NAME["loopback_testbed"].directory,
            manifests["loopback_testbed"],
        )
    return output


def build_top_level_artifacts(
    results_root: Path = DEFAULT_RESULTS_ROOT,
    *,
    project_root: Path = PROJECT_ROOT,
    stage_names: Sequence[str] | None = None,
    require_statistics: bool = False,
    execution_scope: str = "verify_existing",
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify selected stages and write the authoritative top-level artifacts.

    ``statistical_analysis`` is verified whenever its directory exists.  It is
    optional only to permit the pre-inference checkpoint; pass
    ``require_statistics=True`` for a final-package gate.
    """

    project_root = Path(project_root).resolve()
    results_root = Path(results_root).resolve()
    _project_relative(results_root, project_root)
    if stage_names is None:
        selected = [spec.name for spec in STAGE_SPECS if spec.required_by_default]
        statistics_manifest = (
            results_root / SPEC_BY_NAME["statistical_analysis"].directory / "manifest.json"
        )
        if statistics_manifest.is_file() or require_statistics:
            selected.append("statistical_analysis")
    else:
        selected = list(stage_names)
    if not selected or len(selected) != len(set(selected)):
        raise VerificationError("stage selection must be non-empty and unique")
    unknown = sorted(set(selected) - set(SPEC_BY_NAME))
    if unknown:
        raise VerificationError(f"unknown stages: {unknown}")
    canonical_order = [spec.name for spec in STAGE_SPECS if spec.name in selected]
    if "statistical_analysis" in canonical_order:
        for prerequisite in ("coupled_simulation", "loopback_testbed"):
            if prerequisite not in canonical_order:
                raise VerificationError(
                    f"statistical_analysis requires selected stage {prerequisite}"
                )
    if require_statistics and "statistical_analysis" not in canonical_order:
        raise VerificationError("final verification requires statistical_analysis")

    normalized: dict[str, dict[str, Any]] = {}
    summaries: dict[str, Any] = {}
    manifests: dict[str, Mapping[str, Any]] = {}
    for name in canonical_order:
        record, summary, manifest = verify_stage(
            SPEC_BY_NAME[name], results_root, project_root, normalized
        )
        normalized[name] = record
        manifests[name] = manifest
        if summary is not None:
            summaries[name] = summary

    provenance = _orchestrator_provenance(project_root, canonical_order)
    requirements_hash = provenance["requirements"]["sha256"]
    for name in canonical_order:
        if name == "loopback_testbed":
            # The loopback implementation intentionally has no external Python
            # dependency; its standard-library dependency record is verified
            # inside that stage instead.
            continue
        observed = normalized[name]["project_inputs"].get("requirements.txt")
        if observed != requirements_hash:
            raise VerificationError(
                f"{name} is not bound to the top-level pinned requirements.txt"
            )
    fingerprint_payload = {
        "schema_version": SCHEMA_VERSION,
        "execution_scope": execution_scope,
        "verified_stage_order": canonical_order,
        "subresults": normalized,
        "orchestrator_provenance": provenance,
    }
    combined_fingerprint = canonical_json_sha256(fingerprint_payload)
    artifact_scope = (
        "complete_authoritative_evaluation"
        if canonical_order == list(AUTHORITATIVE_STAGE_NAMES)
        else "declared_partial_reproduction"
    )
    includes_live_measurements = "loopback_testbed" in canonical_order
    fresh_reproduction_byte_deterministic = not includes_live_measurements
    summary_payload = {
        "schema_version": SCHEMA_VERSION,
        "artifact_role": "top-level verified evaluation index",
        "artifact_scope": artifact_scope,
        "verification_status": "passed",
        "deterministic_given_bound_inputs_and_runtime": fresh_reproduction_byte_deterministic,
        "determinism_semantics": {
            "published_byte_verification_is_deterministic": True,
            "computational_stages_are_deterministic_on_the_bound_stack": True,
            "fresh_live_loopback_reproduction_is_expected_byte_identical": False
            if includes_live_measurements
            else None,
        },
        "wall_clock_timestamp_included": False,
        "execution_scope": execution_scope,
        "verified_stage_order": canonical_order,
        "combined_fingerprint_sha256": combined_fingerprint,
        "claim_boundaries": _claim_boundaries(summaries, manifests),
        "key_results": _key_results(results_root, summaries, manifests),
        "subresults": normalized,
        "reproducibility_binding": provenance,
    }
    write_json_strict(results_root / "summary.json", summary_payload)
    summary_hash = file_sha256(results_root / "summary.json")
    manifest_payload = {
        "schema_version": SCHEMA_VERSION,
        "artifact_role": "top-level manifest; excludes itself to avoid self-reference",
        "artifact_scope": artifact_scope,
        "deterministic_given_bound_inputs_and_runtime": fresh_reproduction_byte_deterministic,
        "determinism_semantics": summary_payload["determinism_semantics"],
        "wall_clock_timestamp_included": False,
        "combined_fingerprint_sha256": combined_fingerprint,
        "files": {"summary.json": summary_hash},
        "submanifests": {
            name: {
                "path": normalized[name]["manifest_path"],
                "sha256": normalized[name]["manifest_sha256"],
                "schema_version": normalized[name]["schema_version"],
                "declared_file_count": normalized[name]["declared_file_count"],
                "declared_files_fingerprint_sha256": normalized[name][
                    "declared_files_fingerprint_sha256"
                ],
            }
            for name in canonical_order
        },
        "provenance": provenance,
    }
    write_json_strict(results_root / "manifest.json", manifest_payload)
    # Final read-back protects against serialization or partial-write defects.
    written_summary = load_json_strict(results_root / "summary.json")
    written_manifest = load_json_strict(results_root / "manifest.json")
    if written_summary != summary_payload or written_manifest != manifest_payload:
        raise VerificationError("top-level artifact read-back mismatch")
    if file_sha256(results_root / "summary.json") != written_manifest["files"][
        "summary.json"
    ]:
        raise VerificationError("top-level summary hash mismatch after write")
    return summary_payload, manifest_payload


def _verify_stored_orchestrator_provenance(
    provenance: Any,
    project_root: Path,
    stage_names: Sequence[str],
) -> Mapping[str, Any]:
    """Validate published provenance without replacing it with this host."""

    record = _mapping(provenance, "top-level.provenance")
    source_files = _mapping(record.get("source_files"), "top-level.source_files")
    expected_sources = {
        "experiments/reproducible_pipeline.py",
        "run_reproducible_experiments.py",
    }
    if set(source_files) != expected_sources:
        raise VerificationError("top-level source set is incomplete or stale")
    verified_sources: dict[str, str] = {}
    for name, expected_hash in source_files.items():
        path = _safe_project_member(project_root, name, "top-level.source_files")
        expected = _valid_sha256(expected_hash, f"top-level.source_files.{name}")
        actual = file_sha256(path)
        if actual != expected:
            raise VerificationError(f"top-level source hash mismatch for {name}")
        verified_sources[name] = actual
    if canonical_json_sha256(verified_sources) != record.get("source_set_sha256"):
        raise VerificationError("top-level source-set fingerprint mismatch")

    configs = _mapping(
        record.get("canonical_config_files"), "top-level.canonical_config_files"
    )
    expected_configs = {SPEC_BY_NAME[name].canonical_config for name in stage_names}
    if set(configs) != expected_configs:
        raise VerificationError("top-level canonical configuration set is stale")
    verified_configs: dict[str, str] = {}
    for name, expected_hash in configs.items():
        path = _safe_project_member(project_root, name, "top-level.configs")
        load_json_strict(path)
        expected = _valid_sha256(expected_hash, f"top-level.configs.{name}")
        actual = file_sha256(path)
        if actual != expected:
            raise VerificationError(f"top-level configuration hash mismatch for {name}")
        verified_configs[name] = actual
    if canonical_json_sha256(verified_configs) != record.get(
        "canonical_config_set_sha256"
    ):
        raise VerificationError("top-level configuration-set fingerprint mismatch")

    requirements = _mapping(record.get("requirements"), "top-level.requirements")
    requirements_path = _verify_project_binding(
        project_root,
        requirements.get("path"),
        requirements.get("sha256"),
        "top-level.requirements",
        {},
    )
    pinned = _parse_requirements(requirements_path)
    runtime = _mapping(record.get("runtime"), "top-level.runtime")
    runtime_record = _mapping(runtime.get("record"), "top-level.runtime.record")
    _verify_canonical_record_hash(
        runtime_record,
        runtime.get("sha256"),
        "top-level.runtime.sha256",
    )
    packages = _mapping(
        runtime_record.get("pinned_packages"), "top-level.runtime.pinned_packages"
    )
    if set(packages) != set(pinned):
        raise VerificationError("published runtime package set does not match requirements")
    for name, expected_version in pinned.items():
        package = _mapping(packages[name], f"top-level.runtime.pinned_packages.{name}")
        if package.get("expected") != expected_version or package.get("observed") != expected_version:
            raise VerificationError(f"published runtime did not satisfy pinned package {name}")
    return record


def verify_published_top_level(
    results_root: Path = DEFAULT_RESULTS_ROOT,
    *,
    project_root: Path = PROJECT_ROOT,
    require_statistics: bool = False,
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    """Read-only verification of the published top-level index and all stages."""

    project_root = Path(project_root).resolve()
    results_root = Path(results_root).resolve()
    _project_relative(results_root, project_root)
    summary = _mapping(load_json_strict(results_root / "summary.json"), "results.summary")
    manifest = _mapping(load_json_strict(results_root / "manifest.json"), "results.manifest")
    selected = list(summary.get("verified_stage_order", []))
    if not selected or len(selected) != len(set(selected)):
        raise VerificationError("published stage order is missing or duplicated")
    unknown = sorted(set(selected) - set(SPEC_BY_NAME))
    if unknown:
        raise VerificationError(f"published index contains unknown stages: {unknown}")
    canonical_order = [spec.name for spec in STAGE_SPECS if spec.name in selected]
    if selected != canonical_order:
        raise VerificationError("published stage order is noncanonical")
    if require_statistics and "statistical_analysis" not in selected:
        raise VerificationError("final verification requires statistical_analysis")

    normalized: dict[str, dict[str, Any]] = {}
    summaries: dict[str, Any] = {}
    manifests: dict[str, Mapping[str, Any]] = {}
    for name in canonical_order:
        record, stage_summary, stage_manifest = verify_stage(
            SPEC_BY_NAME[name], results_root, project_root, normalized
        )
        normalized[name] = record
        manifests[name] = stage_manifest
        if stage_summary is not None:
            summaries[name] = stage_summary

    published_submanifests = _mapping(
        manifest.get("submanifests"), "results.manifest.submanifests"
    )
    if set(published_submanifests) != set(canonical_order):
        raise VerificationError("published submanifest set is incomplete")
    for name, record in normalized.items():
        expected = {
            "path": record["manifest_path"],
            "sha256": record["manifest_sha256"],
            "schema_version": record["schema_version"],
            "declared_file_count": record["declared_file_count"],
            "declared_files_fingerprint_sha256": record[
                "declared_files_fingerprint_sha256"
            ],
        }
        if published_submanifests[name] != expected:
            raise VerificationError(f"published submanifest record is stale for {name}")

    provenance = _verify_stored_orchestrator_provenance(
        manifest.get("provenance"), project_root, canonical_order
    )
    if summary.get("reproducibility_binding") != provenance:
        raise VerificationError("summary and manifest provenance differ")
    fingerprint_payload = {
        "schema_version": SCHEMA_VERSION,
        "execution_scope": summary.get("execution_scope"),
        "verified_stage_order": canonical_order,
        "subresults": normalized,
        "orchestrator_provenance": provenance,
    }
    fingerprint = canonical_json_sha256(fingerprint_payload)
    if summary.get("combined_fingerprint_sha256") != fingerprint:
        raise VerificationError("published summary fingerprint is stale")
    if manifest.get("combined_fingerprint_sha256") != fingerprint:
        raise VerificationError("published manifest fingerprint is stale")
    if summary.get("subresults") != normalized:
        raise VerificationError("published normalized subresults are stale")
    if summary.get("claim_boundaries") != _claim_boundaries(summaries, manifests):
        raise VerificationError("published claim boundaries are stale")
    if summary.get("key_results") != _key_results(results_root, summaries, manifests):
        raise VerificationError("published compact key results are stale")
    files = _mapping(manifest.get("files"), "results.manifest.files")
    if set(files) != {"summary.json"}:
        raise VerificationError("published top-level file set is invalid")
    if file_sha256(results_root / "summary.json") != files["summary.json"]:
        raise VerificationError("published top-level summary hash is stale")
    includes_live = "loopback_testbed" in canonical_order
    expected_determinism = not includes_live
    if summary.get("deterministic_given_bound_inputs_and_runtime") is not expected_determinism:
        raise VerificationError("published summary determinism claim is inaccurate")
    if manifest.get("deterministic_given_bound_inputs_and_runtime") is not expected_determinism:
        raise VerificationError("published manifest determinism claim is inaccurate")
    return summary, manifest


def _ensure_new_reproduction_root(path: Path, project_root: Path) -> Path:
    target = Path(path).resolve()
    _project_relative(target, project_root)
    forbidden = {project_root.resolve(), (project_root / "results").resolve()}
    if target in forbidden:
        raise VerificationError(f"refusing unsafe reproduction target: {target}")
    if target.exists():
        if not target.is_dir():
            raise VerificationError(f"reproduction target is not a directory: {target}")
        if next(target.iterdir(), None) is not None:
            raise VerificationError(
                f"reproduction target must be new or empty: {target}"
            )
    else:
        target.mkdir(parents=True, exist_ok=False)
    return target


def _run(command: Sequence[str], project_root: Path) -> None:
    rendered = " ".join(command)
    print(f"RUN {rendered}", flush=True)
    subprocess.run(list(command), cwd=project_root, check=True)


def _reproduction_commands(
    output_root: Path, project_root: Path, include_live_loopback: bool
) -> list[list[str]]:
    python = sys.executable
    relative_output = _project_relative(output_root, project_root)
    def out(name: str) -> str:
        return f"{relative_output}/{name}"

    commands = [
        [
            python,
            "-m",
            "experiments.timing_baseline",
            "--config",
            "configs/timing_baseline.json",
            "--results-dir",
            out("timing_baseline_v1"),
        ],
        [
            python,
            "-m",
            "experiments.public_rt_iot2022",
            "--output-dir",
            out("public_rt_iot2022"),
            "--csv",
            "data/public/rt_iot2022/original/RT_IOT2022",
            "--archive",
            "data/public/rt_iot2022/original/rt-iot2022.zip",
            "--config",
            "configs/public_rt_iot2022.json",
        ],
        [
            python,
            "-m",
            "experiments.coupled_simulation",
            "--output-dir",
            out("coupled_simulation"),
            "--config",
            "configs/coupled_simulation.json",
        ],
        [
            python,
            "-m",
            "experiments.synthetic_ablations",
            "--output-dir",
            out("synthetic_ablations"),
            "--config",
            "configs/synthetic_ablations.json",
            "--coupled-config",
            "configs/coupled_simulation.json",
        ],
    ]
    if include_live_loopback:
        commands.append(
            [
                python,
                "-m",
                "prototype.loopback_testbed",
                "--output-dir",
                out("loopback_testbed"),
                "--config",
                "configs/loopback_testbed.json",
            ]
        )
    return commands


def reproduce(
    output_root: Path,
    *,
    include_live_loopback: bool,
    confirm_expensive: bool,
    confirm_live_loopback: bool,
    project_root: Path = PROJECT_ROOT,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run an explicit reproduction into a new root, never authoritative results."""

    if not confirm_expensive:
        raise VerificationError(
            "reproduction is expensive; rerun with --confirm-expensive"
        )
    if include_live_loopback and not confirm_live_loopback:
        raise VerificationError(
            "the full run opens local TCP/UDP sockets and takes substantial wall "
            "time; rerun with --confirm-live-loopback"
        )
    project_root = Path(project_root).resolve()
    target = _ensure_new_reproduction_root(output_root, project_root)
    commands = _reproduction_commands(target, project_root, include_live_loopback)
    for command in commands:
        _run(command, project_root)
    if not include_live_loopback:
        return build_top_level_artifacts(
            target,
            project_root=project_root,
            stage_names=COMPUTATIONAL_STAGE_NAMES,
            execution_scope="reproduce_computational",
        )

    base_config_path = project_root / "configs/statistical_analysis.json"
    statistics_config = _mapping(
        load_json_strict(base_config_path), "statistical analysis config"
    )
    # Round-trip through JSON so the committed plan object is not mutated.
    adjusted = json.loads(json.dumps(statistics_config))
    relative_target = _project_relative(target, project_root)
    adjusted["coupled"]["input_dir"] = f"{relative_target}/coupled_simulation"
    adjusted["loopback"]["input_dir"] = f"{relative_target}/loopback_testbed"
    input_dir = target / "reproduction_inputs"
    input_dir.mkdir(parents=True, exist_ok=False)
    adjusted_config_path = input_dir / "statistical_analysis.json"
    write_json_strict(adjusted_config_path, adjusted)
    _run(
        [
            sys.executable,
            "-m",
            "experiments.statistical_analysis",
            "--config",
            _project_relative(adjusted_config_path, project_root),
            "--output-dir",
            f"{relative_target}/statistical_analysis",
        ],
        project_root,
    )
    return build_top_level_artifacts(
        target,
        project_root=project_root,
        stage_names=AUTHORITATIVE_STAGE_NAMES,
        require_statistics=True,
        execution_scope="reproduce_all_including_live_loopback",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command")

    verify = subparsers.add_parser(
        "verify-existing",
        help="verify published stage and top-level artifacts without rewriting them",
    )
    verify.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    verify.add_argument(
        "--require-statistics",
        action="store_true",
        help="fail unless the frozen statistical stage is present",
    )

    rebuild = subparsers.add_parser(
        "rebuild-index",
        help="explicitly rebuild the two top-level JSON files after authorized source/result changes",
    )
    rebuild.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    rebuild.add_argument("--require-statistics", action="store_true")
    rebuild.add_argument("--confirm-overwrite", action="store_true")

    computational = subparsers.add_parser(
        "reproduce-computational",
        help="run timing/public/coupled/ablation stages into a new directory",
    )
    computational.add_argument("--output-root", type=Path, required=True)
    computational.add_argument("--confirm-expensive", action="store_true")

    all_parser = subparsers.add_parser(
        "reproduce-all",
        help="run all stages, including 480 live localhost socket trials, into a new directory",
    )
    all_parser.add_argument("--output-root", type=Path, required=True)
    all_parser.add_argument("--confirm-expensive", action="store_true")
    all_parser.add_argument("--confirm-live-loopback", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    # An empty invocation is intentionally safe: it verifies, but never runs,
    # experiments.  Explicit subcommands make costly execution visible.
    if not arguments:
        arguments = ["verify-existing"]
    parser = build_parser()
    args = parser.parse_args(arguments)
    if args.command == "verify-existing":
        summary, _ = verify_published_top_level(
            args.results_root,
            require_statistics=args.require_statistics,
        )
    elif args.command == "rebuild-index":
        if not args.confirm_overwrite:
            raise VerificationError("rebuild-index requires --confirm-overwrite")
        summary, _ = build_top_level_artifacts(
            args.results_root,
            require_statistics=args.require_statistics,
            execution_scope="published_authoritative_index",
        )
    elif args.command == "reproduce-computational":
        summary, _ = reproduce(
            args.output_root,
            include_live_loopback=False,
            confirm_expensive=args.confirm_expensive,
            confirm_live_loopback=False,
        )
    elif args.command == "reproduce-all":
        summary, _ = reproduce(
            args.output_root,
            include_live_loopback=True,
            confirm_expensive=args.confirm_expensive,
            confirm_live_loopback=args.confirm_live_loopback,
        )
    else:
        parser.print_help()
        return 2
    print(f"verification_status={summary['verification_status']}")
    print(f"artifact_scope={summary['artifact_scope']}")
    print(f"combined_fingerprint_sha256={summary['combined_fingerprint_sha256']}")
    return 0


def cli(argv: Sequence[str] | None = None) -> int:
    """CLI boundary with concise errors; library functions still raise."""

    try:
        return main(argv)
    except (VerificationError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(cli())
