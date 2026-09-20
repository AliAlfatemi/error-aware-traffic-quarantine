#!/usr/bin/env python3
"""Descriptive, non-pooled comparison of three loopback experiment hosts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


PROTOCOL_PATH = Path(__file__).resolve().parents[1] / "protocols" / "CROSS_HOST_LOOPBACK_PROTOCOL.md"
EXPECTED_HOSTS = ("node001", "node002", "node003")
METRICS_AT_800 = (
    "benign_application_frame_rate_fps",
    "benign_end_to_end_loss_fraction",
    "benign_p99_latency_ms",
    "attack_application_frame_rate_fps",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_new_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")


def verify_analysis_dir(path: Path) -> dict[str, Any]:
    manifest_path = path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "statistical-analysis-1.0":
        raise ValueError(f"unexpected analysis schema in {path}")
    for relative, expected in manifest.get("files", {}).items():
        target = path / relative
        if not target.is_file() or sha256_file(target) != expected:
            raise ValueError(f"manifest mismatch for {target}")
    summary = json.loads((path / "summary.json").read_text(encoding="utf-8"))
    verification = summary.get("loopback_design_verification", {})
    if (
        verification.get("raw_summary_file_count") != 480
        or verification.get("seed_count_per_protocol_load_condition") != 30
        or verification.get("protocols") != ["udp", "tcp"]
        or verification.get("suspicious_offered_pps") != [0.0, 160.0, 400.0, 800.0]
        or verification.get("matched_schedule_configuration_and_resource_checks") is not True
    ):
        raise ValueError(f"loopback design verification failed for {path}")
    return summary


def selected_results(summary: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = [
        row
        for family in summary["comparison_families"]
        if family["family_id"].startswith("loopback_oracle_")
        for row in family["results"]
        if (
            row["condition"]["suspicious_offered_pps"] == 800.0
            and row["metric"]["id"] in METRICS_AT_800
        ) or (
            row["condition"]["suspicious_offered_pps"] == 0.0
            and row["metric"]["id"] == "benign_p99_latency_ms"
        )
    ]
    result = {
        (
            f"protocol={row['condition']['protocol']}|"
            f"suspicious_offered_pps={row['condition']['suspicious_offered_pps']:g}|"
            f"metric={row['metric']['id']}"
        ): row
        for row in rows
    }
    if len(rows) != 10 or len(result) != 10:
        raise ValueError(f"expected exactly ten frozen cross-host checks, got {len(rows)}")
    return result


def directional_label(values: list[float]) -> str:
    if all(value > 0 for value in values):
        return "directionally_replicated_positive"
    if all(value < 0 for value in values):
        return "directionally_replicated_negative"
    if all(value == 0 for value in values):
        return "all_zero"
    return "direction_not_replicated"


def build_summary(host_dirs: dict[str, Path]) -> dict[str, Any]:
    if tuple(sorted(host_dirs)) != EXPECTED_HOSTS:
        raise ValueError(f"hosts must be exactly {EXPECTED_HOSTS}")
    summaries = {host: verify_analysis_dir(path) for host, path in host_dirs.items()}
    selected = {host: selected_results(summary) for host, summary in summaries.items()}
    keys = set(selected["node001"])
    if any(set(rows) != keys for rows in selected.values()):
        raise ValueError("selected comparison keys differ between hosts")
    comparisons: list[dict[str, Any]] = []
    for key in sorted(keys):
        host_results: dict[str, Any] = {}
        means: list[float] = []
        for host in EXPECTED_HOSTS:
            row = selected[host][key]
            mean = float(row["effect_native"]["mean"]["estimate"])
            means.append(mean)
            host_results[host] = {
                "mean_treatment_minus_comparator": mean,
                "bootstrap_percentile_95_ci": row["effect_native"]["mean"]["ci"],
                "exact_sign_test_p_unadjusted": row["nonparametric_test"]["p_value_unadjusted"],
                "holm_adjusted_p": row["nonparametric_test"]["p_value_holm"],
                "significant_after_within_host_holm": row["nonparametric_test"][
                    "statistically_significant_after_holm"
                ],
                "pair_count": row["pair_count"],
            }
        comparisons.append({
            "comparison_key": key,
            "effect_definition": "isolated_minus_shared",
            "host_results": host_results,
            "host_mean_range": [min(means), max(means)],
            "directional_replication": directional_label(means),
            "pooled_estimate": None,
        })
    return {
        "schema_version": "cross-host-loopback-description-1.0",
        "protocol_sha256": sha256_file(PROTOCOL_PATH),
        "hosts": list(EXPECTED_HOSTS),
        "host_count": 3,
        "comparisons": comparisons,
        "all_ten_directions_replicated": all(
            row["directional_replication"].startswith("directionally_replicated_")
            for row in comparisons
        ),
        "inference_boundary": (
            "descriptive host comparison only; no seed pooling, host-level hypothesis test, "
            "or claim that three hosts sample a deployment population"
        ),
        "evidence_boundary": summaries["node001"]["loopback_design_verification"]["claim_boundary"],
    }


def parse_host(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("host must be LABEL=PATH")
    label, raw_path = value.split("=", 1)
    return label, Path(raw_path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", action="append", type=parse_host, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    host_dirs = dict(args.host)
    if len(host_dirs) != len(args.host):
        raise ValueError("duplicate host label")
    result = build_summary(host_dirs)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    write_new_json(args.output_dir / "summary.json", result)
    write_new_json(args.output_dir / "manifest.json", {
        "summary_sha256": sha256_file(args.output_dir / "summary.json"),
        "source_sha256": sha256_file(Path(__file__)),
        "protocol_sha256": sha256_file(PROTOCOL_PATH),
        "input_manifests": {
            host: sha256_file(path / "manifest.json") for host, path in sorted(host_dirs.items())
        },
    })
    print(json.dumps({
        "comparison_count": len(result["comparisons"]),
        "all_ten_directions_replicated": result["all_ten_directions_replicated"],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
