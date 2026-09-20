#!/usr/bin/env python3
"""Pre-specified paired analysis for the causal-selector real-HTB campaign."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import sys
import zlib
from array import array
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

import numpy as np

from experiments.selector_htb import (
    file_sha256,
    load_selector_htb_config,
    nearest_rank,
    write_new_json,
)


ENDPOINTS = (
    "benign_goodput_Bps",
    "benign_latency_p99_ms",
    "attack_fast_leakage_Bps",
    "attack_total_service_Bps",
    "total_goodput_Bps",
)
PRIMARY_ENDPOINTS = (
    "benign_goodput_Bps",
    "benign_latency_p99_ms",
    "attack_fast_leakage_Bps",
)
PRACTICAL_THRESHOLDS = {
    "benign_goodput_Bps": 80_000.0,
    "benign_latency_p99_ms": 5.0,
    "attack_fast_leakage_Bps": 80_000.0,
}


def decode_uint64(payload: dict[str, Any]) -> list[int]:
    if payload.get("encoding") != "zlib_base64_uint64_le_v1":
        raise ValueError("unknown uint64 sample encoding")
    raw = zlib.decompress(base64.b64decode(payload["data_base64"], validate=True))
    if hashlib.sha256(raw).hexdigest() != payload["uncompressed_sha256"]:
        raise ValueError("sample-vector checksum mismatch")
    if len(raw) % 8:
        raise ValueError("uint64 sample vector has an invalid byte length")
    values = array("Q")
    values.frombytes(raw)
    if sys.byteorder != "little":
        values.byteswap()
    result = list(values)
    if len(result) != payload["sample_count"]:
        raise ValueError("sample-vector count mismatch")
    return result


def measurement_value(mapping: dict[str, int], label: str, traffic_class: str | None = None) -> int:
    return sum(
        value
        for key, value in mapping.items()
        if (
            (parts := key.split(":"))[0] == "measurement"
            and len(parts) == 3
            and parts[1] == label
            and (traffic_class is None or parts[2] == traffic_class)
        )
    )


def trial_metrics(record: dict[str, Any], measurement_s: float) -> dict[str, float | int | str]:
    if not record.get("valid"):
        raise ValueError(f"invalid trial cannot enter analysis: {record['trial']['trial_id']}")
    received = record["receiver"]["received_payload_bytes"]
    benign_bytes = measurement_value(received, "benign")
    attack_fast_bytes = measurement_value(received, "attack", "fast")
    attack_suspicious_bytes = measurement_value(received, "attack", "suspicious")
    latency_samples: list[int] = []
    for key, payload in record["receiver"]["latency_by_truth_and_class"].items():
        if key.startswith("measurement:benign:"):
            latency_samples.extend(decode_uint64(payload["samples"]))
    p99_ns = nearest_rank(latency_samples, 0.99)
    if p99_ns is None:
        raise ValueError("benign p99 has no samples")
    return {
        "trial_id": record["trial"]["trial_id"],
        "pair_id": record["trial"]["pair_id"],
        "seed": record["trial"]["seed"],
        "attack_scale": float(record["trial"]["attack_scale"]),
        "selector": record["trial"]["selector"],
        "scheduler": record["trial"]["scheduler"],
        "trace_sha256": record["sender"]["trace"]["trace_sha256"],
        "benign_goodput_Bps": benign_bytes / measurement_s,
        "benign_latency_p99_ms": p99_ns / 1_000_000.0,
        "attack_fast_leakage_Bps": attack_fast_bytes / measurement_s,
        "attack_total_service_Bps": (attack_fast_bytes + attack_suspicious_bytes) / measurement_s,
        "total_goodput_Bps": sum(
            value for key, value in received.items() if key.startswith("measurement:")
        ) / measurement_s,
        "benign_latency_sample_count": len(latency_samples),
    }


def exact_two_sided_sign_test(values: Iterable[float]) -> dict[str, Any]:
    rows = list(values)
    positive = sum(value > 0 for value in rows)
    negative = sum(value < 0 for value in rows)
    zero = len(rows) - positive - negative
    n = positive + negative
    if n == 0:
        p_value = 1.0
    else:
        tail = sum(math.comb(n, index) for index in range(0, min(positive, negative) + 1)) / 2**n
        p_value = min(1.0, 2.0 * tail)
    return {"positive": positive, "negative": negative, "zero": zero, "n_nonzero": n, "p_value": p_value}


def bootstrap_mean_ci(
    values: list[float], replicates: int, seed: int, confidence: float = 0.95
) -> tuple[float, float]:
    if not values:
        raise ValueError("bootstrap requires at least one paired effect")
    rng = np.random.default_rng(seed)
    rows = np.asarray(values, dtype=float)
    draws = np.mean(rng.choice(rows, size=(replicates, len(rows)), replace=True), axis=1)
    alpha = (1.0 - confidence) / 2.0
    low, high = np.quantile(draws, [alpha, 1.0 - alpha])
    return float(low), float(high)


def holm(p_values: dict[str, float], alpha: float = 0.05) -> dict[str, Any]:
    ordered = sorted(p_values, key=lambda key: (p_values[key], key))
    adjusted: dict[str, float] = {}
    running = 0.0
    count = len(ordered)
    for rank, key in enumerate(ordered):
        candidate = min(1.0, (count - rank) * p_values[key])
        running = max(running, candidate)
        adjusted[key] = running
    return {
        key: {"raw_p": p_values[key], "holm_adjusted_p": adjusted[key], "reject": adjusted[key] <= alpha}
        for key in p_values
    }


def analyze(input_dir: Path, config_path: Path, output_dir: Path) -> dict[str, Any]:
    config = load_selector_htb_config(config_path)
    campaign = json.loads((input_dir / "summary.json").read_text(encoding="utf-8"))
    if campaign.get("profile") != "authoritative" or not campaign.get("mechanical_pass"):
        raise ValueError("analysis requires a mechanically passing authoritative campaign")
    raw_paths = sorted((input_dir / "raw").glob("*.json"))
    expected_trials = 2 * len(config.heldout_seeds) * len(config.attack_scales) * len(config.selectors)
    if len(raw_paths) != expected_trials:
        raise ValueError(f"expected {expected_trials} raw trials, found {len(raw_paths)}")
    coupled_payload = json.loads(config.base_config_path.read_text(encoding="utf-8"))
    measurement_s = float(coupled_payload["duration_s"]) - float(coupled_payload["warmup_s"])
    records = [json.loads(path.read_text(encoding="utf-8")) for path in raw_paths]
    metrics = [trial_metrics(record, measurement_s) for record in records]
    by_pair: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in metrics:
        by_pair[str(row["pair_id"])][str(row["scheduler"])] = row
    effects: list[dict[str, Any]] = []
    for pair_id, arms in sorted(by_pair.items()):
        if set(arms) != {"fixed", "borrowing"}:
            raise ValueError(f"pair {pair_id} does not contain both arms")
        if arms["fixed"]["trace_sha256"] != arms["borrowing"]["trace_sha256"]:
            raise ValueError(f"trace mismatch inside pair {pair_id}")
        row = {
            "pair_id": pair_id, "seed": arms["fixed"]["seed"],
            "attack_scale": arms["fixed"]["attack_scale"],
            "selector": arms["fixed"]["selector"],
            "trace_sha256": arms["fixed"]["trace_sha256"],
            "effect_definition": "borrowing_minus_fixed",
            "effects": {
                endpoint: float(arms["borrowing"][endpoint]) - float(arms["fixed"][endpoint])
                for endpoint in ENDPOINTS
            },
        }
        effects.append(row)
    grouped: dict[tuple[str, float], list[dict[str, Any]]] = defaultdict(list)
    for row in effects:
        grouped[(str(row["selector"]), float(row["attack_scale"]))].append(row)
    summaries: list[dict[str, Any]] = []
    primary_p: dict[str, float] = {}
    for group_index, ((selector, scale), rows) in enumerate(sorted(grouped.items()), start=1):
        if len(rows) != len(config.heldout_seeds):
            raise ValueError(f"group {selector}/{scale:g} has {len(rows)} rather than 30 pairs")
        endpoints: dict[str, Any] = {}
        for endpoint_index, endpoint in enumerate(ENDPOINTS, start=1):
            values = [float(row["effects"][endpoint]) for row in rows]
            ci = bootstrap_mean_ci(
                values, config.bootstrap_replicates,
                config.bootstrap_seed + group_index * 100 + endpoint_index,
            )
            sign = exact_two_sided_sign_test(values)
            endpoints[endpoint] = {
                "pair_count": len(values), "mean_effect": float(np.mean(values)),
                "median_effect": float(np.median(values)),
                "bootstrap_percentile_95_ci": list(ci), "sign_test": sign,
                "practical_threshold": PRACTICAL_THRESHOLDS.get(endpoint),
            }
            if selector == "multifeature" and scale == 4.0 and endpoint in PRIMARY_ENDPOINTS:
                primary_p[endpoint] = sign["p_value"]
        summaries.append({"selector": selector, "attack_scale": scale, "endpoints": endpoints})
    if set(primary_p) != set(PRIMARY_ENDPOINTS):
        raise ValueError("the three pre-specified primary hypotheses are incomplete")
    result = {
        "schema_version": "selector-htb-analysis-1.0",
        "input_campaign_name": input_dir.name,
        "input_summary_sha256": file_sha256(input_dir / "summary.json"),
        "config_sha256": file_sha256(config_path), "measurement_s": measurement_s,
        "effect_definition": "borrowing_minus_fixed",
        "primary_family": {
            "selector": "multifeature", "attack_scale": 4.0,
            "endpoints": list(PRIMARY_ENDPOINTS), "multiplicity": "Holm, familywise alpha=0.05",
            "tests": holm(primary_p),
        },
        "group_summaries": summaries,
        "claim_permitted": True,
        "evidence_boundary": config.evidence_boundary,
    }
    output_dir.mkdir(parents=True, exist_ok=False)
    write_new_json(output_dir / "paired_effects.json", effects)
    write_new_json(output_dir / "analysis.json", result)
    write_new_json(output_dir / "manifest.json", {
        "analysis_sha256": file_sha256(output_dir / "analysis.json"),
        "paired_effects_sha256": file_sha256(output_dir / "paired_effects.json"),
        "analysis_source_sha256": file_sha256(Path(__file__)),
        "config_sha256": file_sha256(config_path),
    })
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = analyze(args.input_dir, args.config, args.output_dir)
    print(json.dumps(result["primary_family"], sort_keys=True))


if __name__ == "__main__":
    main()
