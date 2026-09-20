#!/usr/bin/env python3
"""Semantically verify and cryptographically seal a selector-HTB campaign."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from experiments.selector_htb import PROJECT_ROOT, file_sha256, load_selector_htb_config, write_new_json


EXPECTED_STATIC_FILES = {
    "calibration.json", "environment.json", "plan.json", "summary.json", "topology.json"
}


def strict_json(path: Path) -> Any:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON token {value} in {path.name}")

    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise ValueError(f"duplicate JSON key in {path.name}")
            result[key] = value
        return result

    return json.loads(
        path.read_text(encoding="utf-8"), parse_constant=reject_constant, object_pairs_hook=pairs
    )


def seal(campaign_dir: Path, config_path: Path) -> dict[str, Any]:
    campaign_dir = campaign_dir.resolve()
    config_path = config_path.resolve()
    manifest_path = campaign_dir / "sealed_manifest.json"
    if manifest_path.exists():
        raise FileExistsError(f"seal already exists: {manifest_path}")
    config = load_selector_htb_config(config_path)
    plan = strict_json(campaign_dir / "plan.json")
    environment = strict_json(campaign_dir / "environment.json")
    summary = strict_json(campaign_dir / "summary.json")
    if plan.get("executed_profile") != "authoritative":
        raise ValueError("only an authoritative campaign may be sealed")
    trials = plan.get("executed_trials")
    if not isinstance(trials, list) or len(trials) != 360:
        raise ValueError("authoritative plan must contain exactly 360 executed trials")
    if summary != {
        **summary,
        "profile": "authoritative",
        "planned_trial_count": 360,
        "completed_trial_count": 360,
        "valid_trial_count": 360,
        "invalid_trial_count": 0,
        "within_pair_sent_count_errors": {},
        "mechanical_pass": True,
    }:
        raise ValueError("campaign summary does not encode a complete mechanical pass")
    if environment.get("config_sha256") != file_sha256(config_path):
        raise ValueError("configuration hash differs from the start-of-run environment")
    source_hashes = environment.get("source_files")
    if not isinstance(source_hashes, dict) or not source_hashes:
        raise ValueError("start-of-run source inventory is missing")
    for relative, expected_hash in source_hashes.items():
        source = (PROJECT_ROOT / relative).resolve()
        if PROJECT_ROOT.resolve() not in source.parents or file_sha256(source) != expected_hash:
            raise ValueError(f"frozen source mismatch: {relative}")
    expected_trials = {trial["trial_id"]: trial for trial in trials}
    if len(expected_trials) != len(trials):
        raise ValueError("duplicate trial id in plan")
    raw_paths = sorted((campaign_dir / "raw").glob("*.json"))
    if {path.stem for path in raw_paths} != set(expected_trials):
        raise ValueError("raw trial inventory does not exactly equal the plan")
    paired: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for path in raw_paths:
        record = strict_json(path)
        trial = record.get("trial")
        if trial != expected_trials[path.stem]:
            raise ValueError(f"raw trial metadata differs from plan: {path.name}")
        if record.get("valid") is not True or record.get("invalid_reasons") != []:
            raise ValueError(f"invalid raw arm: {path.name}")
        if record.get("tc_validation") != {"before": [], "after": []}:
            raise ValueError(f"live tc validation failed: {path.name}")
        conservation = record.get("packet_conservation", {})
        if conservation.get("exact") is not True or conservation.get("errors") != []:
            raise ValueError(f"packet conservation failed: {path.name}")
        paired[trial["pair_id"]].append(record)
    if len(paired) != 180 or any(len(records) != 2 for records in paired.values()):
        raise ValueError("campaign does not contain exactly 180 complete pairs")
    pair_fidelity: dict[str, Any] = {}
    tolerance = float(config.validity["maximum_within_pair_sent_count_relative_difference"])
    for pair_id, records in sorted(paired.items()):
        schedulers = {record["trial"]["scheduler"] for record in records}
        traces = {record["sender"]["trace"]["trace_sha256"] for record in records}
        sent = [int(record["sender"]["sent_packets"]) for record in records]
        relative = (max(sent) - min(sent)) / max(sent) if max(sent) else 0.0
        if schedulers != {"fixed", "borrowing"} or len(traces) != 1 or relative > tolerance:
            raise ValueError(f"paired fidelity failed: {pair_id}")
        pair_fidelity[pair_id] = {
            "trace_sha256": next(iter(traces)), "sent_packets": sent,
            "relative_sent_count_difference": relative,
        }
    all_paths = sorted(path for path in campaign_dir.rglob("*") if path.is_file())
    relative_paths = {path.relative_to(campaign_dir).as_posix() for path in all_paths}
    expected_paths = EXPECTED_STATIC_FILES | {f"raw/{trial_id}.json" for trial_id in expected_trials}
    if relative_paths != expected_paths:
        raise ValueError(
            f"campaign has an unexpected closed-file set: missing={sorted(expected_paths-relative_paths)}, "
            f"extra={sorted(relative_paths-expected_paths)}"
        )
    result = {
        "schema_version": "selector-htb-seal-1.0",
        "semantic_verification_passed": True,
        "file_count": len(all_paths),
        "files": {
            path.relative_to(campaign_dir).as_posix(): file_sha256(path) for path in all_paths
        },
        "source_files_reverified": source_hashes,
        "pair_count": len(pair_fidelity),
        "pair_fidelity": pair_fidelity,
        "sealer_source_sha256": file_sha256(Path(__file__)),
        "integrity_addendum_sha256": file_sha256(
            PROJECT_ROOT / "protocols" / "SELECTOR_HTB_INTEGRITY_ADDENDUM.md"
        ),
    }
    write_new_json(manifest_path, result)
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = seal(args.campaign_dir, args.config)
    print(json.dumps({
        "semantic_verification_passed": result["semantic_verification_passed"],
        "file_count": result["file_count"], "pair_count": result["pair_count"],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
