from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from experiments.seal_selector_htb_campaign import seal, strict_json
from experiments.selector_htb import (
    build_execution_plan,
    file_sha256,
    load_selector_htb_config,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "configs" / "selector_htb.json"


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, sort_keys=True, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def build_campaign(root: Path) -> None:
    config = load_selector_htb_config(CONFIG_PATH)
    plan = build_execution_plan(config)
    trials = plan["trials"]
    write_json(
        root / "plan.json",
        {
            **plan,
            "executed_profile": "authoritative",
            "executed_trials": trials,
        },
    )
    write_json(root / "calibration.json", {"fixture": True})
    write_json(root / "topology.json", {"fixture": True})
    write_json(
        root / "environment.json",
        {
            "config_sha256": file_sha256(CONFIG_PATH),
            "source_files": {
                "configs/selector_htb.json": file_sha256(CONFIG_PATH),
            },
        },
    )
    write_json(
        root / "summary.json",
        {
            "schema_version": "selector-htb-campaign-1.0",
            "profile": "authoritative",
            "planned_trial_count": 360,
            "completed_trial_count": 360,
            "valid_trial_count": 360,
            "invalid_trial_count": 0,
            "within_pair_sent_count_errors": {},
            "mechanical_pass": True,
        },
    )
    for trial in trials:
        trace_hash = hashlib.sha256(trial["pair_id"].encode("utf-8")).hexdigest()
        write_json(
            root / "raw" / f"{trial['trial_id']}.json",
            {
                "trial": trial,
                "valid": True,
                "invalid_reasons": [],
                "tc_validation": {"before": [], "after": []},
                "packet_conservation": {"exact": True, "errors": []},
                "sender": {
                    "trace": {"trace_sha256": trace_hash},
                    "sent_packets": 1000,
                },
            },
        )


class SelectorHtbSealerTests(unittest.TestCase):
    def test_complete_campaign_is_semantically_verified_and_sealed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            campaign = Path(raw)
            build_campaign(campaign)
            result = seal(campaign, CONFIG_PATH)
            self.assertTrue(result["semantic_verification_passed"])
            self.assertEqual(result["file_count"], 365)
            self.assertEqual(result["pair_count"], 180)
            self.assertTrue((campaign / "sealed_manifest.json").is_file())
            with self.assertRaises(FileExistsError):
                seal(campaign, CONFIG_PATH)

    def test_invalid_raw_arm_blocks_sealing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            campaign = Path(raw)
            build_campaign(campaign)
            path = next((campaign / "raw").glob("*.json"))
            record = strict_json(path)
            record["valid"] = False
            record["invalid_reasons"] = ["fixture_failure"]
            write_json(path, record)
            with self.assertRaisesRegex(ValueError, "invalid raw arm"):
                seal(campaign, CONFIG_PATH)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "duplicate.json"
            path.write_text('{"value": 1, "value": 2}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                strict_json(path)


if __name__ == "__main__":
    unittest.main()
