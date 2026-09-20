from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from testbed.matched_scheduler_lib import (
    FROZEN_SOURCE_RELATIVE_PATHS,
    file_sha256,
)


ROOT = Path(__file__).resolve().parents[1]
STUDY_C_MANIFEST = ROOT / "provenance" / "study_c_source_manifest.json"
SELECTOR_SEAL_RECORD = ROOT / "provenance" / "selector_htb_seal_record.json"
OBSOLETE_PILOT_PATHS = {
    "testbed/apply_htb_baseline.sh",
    "testbed/run_campaign.py",
    "testbed/sbeq_budget_controller.sh",
    "testbed/setup_netns.sh",
    "testbed/teardown_netns.sh",
    "testbed/traffic_gen.py",
}
LOCAL_LINK = re.compile(r"\[[^]]+\]\(([^)]+)\)")


class FrozenStudyCSourceTests(unittest.TestCase):
    def test_committed_manifest_matches_successful_campaign_source(self) -> None:
        entries = json.loads(STUDY_C_MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(
            tuple(entry["path"] for entry in entries),
            FROZEN_SOURCE_RELATIVE_PATHS,
        )
        for entry in entries:
            with self.subTest(path=entry["path"]):
                path = ROOT / entry["path"]
                self.assertTrue(path.is_file())
                self.assertEqual(path.stat().st_size, entry["size_bytes"])
                self.assertEqual(file_sha256(path), entry["sha256"])

    def test_selector_campaign_public_seal_record_matches_source(self) -> None:
        record = json.loads(SELECTOR_SEAL_RECORD.read_text(encoding="utf-8"))
        self.assertTrue(record["campaign_seal"]["semantic_verification_passed"])
        self.assertEqual(record["campaign_seal"]["file_count"], 365)
        self.assertEqual(record["campaign_seal"]["pair_count"], 180)
        for relative, expected_hash in record["source_files_reverified"].items():
            with self.subTest(path=relative):
                self.assertEqual(file_sha256(ROOT / relative), expected_hash)
        self.assertEqual(
            file_sha256(ROOT / "experiments" / "seal_selector_htb_campaign.py"),
            record["sealer_source_sha256"],
        )
        self.assertEqual(
            file_sha256(ROOT / "protocols" / "SELECTOR_HTB_INTEGRITY_ADDENDUM.md"),
            record["integrity_addendum_sha256"],
        )

    def test_obsolete_pilot_stack_is_not_published(self) -> None:
        for relative in OBSOLETE_PILOT_PATHS:
            with self.subTest(path=relative):
                self.assertFalse((ROOT / relative).exists())


class ReaderDocumentationTests(unittest.TestCase):
    def _markdown_files(self) -> list[Path]:
        paths = list(ROOT.glob("*.md"))
        for directory in ("data", "docs", "protocols", "testbed"):
            paths.extend((ROOT / directory).rglob("*.md"))
        return sorted(set(paths))

    def test_all_local_markdown_links_resolve(self) -> None:
        for document in self._markdown_files():
            for target in LOCAL_LINK.findall(document.read_text(encoding="utf-8")):
                target = target.strip().split("#", 1)[0]
                if not target or "://" in target or target.startswith("mailto:"):
                    continue
                with self.subTest(document=document.relative_to(ROOT), target=target):
                    self.assertTrue((document.parent / target).resolve().exists())

    def test_release_metadata_and_reader_guides_are_current(self) -> None:
        citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("version: 1.1.2", citation)
        self.assertIn("docs/STUDY_C_REPRODUCIBILITY.md", readme)
        self.assertIn("protocols/README.md", readme)
        self.assertIn("experiments.seal_selector_htb_campaign", readme)
        self.assertNotIn(
            "[`testbed/MATCHED_SCHEDULER.md`](testbed/MATCHED_SCHEDULER.md)",
            readme,
        )


if __name__ == "__main__":
    unittest.main()
