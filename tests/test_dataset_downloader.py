from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "public"
    / "rt_iot2022"
    / "download.py"
)
SPEC = importlib.util.spec_from_file_location("rt_iot2022_download", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
downloader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(downloader)


class DatasetDownloaderTests(unittest.TestCase):
    @staticmethod
    def _fixture_archive(path: Path, payload: bytes, member: str = "RT_IOT2022") -> None:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr(member, payload)

    def test_verified_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive = root / "fixture.zip"
            output = root / "RT_IOT2022"
            payload = b"label,value\nnormal,1\n"
            self._fixture_archive(archive, payload)
            downloader.extract_verified_archive(
                archive,
                output,
                archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
                extracted_sha256=hashlib.sha256(payload).hexdigest(),
            )
            self.assertEqual(output.read_bytes(), payload)

    def test_rejects_wrong_archive_hash(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive = root / "fixture.zip"
            self._fixture_archive(archive, b"payload")
            with self.assertRaisesRegex(downloader.DatasetIntegrityError, "archive SHA-256"):
                downloader.extract_verified_archive(
                    archive,
                    root / "RT_IOT2022",
                    archive_sha256="0" * 64,
                    extracted_sha256="0" * 64,
                )

    def test_rejects_unexpected_member_set(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive = root / "fixture.zip"
            self._fixture_archive(archive, b"payload", member="wrong.csv")
            archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
            with self.assertRaisesRegex(downloader.DatasetIntegrityError, "member set"):
                downloader.extract_verified_archive(
                    archive,
                    root / "RT_IOT2022",
                    archive_sha256=archive_hash,
                    extracted_sha256=hashlib.sha256(b"payload").hexdigest(),
                )


if __name__ == "__main__":
    unittest.main()
