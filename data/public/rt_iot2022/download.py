#!/usr/bin/env python3
"""Download and hash-verify the official RT-IoT2022 release.

The downloader accepts no alternate mirror from its CLI.  It refuses to
overwrite an invalid existing file, downloads to a temporary file in the
destination directory, verifies the official archive digest, requires the
single expected archive member, and verifies the extracted-file digest before
an atomic rename.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import tempfile
from typing import BinaryIO, Callable
from urllib.request import urlopen
import zipfile


OFFICIAL_URL = "https://archive.ics.uci.edu/static/public/942/rt-iot2022.zip"
ARCHIVE_NAME = "rt-iot2022.zip"
MEMBER_NAME = "RT_IOT2022"
ARCHIVE_SHA256 = "bcaa24d62abbb1215be576d5cf9c02dfcb0bb7c4c2f5a00e03055afaa1ed109e"
EXTRACTED_SHA256 = "956956c09c1764584fa08acd0f6876475626bcedcd6a6b1f8c492c2e9a2089ea"
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "original"


class DatasetIntegrityError(RuntimeError):
    """Raised when official-source provenance cannot be established."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_hash(path: Path, expected: str, label: str) -> None:
    if not path.is_file():
        raise DatasetIntegrityError(f"missing {label}: {path}")
    observed = sha256(path)
    if observed != expected:
        raise DatasetIntegrityError(
            f"invalid {label} SHA-256 for {path}: expected {expected}, observed {observed}"
        )


def verify_installation(
    output_dir: Path,
    *,
    archive_sha256: str = ARCHIVE_SHA256,
    extracted_sha256: str = EXTRACTED_SHA256,
) -> None:
    output_dir = Path(output_dir)
    _require_hash(output_dir / ARCHIVE_NAME, archive_sha256, "archive")
    _require_hash(output_dir / MEMBER_NAME, extracted_sha256, "extracted dataset")


def extract_verified_archive(
    archive_path: Path,
    extracted_path: Path,
    *,
    archive_sha256: str = ARCHIVE_SHA256,
    extracted_sha256: str = EXTRACTED_SHA256,
    member_name: str = MEMBER_NAME,
) -> None:
    """Extract one expected member, refusing ambiguous or unsafe archives."""

    _require_hash(archive_path, archive_sha256, "archive")
    with zipfile.ZipFile(archive_path, "r") as archive:
        members = archive.infolist()
        if len(members) != 1 or members[0].filename != member_name:
            names = [member.filename for member in members]
            raise DatasetIntegrityError(
                f"archive member set differs from official release: {names!r}"
            )
        if members[0].is_dir() or Path(members[0].filename).name != member_name:
            raise DatasetIntegrityError("unsafe or non-file archive member")
        extracted_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{member_name}.", suffix=".part", dir=extracted_path.parent
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            digest = hashlib.sha256()
            with archive.open(members[0], "r") as source, temporary.open("wb") as target:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    target.write(block)
                    digest.update(block)
            observed = digest.hexdigest()
            if observed != extracted_sha256:
                raise DatasetIntegrityError(
                    "invalid extracted dataset SHA-256: "
                    f"expected {extracted_sha256}, observed {observed}"
                )
            temporary.replace(extracted_path)
        finally:
            temporary.unlink(missing_ok=True)


def download_dataset(
    output_dir: Path,
    *,
    opener: Callable[..., BinaryIO] = urlopen,
) -> str:
    """Install the official archive and CSV, or verify an existing install."""

    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = output_dir / ARCHIVE_NAME
    extracted_path = output_dir / MEMBER_NAME
    if archive_path.exists() or extracted_path.exists():
        if not (archive_path.is_file() and extracted_path.is_file()):
            raise DatasetIntegrityError(
                "partial dataset installation exists; move it aside before retrying"
            )
        verify_installation(output_dir)
        return "verified_existing"

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{ARCHIVE_NAME}.", suffix=".part", dir=output_dir
    )
    os.close(descriptor)
    temporary_archive = Path(temporary_name)
    try:
        digest = hashlib.sha256()
        with opener(OFFICIAL_URL, timeout=120) as response, temporary_archive.open("wb") as target:
            for block in iter(lambda: response.read(1024 * 1024), b""):
                target.write(block)
                digest.update(block)
        observed = digest.hexdigest()
        if observed != ARCHIVE_SHA256:
            raise DatasetIntegrityError(
                f"official download hash mismatch: expected {ARCHIVE_SHA256}, observed {observed}"
            )
        temporary_archive.replace(archive_path)
        extract_verified_archive(archive_path, extracted_path)
        verify_installation(output_dir)
        return "downloaded_and_verified"
    finally:
        temporary_archive.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="verify an existing archive and extracted file without network access",
    )
    args = parser.parse_args()
    try:
        if args.verify_only:
            verify_installation(args.output_dir)
            status = "verified_existing"
        else:
            status = download_dataset(args.output_dir)
    except (DatasetIntegrityError, OSError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}")
        return 1
    print(f"dataset_status={status}")
    print(f"archive_sha256={ARCHIVE_SHA256}")
    print(f"extracted_sha256={EXTRACTED_SHA256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
