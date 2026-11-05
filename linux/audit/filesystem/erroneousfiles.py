#!/usr/bin/env python3
"""Scan the local Linux filesystem for files whose magic bytes do not match their extension.

This script walks from the filesystem root (/) and checks the file header of each
file against a list of known signatures. Files whose extension does not match the
signature seen in the first bytes are reported as suspicious, which may help spot
malicious files disguised by a misleading extension.
"""

from __future__ import annotations

import os
import sys
from typing import Callable, Dict, Iterable, List, Sequence, Tuple

SKIP_DIRS: set[str] = {
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/snap",
}


def should_skip(path: str) -> bool:
    """Return True if the provided path should not be scanned."""
    return any(path == skip or path.startswith(skip + os.sep) for skip in SKIP_DIRS)


def read_file_header(path: str, size: int = 4096) -> bytes:
    """Read a short header from a file to inspect its magic bytes."""
    try:
        with open(path, "rb") as handle:
            return handle.read(size)
    except OSError:
        return b""


# File extensions and their expected magic-byte signatures. The signatures are
# intentionally conservative so that false positives are kept low while still
# catching renamed malicious files.
SIGNATURE_CHECKS: Dict[str, Callable[[bytes], bool]] = {
    ".jpg": lambda header: header.startswith((b"\xff\xd8\xff",)),
    ".jpeg": lambda header: header.startswith((b"\xff\xd8\xff",)),
    ".png": lambda header: header.startswith(b"\x89PNG\r\n\x1a\n"),
    ".gif": lambda header: header.startswith((b"GIF87a", b"GIF89a")),
    ".bmp": lambda header: header.startswith((b"BM", b"BA", b"CI", b"CP", b"IC", b"PT")),
    ".pdf": lambda header: header.startswith(b"%PDF"),
    ".zip": lambda header: header.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")),
    ".docx": lambda header: header.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")),
    ".xlsx": lambda header: header.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")),
    ".pptx": lambda header: header.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")),
    ".jar": lambda header: header.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")),
    ".apk": lambda header: header.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")),
    ".rar": lambda header: header.startswith((b"Rar!\x1a\x07", b"Rar!\x1a\x07\x00")),
    ".gz": lambda header: header.startswith(b"\x1f\x8b\x08"),
    ".tar": lambda header: header.startswith((b"ustar",)),
    ".wav": lambda header: header.startswith(b"RIFF") and b"WAVE" in header[8:16],
    ".mp3": lambda header: header.startswith((b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2")),
    ".mp4": lambda header: b"ftyp" in header[:64],
    ".m4a": lambda header: b"ftyp" in header[:64],
    ".m4v": lambda header: b"ftyp" in header[:64],
    ".avi": lambda header: header.startswith(b"RIFF") and b"AVI" in header[8:16],
    ".mov": lambda header: b"ftyp" in header[:64],
    ".webm": lambda header: b"\x1aE\xdf\xa3" in header[:16],
    ".exe": lambda header: header.startswith(b"MZ"),
    ".dll": lambda header: header.startswith(b"MZ"),
    ".sys": lambda header: header.startswith(b"MZ"),
    ".elf": lambda header: header.startswith(b"\x7fELF"),
    ".msi": lambda header: header.startswith(b"MSI"),
    ".html": lambda header: header.lstrip().startswith((b"<!DOCTYPE", b"<html", b"<HTML")),
    ".htm": lambda header: header.lstrip().startswith((b"<!DOCTYPE", b"<html", b"<HTML")),
    ".svg": lambda header: header.lstrip().startswith((b"<svg", b"<?xml")),
}


def detect_signature(header: bytes) -> List[str]:
    """Return the known file types whose signatures match the provided header."""
    matches: List[str] = []
    for extension, checker in SIGNATURE_CHECKS.items():
        if checker(header):
            matches.append(extension)
    return matches


def evaluate_file(path: str) -> tuple[str, str] | None:
    """Return a mismatch description if the file signature does not match its extension."""
    filename = os.path.basename(path)
    extension = os.path.splitext(filename)[1].lower()

    if not extension or extension not in SIGNATURE_CHECKS:
        return None

    header = read_file_header(path)
    detected = detect_signature(header)

    if not detected:
        return path, f"signature mismatch: expected {extension}, but file header does not match any known signature"

    if extension not in detected:
        return path, f"signature mismatch: expected {extension}, but detected {', '.join(detected)}"

    return None


def scan_erroneous_files(root: str = "/") -> List[tuple[str, str]]:
    """Recursively scan a filesystem root and return suspicious files."""
    suspicious: List[tuple[str, str]] = []

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames[:] = [d for d in dirnames if not should_skip(os.path.join(dirpath, d))]

        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            result = evaluate_file(full_path)
            if result is not None:
                suspicious.append(result)

    return sorted(suspicious, key=lambda item: item[0])


def main() -> int:
    """CLI entry point."""
    root = "/" if len(sys.argv) == 1 else sys.argv[1]

    if not os.path.exists(root):
        print(f"Error: path does not exist: {root}", file=sys.stderr)
        return 1

    if not os.path.isdir(root):
        print(f"Error: not a directory: {root}", file=sys.stderr)
        return 1

    suspicious = scan_erroneous_files(root)

    if not suspicious:
        print(f"No suspicious file signature mismatches found under {root}")
        return 0

    print(f"Found {len(suspicious)} suspicious files under {root}:")
    for path, reason in suspicious:
        print(f"- {path}: {reason}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
