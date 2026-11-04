#!/usr/bin/env python3
"""Scan the local Linux filesystem for common media files.

This script walks from the filesystem root (/) and collects files whose
extensions match a known set of media types. It skips pseudo-filesystems such
as /proc, /sys, /dev, and /run so it does not traverse kernel/runtime data.
"""

from __future__ import annotations

import os
import sys
from typing import Iterable, List, Set

MEDIA_EXTENSIONS: List[str] = [
    ".3gp",
    ".aac",
    ".avi",
    ".bmp",
    ".flac",
    ".flv",
    ".gif",
    ".heic",
    ".heif",
    ".jpeg",
    ".jpg",
    ".m4a",
    ".m4v",
    ".mkv",
    ".mov",
    ".mp3",
    ".mp4",
    ".ogg",
    ".png",
    ".svg",
    ".tif",
    ".tiff",
    ".wav",
    ".webm",
    ".webp",
    ".wmv",
]

MEDIA_EXTENSIONS_SET: Set[str] = {ext.lower() for ext in MEDIA_EXTENSIONS}

SKIP_DIRS: Set[str] = {
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/snap",
}


def should_skip(path: str) -> bool:
    """skip goon paths"""
    return any(path == skip or path.startswith(skip + os.sep) for skip in SKIP_DIRS)


def scan_media_files(root: str = "/") -> List[str]:
    """Recursively scan a filesystem root and return the matching media files."""
    matches: List[str] = []

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames[:] = [
            d for d in dirnames if not should_skip(os.path.join(dirpath, d))
        ]

        for filename in filenames:
            _, ext = os.path.splitext(filename)
            if ext.lower() in MEDIA_EXTENSIONS_SET:
                matches.append(os.path.join(dirpath, filename))

    return sorted(matches)


def main() -> int:
    """CLI entry point."""
    root = "/" if len(sys.argv) == 1 else sys.argv[1]

    if not os.path.exists(root):
        print(f"Error: path does not exist: {root}", file=sys.stderr)
        return 1

    if not os.path.isdir(root):
        print(f"Error: not a directory: {root}", file=sys.stderr)
        return 1

    media_files = scan_media_files(root)

    if not media_files:
        print(f"No media files found under {root}")
        return 0

    print(f"Found {len(media_files)} media files under {root}:")
    for item in media_files:
        print(item)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
