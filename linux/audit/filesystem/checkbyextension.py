#!/usr/bin/env python3
"""Scan the local Linux filesystem for files with selected extensions.

This script walks from a chosen root and collects files whose extensions match
user-provided values. It skips pseudo-filesystems such as /proc, /sys, /dev,
and /run so it does not traverse kernel/runtime data.
"""

from __future__ import annotations

import os
import sys
from typing import Iterable, List, Set

DEFAULT_MEDIA_EXTENSIONS: List[str] = [
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

MEDIA_EXTENSIONS_SET: Set[str] = {ext.lower() for ext in DEFAULT_MEDIA_EXTENSIONS}

SKIP_DIRS: Set[str] = {
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/snap",
}


def normalize_extensions(extensions: Iterable[str]) -> Set[str]:
    """Normalize a set of extensions to lowercase dotted forms."""
    cleaned: Set[str] = set()
    for extension in extensions:
        value = str(extension).strip()
        if not value:
            continue
        if value.startswith("."):
            cleaned.add(value.lower())
        else:
            cleaned.add(f".{value.lower()}")
    return cleaned


def should_skip(path: str) -> bool:
    """Skip known pseudo-filesystem directories."""
    return any(path == skip or path.startswith(skip + os.sep) for skip in SKIP_DIRS)


def scan_media_files(root: str = "/", extensions: Set[str] | None = None) -> List[str]:
    """Recursively scan a filesystem root and return the matching media files."""
    matches: List[str] = []
    target_extensions = extensions if extensions is not None else MEDIA_EXTENSIONS_SET

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames[:] = [
            d for d in dirnames if not should_skip(os.path.join(dirpath, d))
        ]

        for filename in filenames:
            _, ext = os.path.splitext(filename)
            if ext.lower() in target_extensions:
                matches.append(os.path.join(dirpath, filename))

    return sorted(matches)


def prompt_for_extensions() -> List[str]:
    """Ask the user which extensions to search for."""
    raw_input = input(
        "Enter file extensions to search for (space separated, e.g. jpg png mp4): "
    ).strip()
    if not raw_input:
        return DEFAULT_MEDIA_EXTENSIONS
    return raw_input.split()


def main() -> int:
    """CLI entry point."""
    args = sys.argv[1:]

    if args and not args[0].startswith(".") and os.path.isdir(args[0]):
        root = args[0]
        user_extensions = args[1:]
    else:
        root = "/"
        user_extensions = args

    if not user_extensions:
        try:
            user_extensions = prompt_for_extensions()
        except EOFError:
            user_extensions = DEFAULT_MEDIA_EXTENSIONS

    if not os.path.exists(root):
        print(f"Error: path does not exist: {root}", file=sys.stderr)
        return 1

    if not os.path.isdir(root):
        print(f"Error: not a directory: {root}", file=sys.stderr)
        return 1

    media_extensions = normalize_extensions(user_extensions)
    media_files = scan_media_files(root, media_extensions)

    if not media_files:
        print(
            f"No media files found under {root} with extensions: "
            f"{', '.join(sorted(media_extensions))}"
        )
        return 0

    print(
        f"Found {len(media_files)} media files under {root} "
        f"for extensions: {', '.join(sorted(media_extensions))}:"
    )
    for item in media_files:
        print(item)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
