#!/usr/bin/env python3
"""Audit the filesystem for overly permissive permissions.

This script walks the filesystem from a starting path (default: /), checks each
regular file and directory, and reports entries with dangerous permission bits
(such as world/group write access or a full 0777/0775-style mode) without
modifying any files.

Examples:
    python3 permissionchecks.py
    python3 permissionchecks.py /var
"""

import os
import stat
import sys

EXCLUDED_ROOTS = ("/proc", "/sys", "/dev", "/run")


def check_permissions(mode: int, is_dir: bool = False):
    """Return a human-readable reason if the permission mode is suspicious."""
    # Report group/world write access as dangerous for both files and directories.
    if mode & 0o002:
        return "world writable"
    if mode & 0o020:
        return "group writable"

    # A fully open permission set (0777 / 0775 style) is a clear audit finding.
    if mode & 0o777 == 0o777:
        return "777 permissions"

    # Other unsafe 'open' modes, especially for directories, are worth reporting.
    if is_dir and (mode & 0o077) == 0o077:
        return "group/other access enabled"

    return None


def iter_file_system(path: str):
    """Yield all regular files and directories under the supplied path."""
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    print(f"Skipping unreadable entry: {entry.path} ({exc})", file=sys.stderr)
                    continue

                mode = st.st_mode
                if stat.S_ISLNK(mode):
                    continue

                is_dir = stat.S_ISDIR(mode)
                if is_dir:
                    # Do not traverse pseudo-filesystems that are not real on-disk data.
                    if entry.path in EXCLUDED_ROOTS or entry.path.startswith(EXCLUDED_ROOTS):
                        continue
                    yield entry.path, st, is_dir
                    yield from iter_file_system(entry.path)
                elif stat.S_ISREG(mode):
                    yield entry.path, st, False
    except OSError as exc:
        print(f"Skipping unreadable directory: {path} ({exc})", file=sys.stderr)


def main():
    root = "/" if len(sys.argv) < 2 else sys.argv[1]

    findings = []
    try:
        for path, st, is_dir in iter_file_system(root):
            perm_bits = stat.S_IMODE(st.st_mode)
            reason = check_permissions(perm_bits, is_dir=is_dir)
            if reason:
                findings.append((path, oct(perm_bits), reason))
    except Exception as exc:  # pragma: no cover - defensive only
        print(f"Fatal error while auditing {root}: {exc}", file=sys.stderr)
        return 2

    if not findings:
        print(f"No suspicious permissions found under {root}.")
        return 0

    print(f"Suspicious permissions found under {root}:")
    for path, mode, reason in findings:
        print(f"- {path}: {mode} ({reason})")

    print(f"Total suspicious entries: {len(findings)}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
