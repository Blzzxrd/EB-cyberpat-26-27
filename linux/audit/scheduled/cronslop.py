#!/usr/bin/env python3

"""List cron jobs with their owner, schedule, and command.

This script inspects the system crontab, files under /etc/cron.d, and each
user's personal crontab (when available) and prints a readable summary for each
entry.
"""

# systemctl list-timers --all

from __future__ import annotations

import pwd
import re
import shutil
import subprocess
from pathlib import Path


SYSTEM_CRONTAB = Path("/etc/crontab")
CRON_DIR = Path("/etc/cron.d")

SPECIAL_SCHEDULES = {
    "@yearly": "minute hour day-of-month month day-of-week",
    "@annually": "minute hour day-of-month month day-of-week",
    "@monthly": "minute hour day-of-month month day-of-week",
    "@weekly": "minute hour day-of-month month day-of-week",
    "@daily": "minute hour day-of-month month day-of-week",
    "@midnight": "minute hour day-of-month month day-of-week",
    "@hourly": "minute hour day-of-month month day-of-week",
    "@reboot": "special reboot",
}


def parse_cron_line(line: str, source: str, default_user: str | None = None):
    """Return a cron job dictionary or None for non-job lines."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", stripped):
        return None

    if stripped.startswith("@"):
        match = re.match(r"@([A-Za-z]+)\s+(.*)$", stripped)
        if not match:
            return None
        tag, command = match.groups()
        return {
            "source": source,
            "user": default_user or "system",
            "schedule": f"@{tag}",
            "description": SPECIAL_SCHEDULES.get(f"@{tag}", "special schedule"),
            "command": command.strip(),
        }

    parts = stripped.split()
    if default_user is not None:
        if len(parts) < 6:
            return None
        schedule = " ".join(parts[:5])
        command = " ".join(parts[5:])
        user = default_user
    else:
        if len(parts) < 7:
            return None
        schedule = " ".join(parts[:5])
        user = parts[5]
        command = " ".join(parts[6:])

    if not command:
        return None

    return {
        "source": source,
        "user": user,
        "schedule": schedule,
        "description": "minute hour day-of-month month day-of-week",
        "command": command,
    }


def read_file_jobs(path: Path, default_user: str | None = None):
    """Read cron jobs from a single file."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except OSError:
        return []

    jobs = []
    for line in lines:
        job = parse_cron_line(line, str(path), default_user)
        if job:
            jobs.append(job)
    return jobs


def read_user_crontabs():
    """Read per-user crontabs when the system supports them."""
    jobs = []
    if not shutil.which("crontab"):
        return jobs

    for entry in pwd.getpwall():
        username = entry.pw_name
        try:
            output = subprocess.check_output(
                ["crontab", "-l", "-u", username],
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue

        for line in output.splitlines():
            job = parse_cron_line(line, f"crontab -u {username}", username)
            if job:
                jobs.append(job)
    return jobs


def collect_jobs():
    """Collect cron definitions from the common system locations."""
    jobs = []

    if SYSTEM_CRONTAB.exists():
        jobs.extend(read_file_jobs(SYSTEM_CRONTAB))

    if CRON_DIR.exists():
        for cron_file in sorted(CRON_DIR.iterdir()):
            if cron_file.is_file():
                jobs.extend(read_file_jobs(cron_file))

    jobs.extend(read_user_crontabs())
    return jobs


def print_jobs(jobs):
    if not jobs:
        print("No cron jobs found.")
        return

    print(f"Found {len(jobs)} cron job(s):\n")
    for index, job in enumerate(jobs, start=1):
        print(f"Job #{index}")
        print(f"  Source: {job['source']}")
        print(f"  User:   {job['user']}")
        print(f"  Schedule: {job['schedule']}")
        print(f"  Command: {job['command']}")
        print()


def main():
    jobs = collect_jobs()
    print_jobs(jobs)


if __name__ == "__main__":
    main()
