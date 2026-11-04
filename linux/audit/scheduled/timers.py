#!/usr/bin/env python3
"""Inspect systemd timer units and print the key schedule details."""

import subprocess
import sys
from pathlib import Path


TIMER_DIRECTORIES = (
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
)


def run_command(args):
    """Run a command and return the raw output alongside its exit code."""
    try:
        result = subprocess.run(args, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return 127, "", f"Command not found: {args[0]}\n"


def print_section(title):
    print()
    print("=" * 90)
    print(title)
    print("=" * 90)
    print()


def print_command_output(label, cmd):
    code, stdout, stderr = run_command(cmd)
    print_section(f"{label} (exit code: {code})")
    if stdout:
        print(stdout, end="")
    if stderr:
        print(stderr, end="", file=sys.stderr)
    return code, stdout, stderr


def discover_timer_units():
    """Return a stable list of discovered .timer units."""
    units = set()

    code, stdout, _ = run_command(["systemctl", "list-timers", "--all", "--no-pager"])
    if code == 0:
        for line in stdout.splitlines():
            parts = line.split()
            if parts and parts[0].endswith(".timer"):
                units.add(parts[0])

    code, stdout, _ = run_command(["systemctl", "--all", "--type=timer", "list-unit-files", "--no-pager"])
    if code == 0:
        for line in stdout.splitlines():
            parts = line.split()
            if parts and parts[0].endswith(".timer"):
                units.add(parts[0])

    for base in TIMER_DIRECTORIES:
        base_path = Path(base)
        if not base_path.exists():
            continue
        for timer_path in sorted(base_path.rglob("*.timer")):
            units.add(timer_path.name)

    return sorted(units)


def print_timer_details(unit_name):
    """Display the most useful systemctl metadata for a timer."""
    print_section(f"Timer details for {unit_name}")
    commands = [
        ["systemctl", "show", "--no-pager", "--property=*", unit_name],
        ["systemctl", "cat", "--", unit_name],
        ["systemctl", "status", "--full", "--no-pager", unit_name],
    ]

    for cmd in commands:
        print_command_output(f"Command: {' '.join(cmd)}", cmd)


def print_timer_files():
    """Print the timer unit files found on disk."""
    print_section("Timer unit files on disk")
    seen = set()

    for base in TIMER_DIRECTORIES:
        base_path = Path(base)
        if not base_path.exists():
            continue

        for timer_path in sorted(base_path.rglob("*.timer")):
            if timer_path in seen:
                continue
            seen.add(timer_path)
            print_section(f"File: {timer_path}")
            try:
                print(timer_path.read_text())
            except OSError as exc:
                print(f"Unable to read {timer_path}: {exc}")


def main():
    print_section("systemctl list-timers --all")
    code, stdout, stderr = run_command(["systemctl", "list-timers", "--all", "--no-pager"])
    print(f"Exit code: {code}")
    if stdout:
        print(stdout, end="")
    if stderr:
        print(stderr, end="", file=sys.stderr)

    timers = discover_timer_units()
    print_section(f"Discovered timer units ({len(timers)})")
    if timers:
        for unit_name in timers:
            print(unit_name)
    else:
        print("No systemd timer units were detected.")

    for unit_name in timers:
        print_timer_details(unit_name)

    print_timer_files()


if __name__ == "__main__":
    main()