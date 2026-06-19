"""Worktree operations for Beta-3 source apply.

This module owns Git command execution and source-tree snapshots. It does not
decide authorization, write receipts, or advance later release gates.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any


def repo_snapshot(repo: Path, failures: list[str]) -> dict[str, str]:
    return {
        "head_commit": git_text(repo, failures, "rev-parse", "HEAD").strip(),
        "status_short": git_text(repo, failures, "status", "--short"),
    }


def git(repo: Path, failures: list[str], *args: str) -> dict[str, Any]:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=False,
        text=True,
        capture_output=True,
    )
    run = command_report(" ".join(["git", *args]), result)
    if run["returncode"] != 0:
        failures.append(f"{run['command']} failed")
    return run


def git_text(repo: Path, failures: list[str], *args: str) -> str:
    run = git(repo, failures, *args)
    return str(run["stdout"])


def run_test_commands(
    repo: Path,
    commands: list[str],
    failures: list[str],
    failure_codes: list[str],
) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    for command in commands:
        result = subprocess.run(
            command,
            cwd=repo,
            shell=True,
            check=False,
            text=True,
            capture_output=True,
        )
        run = command_report(command, result)
        runs.append(run)
        if run["returncode"] != 0:
            failures.append(f"source apply test command failed: {command}")
            append_code(failure_codes, "post_apply_test_failed")
    return runs


def command_report(
    command: str,
    result: subprocess.CompletedProcess[str],
) -> dict[str, Any]:
    return {
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def append_code(codes: list[str], code: str) -> None:
    if code not in codes:
        codes.append(code)
