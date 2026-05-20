#!/usr/bin/env python3
"""Validate Beta-2 patch proposal artifacts.

Beta-2 allows an external model to propose a patch artifact. This script only
validates that artifact. It never applies a patch, commits, pushes, merges,
deploys, executes production runtime actions, or writes production receipts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


VALIDATION_SCHEMA = "beta2-patch-proposal-validation:v1"
DEFAULT_DENY_FRAGMENTS = (
    ".env",
    ".ssh",
    "id_rsa",
    "private_key",
    "secret",
    "secrets/",
    "production",
    "deploy",
    "deployment",
    "terraform",
    "kube",
)
FORBIDDEN_CLAIMS = (
    "already applied",
    "applied successfully",
    "already committed",
    "committed successfully",
    "already pushed",
    "pushed successfully",
    "already merged",
    "merged successfully",
    "already deployed",
    "deployed successfully",
    "production ready",
    "h.3 ready",
    "h3 ready",
    "production_runtime_execution_allowed=true",
    "production_receipt_write_allowed=true",
)
NON_CLAIMS = (
    "beta2_patch_proposal_is_l1_controlled_pilot_only",
    "beta2_patch_proposal_does_not_apply_patch",
    "beta2_patch_proposal_does_not_authorize_commit_push_merge_or_deploy",
    "beta2_patch_proposal_does_not_claim_h3_production_readiness",
    "beta2_patch_proposal_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate a patch proposal artifact")
    validate.add_argument("--repo", required=True, help="Git repository root or subdirectory.")
    validate.add_argument("--patch", required=True, help="Patch proposal artifact path.")
    validate.add_argument("--request", help="Optional Beta-1/Beta-2 request JSON path to cross-check.")
    validate.add_argument("--output", help="Optional validation report output path.")
    validate.add_argument(
        "--allow-path-prefix",
        action="append",
        default=[],
        help="Allowed target path prefix. Repeatable. If omitted, all non-denied repo paths are allowed.",
    )
    validate.add_argument(
        "--deny-path-fragment",
        action="append",
        default=[],
        help="Additional denied target path fragment. Repeatable.",
    )
    args = parser.parse_args(argv)

    if args.command == "validate":
        report = validate_patch_proposal(
            repo=Path(args.repo),
            patch_path=Path(args.patch),
            request_path=Path(args.request) if args.request else None,
            allow_path_prefixes=args.allow_path_prefix,
            deny_path_fragments=args.deny_path_fragment,
        )
        if args.output:
            _write_json(Path(args.output), report)
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if report["passed"] else 1
    raise AssertionError(f"unknown command: {args.command}")


def validate_patch_proposal(
    *,
    repo: Path,
    patch_path: Path,
    request_path: Path | None = None,
    allow_path_prefixes: list[str] | None = None,
    deny_path_fragments: list[str] | None = None,
) -> dict[str, Any]:
    failures: list[str] = []
    repo_root = _safe_repo_root(repo, failures)
    patch_text = _safe_read_text(patch_path, failures, "patch")
    request = _safe_read_json(request_path, failures, "request") if request_path else None
    allow_prefixes = _normalize_prefixes(allow_path_prefixes or [])
    deny_fragments = tuple(DEFAULT_DENY_FRAGMENTS) + tuple(deny_path_fragments or [])

    target_paths = parse_patch_target_paths(patch_text)
    if not patch_text.strip():
        failures.append("patch proposal must not be empty")
    if not target_paths:
        failures.append("patch proposal must contain target paths")
    if "@@" not in patch_text:
        failures.append("patch proposal must contain at least one unified diff hunk")
    _validate_forbidden_claims(patch_text, failures)
    if repo_root is not None:
        _validate_target_paths(
            repo_root=repo_root,
            target_paths=target_paths,
            allow_prefixes=allow_prefixes,
            deny_fragments=deny_fragments,
            failures=failures,
        )
    if isinstance(request, dict):
        _validate_request_boundary(request, failures)

    return {
        "schema_version": VALIDATION_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "repo_root": str(repo_root) if repo_root else None,
        "patch_path": str(patch_path.resolve()),
        "patch_sha256": _sha256(patch_path) if patch_path.is_file() else None,
        "target_paths": target_paths,
        "allow_path_prefixes": allow_prefixes,
        "deny_path_fragments": list(deny_fragments),
        "request_path": str(request_path.resolve()) if request_path else None,
        "request_sha256": _sha256(request_path) if request_path and request_path.is_file() else None,
        "dangerous_actions_allowed": {
            "apply_patch": False,
            "commit": False,
            "push": False,
            "merge": False,
            "deploy": False,
            "production_runtime_execution": False,
            "production_receipt_write": False,
        },
        "non_claims": list(NON_CLAIMS),
    }


def parse_patch_target_paths(patch_text: str) -> list[str]:
    paths: list[str] = []
    for raw_line in patch_text.splitlines():
        line = raw_line.strip()
        if line.startswith("diff --git "):
            parts = line.split()
            if len(parts) >= 4:
                _append_path(paths, _strip_git_prefix(parts[2]))
                _append_path(paths, _strip_git_prefix(parts[3]))
        elif line.startswith("--- ") or line.startswith("+++ "):
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                _append_path(paths, _strip_git_prefix(parts[1].split("\t", 1)[0]))
    return sorted(set(paths))


def _append_path(paths: list[str], value: str) -> None:
    if value and value != "/dev/null" and value not in paths:
        paths.append(value)


def _strip_git_prefix(value: str) -> str:
    value = value.strip().strip('"')
    if value.startswith("a/") or value.startswith("b/"):
        return value[2:]
    return value


def _validate_target_paths(
    *,
    repo_root: Path,
    target_paths: list[str],
    allow_prefixes: list[str],
    deny_fragments: tuple[str, ...],
    failures: list[str],
) -> None:
    for target in target_paths:
        target_path = Path(target)
        target_lower = target.casefold()
        if target_path.is_absolute():
            failures.append(f"patch target must be repo-relative: {target}")
            continue
        if ".." in target_path.parts:
            failures.append(f"patch target must not escape repo root: {target}")
            continue
        if allow_prefixes and not any(target == prefix.rstrip("/") or target.startswith(prefix) for prefix in allow_prefixes):
            failures.append(f"patch target is outside allowlist: {target}")
        for fragment in deny_fragments:
            if fragment.casefold() in target_lower:
                failures.append(f"patch target contains denied fragment {fragment!r}: {target}")
                break
        resolved = (repo_root / target).resolve()
        try:
            resolved.relative_to(repo_root)
        except ValueError:
            failures.append(f"patch target resolves outside repo root: {target}")
            continue
        if _git_check_ignore(repo_root, target):
            failures.append(f"patch target is git-ignored and cannot be proposed: {target}")


def _validate_forbidden_claims(patch_text: str, failures: list[str]) -> None:
    lowered = patch_text.casefold()
    for claim in FORBIDDEN_CLAIMS:
        if claim in lowered:
            failures.append(f"patch proposal contains forbidden claim: {claim}")


def _validate_request_boundary(request: dict[str, Any], failures: list[str]) -> None:
    if request.get("mode") != "proposal_only":
        failures.append("request.mode must be proposal_only")
    h3_boundary = request.get("h3_boundary")
    if not isinstance(h3_boundary, dict):
        failures.append("request.h3_boundary must be an object")
        return
    if h3_boundary.get("h3_remains_blocked") is not True:
        failures.append("request.h3_boundary.h3_remains_blocked must be true")
    if h3_boundary.get("h3_production_readiness_claimed") is not False:
        failures.append("request.h3_boundary.h3_production_readiness_claimed must be false")
    if h3_boundary.get("production_runtime_execution_allowed") is not False:
        failures.append("request.h3_boundary.production_runtime_execution_allowed must be false")
    if h3_boundary.get("production_receipt_write_allowed") is not False:
        failures.append("request.h3_boundary.production_receipt_write_allowed must be false")


def _safe_repo_root(repo: Path, failures: list[str]) -> Path | None:
    try:
        return _repo_root(repo)
    except Exception as exc:  # noqa: BLE001 - validation report needs the reason.
        failures.append(f"repo root could not be resolved: {exc}")
        return None


def _safe_read_text(path: Path, failures: list[str], label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        failures.append(f"{label} could not be read: {exc}")
        return ""


def _safe_read_json(path: Path | None, failures: list[str], label: str) -> Any:
    if path is None:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        failures.append(f"{label} could not be read: {exc}")
        return None


def _repo_root(repo: Path) -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=repo,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return Path(result.stdout.strip()).resolve()


def _git_check_ignore(repo_root: Path, target: str) -> bool:
    result = subprocess.run(
        ["git", "check-ignore", "-q", "--", target],
        cwd=repo_root,
        check=False,
    )
    return result.returncode == 0


def _normalize_prefixes(values: list[str]) -> list[str]:
    prefixes = []
    for value in values:
        normalized = value.strip()
        if normalized and not normalized.endswith("/"):
            normalized = normalized + "/"
        if normalized:
            prefixes.append(normalized)
    return prefixes


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    sys.exit(main())
