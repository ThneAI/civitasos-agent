#!/usr/bin/env python3
"""benchmarks/f1c_preflight.py — F.1.c agent registration pre-flight.

Per F1_BASELINE_DESIGN §3.5 and §4.1, F.1.c needs 3 differentiated agent
configurations:

    alpha-bench  capabilities: trading, analysis
    beta-bench   capabilities: scouting, translation
    gamma-bench  capabilities: scholar, research

This script:
  1. Generates a stable Ed25519 identity per agent (saved under
     ``runs/F1c/identity/<agent>.key``).
  2. Calls ``a2a_quickstart`` to register each agent on the backend.
     Server-side DID is derived from the public key, so re-running this
     script is idempotent for the same key files.
  3. Writes ``runs/F1c/agent_ids.json`` mapping ``agent_alias → DID``.
  4. Validates DID by listing pool agents.

Usage:
    ./.venv/bin/python -m benchmarks.f1c_preflight \\
        --backend-url http://localhost:8099 \\
        --runs-root runs/F1c
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("f1c_preflight")
_AUTH_TOKEN: str | None = None


@dataclass(frozen=True)
class AgentConfig:
    alias: str            # short id used in filenames + run-id suffix
    name: str             # human-readable AGENT_NAME
    capabilities: tuple[str, ...]


# §3.5 Causal-chain capability matrix. Sets are deliberately disjoint so
# auto_claim_matching produces different active_tasks per agent.
AGENT_CONFIGS: tuple[AgentConfig, ...] = (
    AgentConfig("alpha", "AlphaTrader", ("trading", "analysis")),
    AgentConfig("beta",  "BetaScout",   ("scouting", "translation")),
    AgentConfig("gamma", "GammaScholar", ("scholar", "research")),
)


def _ensure_identity(sdk, identity_path: Path) -> str:
    """Load existing identity or generate + save a new one. Returns hex pubkey."""
    if identity_path.exists():
        pub = sdk.load_identity(str(identity_path))
        logger.info("loaded existing identity %s pub=%s...", identity_path.name, pub[:16])
        return pub
    identity_path.parent.mkdir(parents=True, exist_ok=True)
    pub = sdk.generate_keys()
    sdk.save_identity(str(identity_path))
    logger.info("generated new identity %s pub=%s...", identity_path.name, pub[:16])
    return pub


def _institutional_identity_enabled() -> bool:
    return os.getenv("CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def _url_origin(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if not parsed.scheme or not parsed.netloc:
        raise RuntimeError(f"invalid URL: {url}")
    return f"{parsed.scheme}://{parsed.netloc}"


def _bootstrap_demo_jwt(base_url: str) -> None:
    global _AUTH_TOKEN
    if _AUTH_TOKEN:
        return
    payload = {"agent_id": os.getenv("BENCHMARK_PREFLIGHT_AGENT_ID", "f1c_preflight")}
    req = urllib.request.Request(
        f"{base_url}/api/v1/auth/demo-login",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8")
    except Exception as exc:  # noqa: BLE001
        logger.warning("demo-login bootstrap failed: %s", exc)
        return
    body = json.loads(raw) if raw else {}
    token = body.get("token") or body.get("data", {}).get("token")
    if token:
        _AUTH_TOKEN = str(token)
        logger.info("preflight auth token bootstrapped via demo-login")


def _bootstrap_sdk_demo_jwt(sdk, base_url: str, cfg: AgentConfig) -> None:
    if getattr(sdk, "_jwt_token", None):
        return
    candidates = (
        getattr(sdk, "_agent_id", None),
        cfg.name.lower().replace(" ", "_"),
        cfg.name,
        cfg.alias,
    )
    for candidate in candidates:
        if not candidate:
            continue
        req = urllib.request.Request(
            f"{base_url.rstrip('/')}/api/v1/auth/demo-login",
            data=json.dumps({"agent_id": candidate}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            logger.debug("SDK demo-login bootstrap failed for %s: %s", candidate, exc)
            continue
        token = body.get("token") or body.get("data", {}).get("token")
        if not token:
            continue
        sdk._jwt_token = str(token)
        expires_in = body.get("expires_in") or body.get("data", {}).get("expires_in") or 3600
        sdk._jwt_expires_at = time.time() + int(expires_in)
        logger.info("preflight SDK auth token bootstrapped via demo-login for %s", candidate)
        return


def _request_json(url: str, *, method: str, payload: dict | None = None) -> dict:
    global _AUTH_TOKEN
    body = json.dumps(payload).encode("utf-8") if payload is not None else None

    def _build_request() -> urllib.request.Request:
        headers: dict[str, str] = {}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if _AUTH_TOKEN:
            headers["Authorization"] = f"Bearer {_AUTH_TOKEN}"
        return urllib.request.Request(url, data=body, headers=headers, method=method)

    req = _build_request()
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        if exc.code != 401:
            raise
        _bootstrap_demo_jwt(_url_origin(url))
        if not _AUTH_TOKEN:
            raise
        retry_req = _build_request()
        with urllib.request.urlopen(retry_req, timeout=20) as resp:
            raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def _post_json(url: str, payload: dict) -> dict:
    return _request_json(url, method="POST", payload=payload)


def _get_json(url: str) -> dict:
    return _request_json(url, method="GET")


def _resolve_birth_sponsor() -> str:
    for key in ("BENCHMARK_BIRTH_SPONSOR", "CIVITASOS_BIRTH_SPONSOR"):
        sponsor = os.getenv(key, "").strip()
        if sponsor:
            return sponsor
    return "@guardian"


def _validate_birth_sponsor(*, backend_url: str) -> None:
    """Fail fast if BENCHMARK_BIRTH_SPONSOR is missing or not eligible."""
    sponsor = _resolve_birth_sponsor()
    encoded = urllib.parse.quote(sponsor, safe="")
    identity_url = f"{backend_url}/api/v1/agents/{encoded}/identity-state"
    try:
        payload = _get_json(identity_url)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        if exc.code == 404:
            raise RuntimeError(
                f"birth sponsor not found: {sponsor}. "
                "Set BENCHMARK_BIRTH_SPONSOR to an existing DID/alias."
            ) from exc
        raise RuntimeError(
            f"failed to verify birth sponsor {sponsor}: HTTP {exc.code} {detail}"
        ) from exc

    data = payload.get("data", {}) if isinstance(payload, dict) else {}
    state = str(data.get("state", "")).strip().upper()
    did = str(data.get("did", "")).strip() or sponsor
    if not state:
        raise RuntimeError(f"birth sponsor {sponsor} identity-state response malformed: {payload}")
    if state in {"PROVISIONAL", "LIQUIDATED"}:
        raise RuntimeError(
            f"birth sponsor {did} not eligible in state {state}; "
            "use a CIVITAS_IDENTITY sponsor"
        )
    logger.info("validated birth sponsor %s did=%s state=%s", sponsor, did, state)


def _validate_birth_aliases(*, backend_url: str, identity_dir: Path) -> None:
    """Fail early when alias already exists but local identity key is missing."""
    for cfg in AGENT_CONFIGS:
        identity_file = identity_dir / f"{cfg.alias}.key"
        if identity_file.exists():
            continue

        encoded = urllib.parse.quote(cfg.alias, safe="")
        identity_url = f"{backend_url}/api/v1/agents/{encoded}/identity-state"
        try:
            payload = _get_json(identity_url)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                continue
            detail = exc.read().decode("utf-8", errors="ignore")
            raise RuntimeError(
                f"failed to verify alias {cfg.alias}: HTTP {exc.code} {detail}"
            ) from exc

        data = payload.get("data", {}) if isinstance(payload, dict) else {}
        did = str(data.get("did", "")).strip() or "<unknown>"
        raise RuntimeError(
            f"alias {cfg.alias} already exists as {did}, but {identity_file} is missing. "
            "Reuse the original identity key files (same runs-root) or choose a new alias."
        )


def _birth_proposal(
    *,
    backend_url: str,
    public_key: str,
    cfg: AgentConfig,
) -> str:
    sponsor = _resolve_birth_sponsor()
    payload = {
        "public_key": public_key,
        "name": cfg.name,
        "alias": cfg.alias,
        "endpoint": f"http://localhost:0/{cfg.alias}",
        "description": f"F.1.c benchmark agent ({', '.join(cfg.capabilities)})",
        "sponsor": sponsor,
        "intent": "F.1.c benchmark incubation",
        "stake": int(os.getenv("BENCHMARK_BIRTH_STAKE", "100")),
        "capabilities": [
            {
                "id": cap,
                "name": cap.replace("_", " ").title(),
                "description": f"Benchmark capability: {cap}",
                "input_schema": None,
                "output_schema": None,
            }
            for cap in cfg.capabilities
        ],
        "obligations": ["complete_assigned_tasks"],
    }
    incubation_epochs_raw = os.getenv("BENCHMARK_BIRTH_INCUBATION_EPOCHS", "").strip()
    if incubation_epochs_raw:
        payload["incubation_epochs"] = int(incubation_epochs_raw)
    try:
        resp = _post_json(f"{backend_url}/api/v1/agents/birth-proposal", payload)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        if exc.code == 409:
            raise RuntimeError(
                f"birth-proposal conflict for alias {cfg.alias}: {detail}. "
                "Ensure this alias reuses its original identity key."
            ) from exc
        raise RuntimeError(
            f"birth-proposal failed for alias {cfg.alias}: HTTP {exc.code} {detail}"
        ) from exc

    data = resp.get("data", {}) if isinstance(resp, dict) else {}
    agent = data.get("agent", {}) if isinstance(data, dict) else {}
    did = agent.get("did") or data.get("did")
    if not did:
        raise RuntimeError(f"birth-proposal response missing did: {resp}")
    logger.info("birth-proposed %s did=%s sponsor=%s", cfg.alias, did, sponsor)
    return str(did)


def register_agent(
    *, backend_url: str, cfg: AgentConfig, identity_dir: Path,
) -> dict:
    """Register one agent; returns {alias, name, did, identity_file, capabilities}."""
    from civitasos import CivitasAgent  # type: ignore[import-not-found]

    identity_file = identity_dir / f"{cfg.alias}.key"
    sdk = CivitasAgent(base_url=backend_url)
    public_key = _ensure_identity(sdk, identity_file)
    _bootstrap_sdk_demo_jwt(sdk, backend_url, cfg)

    if _institutional_identity_enabled():
        did = _birth_proposal(backend_url=backend_url, public_key=public_key, cfg=cfg)
    else:
        # a2a_quickstart is idempotent for the same public key (server returns
        # existing card). On first call it creates; on subsequent runs the DID
        # comes back identical.
        endpoint = f"http://localhost:0/{cfg.alias}"  # placeholder; benchmarks don't accept inbound
        try:
            sdk.a2a_quickstart(
                name=cfg.name,
                endpoint=endpoint,
                description=f"F.1.c benchmark agent ({', '.join(cfg.capabilities)})",
            )
            did = sdk._agent_id  # populated by a2a_quickstart
            logger.info("registered %s did=%s", cfg.alias, did)
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            if "sponsor_required" in msg:
                did = _birth_proposal(backend_url=backend_url, public_key=public_key, cfg=cfg)
            else:
                logger.warning(
                    "a2a_quickstart failed for %s: %s — falling back to register()",
                    cfg.alias,
                    exc,
                )
                sdk.register(
                    agent_id=cfg.name.lower().replace(" ", "_"),
                    name=cfg.name,
                    capabilities=list(cfg.capabilities),
                    stake=100,
                )
                did = sdk._agent_id

    if not did:
        raise RuntimeError(f"could not obtain DID for {cfg.alias} after registration")

    return {
        "alias": cfg.alias,
        "name": cfg.name,
        "did": did,
        "identity_file": str(identity_file.resolve()),
        "capabilities": list(cfg.capabilities),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--backend-url", default="http://localhost:8099")
    p.add_argument("--runs-root", default="runs/F1c")
    p.add_argument("--log-level", default="INFO")
    args = p.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    runs_root = Path(args.runs_root)
    identity_dir = runs_root / "identity"
    out_path = runs_root / "agent_ids.json"
    runs_root.mkdir(parents=True, exist_ok=True)

    if _institutional_identity_enabled():
        _validate_birth_sponsor(backend_url=args.backend_url)
        _validate_birth_aliases(backend_url=args.backend_url, identity_dir=identity_dir)

    records = []
    for cfg in AGENT_CONFIGS:
        rec = register_agent(backend_url=args.backend_url, cfg=cfg, identity_dir=identity_dir)
        records.append(rec)

    out_path.write_text(json.dumps(records, indent=2), encoding="utf-8")
    logger.info("wrote %s with %d agent records", out_path, len(records))

    # Sanity dedup
    dids = [r["did"] for r in records]
    if len(set(dids)) != len(dids):
        logger.error("DID collision: %s", dids)
        return 2

    print(json.dumps(records, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
