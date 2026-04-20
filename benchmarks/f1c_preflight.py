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
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("f1c_preflight")


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


def _post_json(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        body = resp.read().decode("utf-8")
    return json.loads(body) if body else {}


def _birth_proposal(
    *,
    backend_url: str,
    public_key: str,
    cfg: AgentConfig,
) -> str:
    sponsor = os.getenv("BENCHMARK_BIRTH_SPONSOR", "@guardian")
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
    resp = _post_json(f"{backend_url}/api/v1/agents/birth-proposal", payload)
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
