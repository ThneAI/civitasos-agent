from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "p3_multivm_authenticated_deploy.py"
)


def load_script():
    spec = importlib.util.spec_from_file_location("p3_multivm_authenticated_deploy", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_wait_converged_receipts_waits_for_every_node(monkeypatch):
    module = load_script()
    nodes = ("vm1", "vm2", "vm3")
    poll = 0
    calls_in_poll = 0

    def fake_request(address, path, context):
        nonlocal poll, calls_in_poll
        calls_in_poll += 1
        current_poll = poll
        if calls_in_poll == len(nodes):
            calls_in_poll = 0
            poll += 1
        count = 2 if address == module.NODES["vm3"] and current_poll < 3 else 3
        receipt_hash = "lagging" if count == 2 else "converged"
        return 200, {
            "data": {"fact_count": count, "receipt_hash": receipt_hash},
        }

    clock = iter(index * 0.01 for index in range(100))
    monkeypatch.setattr(module, "request", fake_request)
    monkeypatch.setattr(module.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(module.time, "sleep", lambda _: None)

    receipts = module.wait_converged_receipts(
        nodes, "task-id", 3, object(), timeout=1, stable_polls=3
    )

    assert poll == 6
    assert {receipt["fact_count"] for receipt in receipts.values()} == {3}
    assert {receipt["receipt_hash"] for receipt in receipts.values()} == {"converged"}
