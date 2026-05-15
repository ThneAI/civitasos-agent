from __future__ import annotations

from pathlib import Path


def test_nightly_wrapper_wires_l1_pilot_contract_chain() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_nightly_regression.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert 'RUN_L1_PILOT_001_CONTRACT_CHAIN="${RUN_L1_PILOT_001_CONTRACT_CHAIN:-0}"' in text
    assert 'L1_PILOT_001_CONTRACT_ROOT="${L1_PILOT_001_CONTRACT_ROOT:-$RUNS_ROOT/l1_pilot_001_contract_runner}"' in text
    assert 'L1_PILOT_001_WAKE_MODE="${L1_PILOT_001_WAKE_MODE:-auto}"' in text
    assert 'if [ "$RUN_L1_PILOT_001_CONTRACT_CHAIN" = "1" ]; then' in text
    assert '"$PYTHON" scripts/l1_pilot_001_contract_runner.py \\' in text
    assert '--wake-mode "$L1_PILOT_001_WAKE_MODE"' in text
    assert '--event-wake-grace "$L1_PILOT_001_EVENT_WAKE_GRACE"' in text
    assert 'L1_ENABLE_EVENT_WAKE="$L1_PILOT_001_ENABLE_EVENT_WAKE"' in text
