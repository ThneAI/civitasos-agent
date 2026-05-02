"""Benchmark-facing H.1 Telos helpers.

The canonical implementation lives in civitasos_runtime.telos. This wrapper
keeps benchmark code from importing runtime internals at call sites.
"""
from __future__ import annotations

from civitasos_runtime.telos import build_telos_alignment, served_intent_layer_for_action

__all__ = ["build_telos_alignment", "served_intent_layer_for_action"]
