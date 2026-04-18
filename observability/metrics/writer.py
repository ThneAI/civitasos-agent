"""RawWriter — RFC 4180 compliant CSV writer for raw_tick rows.

Per F.0.c IPC contract, every row is flushed and fsynced so the orchestrator
watcher (running in a separate process) can tail the file safely.

Threading: one writer per task is the expected pattern; an internal lock makes
single-process concurrent writes safe regardless.
"""
from __future__ import annotations

import csv
import os
import threading
from pathlib import Path
from typing import Mapping

from .schema import RAW_COLUMNS


class RawWriter:
    def __init__(self, csv_path: str | os.PathLike[str]) -> None:
        self._path = Path(csv_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

        new_file = not self._path.exists() or self._path.stat().st_size == 0
        # Open in line-buffered text mode; we still explicitly flush+fsync.
        self._fh = self._path.open("a", encoding="utf-8", newline="")
        self._writer = csv.writer(self._fh, quoting=csv.QUOTE_MINIMAL)
        if new_file:
            self._writer.writerow(RAW_COLUMNS)
            self._fh.flush()
            os.fsync(self._fh.fileno())

    @property
    def path(self) -> Path:
        return self._path

    def write(self, row: Mapping[str, object]) -> None:
        """Write one tick row. Missing keys default to ''. Extra keys are dropped."""
        ordered = [_csv_cell(row.get(col, "")) for col in RAW_COLUMNS]
        with self._lock:
            self._writer.writerow(ordered)
            self._fh.flush()
            os.fsync(self._fh.fileno())

    def close(self) -> None:
        with self._lock:
            if not self._fh.closed:
                self._fh.flush()
                try:
                    os.fsync(self._fh.fileno())
                except OSError:
                    pass
                self._fh.close()

    def __enter__(self) -> "RawWriter":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _csv_cell(value: object) -> str:
    """Convert a Python value to its CSV cell representation.

    csv.writer handles its own RFC 4180 quoting; we just need a string.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)
