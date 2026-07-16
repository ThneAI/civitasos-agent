import os
from pathlib import Path

import pytest

from scripts.pkcs11_identity_probe import read_pin


def test_read_pin_accepts_only_owner_private_regular_file(tmp_path: Path) -> None:
    pin_file = tmp_path / "token.pin"
    pin_file.write_text("123456\n")
    pin_file.chmod(0o600)

    assert read_pin(pin_file) == "123456"

    pin_file.chmod(0o640)
    with pytest.raises(ValueError, match="group/other"):
        read_pin(pin_file)


def test_read_pin_rejects_symlink_and_fifo_without_blocking(tmp_path: Path) -> None:
    target = tmp_path / "target.pin"
    target.write_text("123456\n")
    target.chmod(0o600)
    symlink = tmp_path / "linked.pin"
    symlink.symlink_to(target)
    with pytest.raises(OSError):
        read_pin(symlink)

    fifo = tmp_path / "token.fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(ValueError, match="regular file"):
        read_pin(fifo)


def test_read_pin_rejects_empty_file(tmp_path: Path) -> None:
    pin_file = tmp_path / "empty.pin"
    pin_file.touch(mode=0o600)
    with pytest.raises(ValueError, match="empty"):
        read_pin(pin_file)
