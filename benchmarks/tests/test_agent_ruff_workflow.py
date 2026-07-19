from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_ruff_is_pinned_and_checked_in_ci() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "ruff.yml").read_text(
        encoding="utf-8"
    )

    assert '"ruff==0.15.22"' in pyproject
    assert 'python -m pip install "ruff==0.15.22"' in workflow
    assert "ruff check ." in workflow
    assert "ruff format" not in workflow
