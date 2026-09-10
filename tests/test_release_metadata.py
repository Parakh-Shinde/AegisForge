import tomllib
from pathlib import Path

from aegisforge import __version__


def test_package_and_project_versions_match_release() -> None:
    project_root = Path(__file__).parents[1]
    payload = tomllib.loads(
        (project_root / "pyproject.toml").read_text(encoding="utf-8")
    )

    assert __version__ == "0.9.0"
    assert payload["project"]["version"] == __version__


def test_release_notes_preserve_holdout_limitations() -> None:
    project_root = Path(__file__).parents[1]
    notes = (project_root / "docs" / "RELEASE_V0.9.0.md").read_text(encoding="utf-8")

    assert "generalization gap" in notes
    assert "not a production-ready" in notes
    assert "Do not rerun" in notes
