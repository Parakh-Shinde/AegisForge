import tomllib
from pathlib import Path

from aegisforge import __version__


def test_package_and_project_versions_match_release() -> None:
    project_root = Path(__file__).parents[1]
    payload = tomllib.loads(
        (project_root / "pyproject.toml").read_text(encoding="utf-8")
    )

    assert __version__ == "0.10.0"
    assert payload["project"]["version"] == __version__


def test_release_notes_preserve_evaluation_limitations() -> None:
    project_root = Path(__file__).parents[1]
    notes = (project_root / "docs" / "RELEASE_V0.10.0.md").read_text(
        encoding="utf-8"
    )

    assert "regression evidence only" in notes
    assert "not independent evaluation" in notes
    assert "Do not rerun" in notes
