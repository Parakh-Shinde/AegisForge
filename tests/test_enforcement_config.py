import pytest

from aegisforge.config import _enforcement_mode_from_environment
from aegisforge.core.enforcement_policy import EnforcementMode


def test_enforcement_mode_reads_environment_case_insensitively(monkeypatch) -> None:
    monkeypatch.setenv("AEGISFORGE_ENFORCEMENT_MODE", "OBSERVE")

    assert _enforcement_mode_from_environment() is EnforcementMode.OBSERVE


def test_invalid_enforcement_mode_fails_closed_during_configuration(
    monkeypatch,
) -> None:
    monkeypatch.setenv("AEGISFORGE_ENFORCEMENT_MODE", "bypass")

    with pytest.raises(ValueError):
        _enforcement_mode_from_environment()
