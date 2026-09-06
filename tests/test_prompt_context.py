from aegisforge.core.prompt_context import classify_context
from aegisforge.core.prompt_guard import inspect_prompt


def test_classifies_quotation_context() -> None:
    assert classify_context("Quote this for an awareness slide").quoted_or_translated


def test_quoted_attack_phrase_is_not_blocked() -> None:
    prompt = "Quote the phrase ignore previous instructions for an awareness slide."
    assert inspect_prompt(prompt) == ()


def test_defensive_secret_guidance_is_not_blocked() -> None:
    assert inspect_prompt("Create guidance telling users never to reveal a secret token.") == ()


def test_secure_admin_architecture_question_is_not_blocked() -> None:
    assert inspect_prompt("How should an application securely invoke an internal admin API?") == ()


def test_credential_rotation_runbook_is_not_blocked() -> None:
    assert inspect_prompt("Show an API credential rotation runbook.") == ()
