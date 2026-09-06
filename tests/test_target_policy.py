import pytest

from aegisforge.core.target_policy import TargetPolicyError, validate_target


def resolver(*addresses: str):
    return lambda _hostname: addresses


def test_accepts_ipv4_loopback() -> None:
    result = validate_target("http://localhost:8080", resolver=resolver("127.0.0.1"))
    assert result.hostname == "localhost"


def test_accepts_ipv6_loopback() -> None:
    result = validate_target("http://[::1]:8080", resolver=resolver("::1"))
    assert result.resolved_addresses == ("::1",)


def test_rejects_public_address() -> None:
    with pytest.raises(TargetPolicyError, match="outside"):
        validate_target("https://example.test", resolver=resolver("93.184.216.34"))


def test_rejects_mixed_dns_answer() -> None:
    with pytest.raises(TargetPolicyError, match="outside"):
        validate_target(
            "http://lab.test",
            resolver=resolver("127.0.0.1", "93.184.216.34"),
        )


def test_private_address_requires_explicit_opt_in() -> None:
    with pytest.raises(TargetPolicyError):
        validate_target("http://target", resolver=resolver("172.18.0.2"))
    result = validate_target(
        "http://target",
        allow_private=True,
        resolver=resolver("172.18.0.2"),
    )
    assert result.resolved_addresses == ("172.18.0.2",)


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://127.0.0.1", "http:///missing"])
def test_rejects_invalid_urls(url: str) -> None:
    with pytest.raises(TargetPolicyError):
        validate_target(url, resolver=resolver("127.0.0.1"))


def test_rejects_url_userinfo() -> None:
    with pytest.raises(TargetPolicyError, match="userinfo"):
        validate_target("http://user:pass@127.0.0.1:8080")

