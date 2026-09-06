from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit


class TargetPolicyError(ValueError):
    """Raised when a target falls outside the authorized lab boundary."""


Resolver = Callable[[str], Iterable[str]]


@dataclass(frozen=True)
class ValidatedTarget:
    url: str
    hostname: str
    resolved_addresses: tuple[str, ...]


def _system_resolver(hostname: str) -> Iterable[str]:
    return {item[4][0] for item in socket.getaddrinfo(hostname, None)}


def validate_target(
    raw_url: str,
    *,
    allow_private: bool = False,
    resolver: Resolver = _system_resolver,
) -> ValidatedTarget:
    """Validate a target before a worker is allowed to connect.

    MVP policy permits HTTP(S) on loopback addresses only. Private container
    ranges can be enabled explicitly for the isolated Docker lab.
    """
    parsed = urlsplit(raw_url)
    if parsed.scheme not in {"http", "https"}:
        raise TargetPolicyError("target scheme must be http or https")
    if not parsed.hostname:
        raise TargetPolicyError("target must include a hostname")
    if parsed.username or parsed.password:
        raise TargetPolicyError("userinfo is not allowed in target URLs")

    try:
        addresses = tuple(sorted(set(resolver(parsed.hostname))))
    except OSError as exc:
        raise TargetPolicyError("target hostname could not be resolved") from exc
    if not addresses:
        raise TargetPolicyError("target hostname resolved to no addresses")

    for value in addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise TargetPolicyError("resolver returned an invalid IP address") from exc

        permitted = address.is_loopback or (allow_private and address.is_private)
        prohibited = address.is_unspecified or address.is_multicast or address.is_link_local
        if not permitted or prohibited:
            raise TargetPolicyError(f"address {address} is outside the authorized lab boundary")

    return ValidatedTarget(
        url=parsed.geturl(),
        hostname=parsed.hostname,
        resolved_addresses=addresses,
    )

