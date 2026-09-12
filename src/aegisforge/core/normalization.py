from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass

_CONFUSABLES = str.maketrans({"І": "I", "і": "i", "О": "O", "о": "o", "А": "A", "а": "a"})
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/=])")
_QUOTED_FRAGMENT_CHAIN = re.compile(
    r"(?P<chain>['\"][A-Za-z]{1,32}['\"]"
    r"(?:\s*\+\s*['\"][A-Za-z ]{1,64}['\"]){1,7})"
)
_QUOTED_FRAGMENT = re.compile(r"['\"]([A-Za-z ]{1,64})['\"]")


@dataclass(frozen=True)
class NormalizedPrompt:
    original: str
    normalized: str
    decoded_segments: tuple[str, ...]
    transformations: tuple[str, ...]

    @property
    def inspection_texts(self) -> tuple[str, ...]:
        return (self.normalized, *self.decoded_segments)


def normalize_prompt(prompt: str, *, max_chars: int = 20_000) -> NormalizedPrompt:
    bounded = prompt[:max_chars]
    nfkc = unicodedata.normalize("NFKC", bounded)
    mapped = nfkc.translate(_CONFUSABLES)
    transformations: list[str] = []
    if nfkc != bounded:
        transformations.append("unicode_nfkc")
    if mapped != nfkc:
        transformations.append("confusable_mapping")
    decoded: list[str] = []
    for match in _QUOTED_FRAGMENT_CHAIN.finditer(mapped):
        parts = _QUOTED_FRAGMENT.findall(match.group("chain"))
        reconstructed = mapped[: match.start()] + "".join(parts) + mapped[match.end() :]
        if reconstructed not in decoded:
            decoded.append(" ".join(reconstructed.split()))
    if decoded:
        transformations.append("quoted_fragment_join")
    for match in _BASE64.finditer(mapped):
        token = match.group(1)
        if len(token) > 4096:
            continue
        try:
            value = base64.b64decode(token, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if value.isprintable():
            decoded.append(value[:4096])
    if any(_BASE64.search(segment) is None for segment in decoded):
        pass
    if any(match for match in _BASE64.finditer(mapped)):
        transformations.append("base64_decode")
    return NormalizedPrompt(
        bounded,
        " ".join(mapped.split()),
        tuple(decoded),
        tuple(transformations),
    )
