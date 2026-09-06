from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass

_CONFUSABLES = str.maketrans({"І": "I", "і": "i", "О": "O", "о": "o", "А": "A", "а": "a"})
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/=])")


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
    if decoded:
        transformations.append("base64_decode")
    return NormalizedPrompt(
        bounded,
        " ".join(mapped.split()),
        tuple(decoded),
        tuple(transformations),
    )
