"""Text normalisation to defeat simple obfuscation (zero-width chars, homoglyphs, leetspeak)."""
from __future__ import annotations

import re
import unicodedata

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad\u202a\u202b\u202c\u202d\u202e"), None)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})


def sanitize(text: str) -> str:
    """Canonical form shown to downstream checks and the LLM."""
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_ZERO_WIDTH)
    text = _CONTROL.sub("", text)
    return text.strip()


def for_matching(text: str) -> str:
    """Aggressive form used only for pattern matching (never sent to the LLM)."""
    t = sanitize(text).lower().translate(_LEET)
    t = re.sub(r"[_\-\.\*]+", " ", t)           # i.g.n.o.r.e -> i g n o r e handled below
    t = re.sub(r"\b(?:\w\s){3,}\w\b", lambda m: m.group(0).replace(" ", ""), t)  # "i g n o r e" -> "ignore"
    return re.sub(r"\s+", " ", t)
