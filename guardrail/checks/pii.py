"""PII detection + redaction (email, phone, cards w/ Luhn, SSN, Aadhaar, PAN, IPv4)."""
from __future__ import annotations

import re
from typing import List, Tuple

from guardrail.checks.base import Check
from guardrail.schemas import Action, CheckResult


def luhn_ok(number: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 19:
        return False
    total, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# (label, regex, validator or None). Order matters: most specific first.
PATTERNS: List[Tuple[str, "re.Pattern", object]] = [
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None),
    ("CARD", re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"), luhn_ok),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), None),
    ("AADHAAR", re.compile(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b"), None),
    ("PAN", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), None),
    ("IPV4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), None),
    ("PHONE", re.compile(r"(?<!\w)(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{3,5}\)?[\s-]?)\d{3,4}[\s-]?\d{3,4}(?!\w)"), lambda s: 10 <= len(re.sub(r"\D", "", s)) <= 13),
]


def find_and_redact(text: str):
    counts = {}
    for label, rx, validator in PATTERNS:
        def _sub(m, label=label, validator=validator):
            if validator and not validator(m.group(0)):
                return m.group(0)
            counts[label] = counts.get(label, 0) + 1
            return f"[REDACTED_{label}]"
        text = rx.sub(_sub, text)
    return text, counts


class PIICheck(Check):
    name = "pii"
    stage = "both"

    def run(self, text, stage):
        redacted, counts = find_and_redact(text)
        if not counts:
            return CheckResult(self.name)
        mode = self.cfg["pii"]["input_action" if stage == "input" else "output_action"]
        reason = "PII found: " + ", ".join(f"{k} x{v}" for k, v in counts.items())
        if mode == "block":
            return CheckResult(self.name, Action.BLOCK, 1.0, reason, details=counts,
                               user_message="Please don't share personal information.")
        return CheckResult(self.name, Action.REDACT, 1.0, reason, redacted_text=redacted, details=counts)
