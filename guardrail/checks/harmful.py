"""Blocks clearly harmful-intent requests (weapons, malware, self-harm methods) in input and output."""
from __future__ import annotations

import re

from guardrail.checks.base import Check
from guardrail.sanitize import for_matching
from guardrail.schemas import Action, CheckResult

CATEGORIES = {
    "weapons": (
        r"\b(how to|steps to|instructions? (for|to)|guide to)\b.{0,30}\b(build|make|assemble|synthesi[sz]e|manufacture)\b.{0,30}\b(bomb|explosive|nerve agent|bioweapon|chemical weapon|untraceable gun|ghost gun)\b",
        "I can't help with creating weapons.",
    ),
    "malware": (
        r"\b(write|create|build|generate|code)\b.{0,30}\b(ransomware|keylogger|computer virus|botnet|malware|rootkit)\b",
        "I can't help with creating malicious software.",
    ),
    "self_harm": (
        r"\b(how (do i|to|can i)|best way to|easiest way to)\b.{0,20}\b(kill myself|commit suicide|end my life|hurt myself)\b",
        "I'm really sorry you're going through this. You deserve support - please reach out to a trusted person "
        "or a local crisis line right now. In India you can call Tele-MANAS at 14416; elsewhere, findahelpline.com lists services.",
    ),
    "fraud": (
        r"\b(how to|help me)\b.{0,25}\b(steal|clone|hack)\b.{0,20}\b(credit cards?|bank accounts?|identity|passwords?)\b",
        "I can't help with fraud or theft.",
    ),
}
_COMPILED = {k: (re.compile(p, re.I | re.S), msg) for k, (p, msg) in CATEGORIES.items()}


class HarmfulContentCheck(Check):
    name = "harmful_content"
    stage = "both"

    def run(self, text, stage):
        norm = for_matching(text)
        for cat, (rx, msg) in _COMPILED.items():
            if rx.search(norm) or rx.search(text):
                return CheckResult(self.name, Action.BLOCK, 1.0, f"harmful category: {cat}",
                                   user_message=msg, details={"category": cat})
        return CheckResult(self.name)
