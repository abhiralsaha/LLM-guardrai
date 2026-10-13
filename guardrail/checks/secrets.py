"""API keys / credentials / private keys."""
from __future__ import annotations

import re

from guardrail.checks.base import Check
from guardrail.schemas import Action, CheckResult

SECRET_PATTERNS = {
    "ANTHROPIC_KEY": r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b",
    "OPENAI_KEY": r"\bsk-[A-Za-z0-9]{32,}\b",
    "AWS_ACCESS_KEY": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    "GITHUB_TOKEN": r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
    "GOOGLE_API_KEY": r"\bAIza[0-9A-Za-z_\-]{35}\b",
    "SLACK_TOKEN": r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
    "JWT": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    "PRIVATE_KEY": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    "GENERIC_SECRET": r"(?i)\b(?:api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*['\"]?[A-Za-z0-9/+_\-]{12,}",
}
_COMPILED = {k: re.compile(v) for k, v in SECRET_PATTERNS.items()}


class SecretsCheck(Check):
    name = "secrets"
    stage = "both"

    def run(self, text, stage):
        found, redacted = [], text
        for label, rx in _COMPILED.items():
            if rx.search(redacted):
                found.append(label)
                redacted = rx.sub(f"[REDACTED_{label}]", redacted)
        if not found:
            return CheckResult(self.name)
        mode = self.cfg["secrets"]["input_action" if stage == "input" else "output_action"]
        reason = "secrets detected: " + ", ".join(found)
        if mode == "block":
            return CheckResult(self.name, Action.BLOCK, 1.0, reason, details={"types": found},
                               user_message="Your message appears to contain a credential or secret. "
                                            "Please remove it (and consider rotating it).")
        return CheckResult(self.name, Action.REDACT, 1.0, reason, redacted_text=redacted, details={"types": found})
