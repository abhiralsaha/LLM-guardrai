"""Keyword allow/deny topic rails (input only)."""
from guardrail.checks.base import Check
from guardrail.schemas import Action, CheckResult


class TopicCheck(Check):
    name = "topic"
    stage = "input"

    def run(self, text, stage):
        cfg = self.cfg["topics"]
        low = text.lower()
        for kw in cfg["blocked_keywords"]:
            if kw.lower() in low:
                return CheckResult(self.name, Action.BLOCK, 1.0, f"blocked topic keyword: {kw}",
                                   user_message="That topic is outside what I can help with.")
        allowed = cfg["allowed_keywords"]
        if allowed and not any(kw.lower() in low for kw in allowed):
            return CheckResult(self.name, Action.BLOCK, 0.8, "off-topic (no allowed keyword)",
                               user_message="I can only help with topics related to this service.")
        return CheckResult(self.name)
