from guardrail.checks.base import Check
from guardrail.schemas import Action, CheckResult


class LengthCheck(Check):
    name = "length"
    stage = "input"

    def run(self, text, stage):
        limit = self.cfg["max_input_chars"]
        if len(text) > limit:
            return CheckResult(self.name, Action.BLOCK, 1.0, f"input exceeds {limit} chars",
                               user_message="Your message is too long. Please shorten it.")
        if not text.strip():
            return CheckResult(self.name, Action.BLOCK, 1.0, "empty input",
                               user_message="Please enter a message.")
        return CheckResult(self.name)
