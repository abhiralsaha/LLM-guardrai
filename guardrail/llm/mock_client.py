from guardrail.llm.base import LLMClient


class EchoClient(LLMClient):
    """Offline stand-in for demos/tests. Optionally returns a canned reply."""

    def __init__(self, reply=None):
        self.reply = reply

    def generate(self, system, prompt):
        return self.reply if self.reply is not None else f"You said: {prompt}"
