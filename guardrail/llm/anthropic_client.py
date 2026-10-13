import os

from guardrail.llm.base import LLMClient


class AnthropicClient(LLMClient):
    def __init__(self, model: str = None, max_tokens: int = 1024):
        import anthropic  # lazy import so the core library has no hard dependency
        self.client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
        self.model = model or os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5")
        self.max_tokens = max_tokens

    def generate(self, system, prompt):
        msg = self.client.messages.create(
            model=self.model, max_tokens=self.max_tokens, system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
