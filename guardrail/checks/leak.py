"""Detects the model leaking its system prompt via word n-gram overlap (output only)."""
from __future__ import annotations

import re

from guardrail.checks.base import Check
from guardrail.schemas import Action, CheckResult


def _tokens(s: str):
    return re.findall(r"[a-z0-9']+", s.lower())


def _ngrams(tokens, n):
    return {tuple(tokens[i:i + n]) for i in range(len(tokens) - n + 1)}


class SystemPromptLeakCheck(Check):
    name = "system_prompt_leak"
    stage = "output"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.n = cfg["leak"]["ngram"]
        self.prompt_grams = _ngrams(_tokens(cfg["system_prompt"]), self.n)

    def run(self, text, stage):
        if not self.prompt_grams:
            return CheckResult(self.name)
        overlap = len(self.prompt_grams & _ngrams(_tokens(text), self.n)) / len(self.prompt_grams)
        if overlap >= self.cfg["leak"]["threshold"]:
            return CheckResult(self.name, Action.BLOCK, round(overlap, 3), "system prompt leakage",
                               user_message="Sorry, I can't share that.")
        return CheckResult(self.name, Action.ALLOW, round(overlap, 3))
