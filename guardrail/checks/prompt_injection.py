"""Heuristic prompt-injection / jailbreak detector (weighted regex, noisy-OR scoring)."""
from __future__ import annotations

import re

from guardrail.checks.base import Check
from guardrail.sanitize import for_matching
from guardrail.schemas import Action, CheckResult

PATTERNS = [
    (r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|any|your)\b.{0,30}\b(instructions?|prompts?|rules?|guidelines?|directives?)\b", 0.9, "instruction override"),
    (r"\b(reveal|show|print|repeat|output|leak|tell me)\b.{0,25}\b(system|hidden|initial|original|secret)\b.{0,10}\b(prompt|instructions?|message)\b", 0.9, "system prompt extraction"),
    (r"\byou are now\b.{0,40}\b(dan|unfiltered|unrestricted|jailbroken|evil|developer mode)\b", 0.9, "persona hijack"),
    (r"\b(act|behave|respond) as (if )?(an? )?(unfiltered|uncensored|unrestricted|jailbroken)\b", 0.8, "unrestricted persona"),
    (r"\bpretend\b.{0,30}\b(no|without)\b.{0,15}\b(rules|restrictions|filters|guardrails|limits)\b", 0.8, "pretend no rules"),
    (r"\b(bypass|disable|turn off|circumvent|evade)\b.{0,20}\b(safety|guardrails?|filters?|moderation|restrictions)\b", 0.8, "bypass safety"),
    (r"\bdeveloper mode\b|\bjailbreak\b|\bdo anything now\b", 0.5, "jailbreak keyword"),
    (r"(<\|im_start\|>|<\|im_end\|>|\[/?inst\]|<</?sys>>|</?system>|^\s*system\s*:)", 0.7, "role/token spoofing"),
    (r"\bnew (instructions?|rules?)\s*:", 0.5, "injected instructions header"),
    (r"[A-Za-z0-9+/]{120,}={0,2}", 0.3, "long encoded blob"),
    (r"\b(translate|decode|rot13|base64)\b.{0,30}\b(then|and)\b.{0,30}\b(execute|follow|obey|run)\b", 0.6, "encoded instruction smuggling"),
]
_COMPILED = [(re.compile(p, re.I | re.S), w, label) for p, w, label in PATTERNS]


class PromptInjectionCheck(Check):
    name = "prompt_injection"
    stage = "input"

    def run(self, text, stage):
        norm = for_matching(text)
        hits, miss_prob = [], 1.0
        for rx, weight, label in _COMPILED:
            if rx.search(norm) or rx.search(text):
                hits.append(label)
                miss_prob *= (1.0 - weight)
        score = round(1.0 - miss_prob, 3)
        if score >= self.cfg["injection"]["threshold"]:
            return CheckResult(self.name, Action.BLOCK, score, "possible prompt injection: " + ", ".join(hits),
                               user_message="I can't follow instructions that try to change my rules.",
                               details={"matched": hits})
        return CheckResult(self.name, Action.ALLOW, score, details={"matched": hits})
