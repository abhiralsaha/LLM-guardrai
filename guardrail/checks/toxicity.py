"""Lightweight lexicon toxicity scorer. Swap `score_fn` for an ML model (e.g. Detoxify) in production."""
from __future__ import annotations

import re
from typing import Callable, Optional

from guardrail.checks.base import Check
from guardrail.sanitize import for_matching
from guardrail.schemas import Action, CheckResult

LEXICON = [
    (r"\b(i|we)('| wi)?ll\b.{0,15}\b(kill|hurt|destroy|find|beat)\b.{0,15}\b(you|u|your family)\b", 1.0),
    (r"\byou (should|deserve to) (die|suffer)\b", 1.0),
    (r"\b(shut up|piss off|get lost)\b", 0.5),
    (r"\b(idiot|moron|stupid|dumb|loser|worthless|pathetic|trash)\b", 0.35),
    (r"\b(hate you|i hate)\b", 0.3),
]
_COMPILED = [(re.compile(p, re.I), w) for p, w in LEXICON]


def lexicon_score(text: str) -> float:
    norm = for_matching(text)
    miss = 1.0
    for rx, w in _COMPILED:
        n = len(rx.findall(norm))
        if n:
            miss *= (1.0 - min(1.0, w * (1 + 0.25 * (n - 1))))
    return round(1.0 - miss, 3)


class ToxicityCheck(Check):
    name = "toxicity"
    stage = "both"

    def __init__(self, cfg, score_fn: Optional[Callable[[str], float]] = None):
        super().__init__(cfg)
        self.score_fn = score_fn or lexicon_score

    def run(self, text, stage):
        score = self.score_fn(text)
        if score >= self.cfg["toxicity"]["threshold"]:
            return CheckResult(self.name, Action.BLOCK, score, "toxic or threatening language",
                               user_message="Let's keep things respectful - I can't respond to that message.")
        return CheckResult(self.name, Action.ALLOW, score)
