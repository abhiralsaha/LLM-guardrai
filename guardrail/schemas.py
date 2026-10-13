"""Shared data types."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any, Dict, List, Optional


class Action(IntEnum):
    """Ordered by severity so max() gives the strictest outcome."""
    ALLOW = 0
    REDACT = 1
    BLOCK = 2


@dataclass
class CheckResult:
    name: str
    action: Action = Action.ALLOW
    score: float = 0.0
    reason: str = ""
    redacted_text: Optional[str] = None      # set when action == REDACT
    user_message: Optional[str] = None       # safe message shown to the user on BLOCK
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def triggered(self) -> bool:
        return self.action != Action.ALLOW


@dataclass
class Decision:
    stage: str                                # "input" | "output"
    action: Action
    text: str                                 # final text (possibly redacted) or "" if blocked
    results: List[CheckResult]
    latency_ms: float = 0.0

    @property
    def allowed(self) -> bool:
        return self.action != Action.BLOCK

    @property
    def blocking_result(self) -> Optional[CheckResult]:
        for r in self.results:
            if r.action == Action.BLOCK:
                return r
        return None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["action"] = self.action.name
        d["allowed"] = self.allowed
        for r in d["results"]:
            r["action"] = Action(r["action"]).name
        return d


@dataclass
class ChatResult:
    response: str
    blocked: bool
    blocked_stage: Optional[str]
    input_decision: Optional[Decision] = None
    output_decision: Optional[Decision] = None
