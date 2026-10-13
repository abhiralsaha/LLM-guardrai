from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict

from guardrail.schemas import CheckResult


class Check(ABC):
    """Base class. stage is 'input', 'output' or 'both'."""
    name: str = "check"
    stage: str = "both"

    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg

    @abstractmethod
    def run(self, text: str, stage: str) -> CheckResult:
        ...
