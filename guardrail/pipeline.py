"""Core: Guardrail (stateless checks) and GuardedLLM (rate limit -> input rails -> LLM -> output rails)."""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Union

from guardrail.audit import AuditLogger
from guardrail.checks import build_checks
from guardrail.config import load_config
from guardrail.llm.base import LLMClient
from guardrail.rate_limiter import RateLimiter
from guardrail.sanitize import sanitize
from guardrail.schemas import Action, ChatResult, CheckResult, Decision


class Guardrail:
    def __init__(self, config: Union[None, str, Dict[str, Any]] = None):
        self.cfg = load_config(config)
        self.input_checks, self.output_checks = build_checks(self.cfg)

    def _run(self, checks, text: str, stage: str) -> Decision:
        start = time.perf_counter()
        current = sanitize(text)
        results: List[CheckResult] = []
        final = Action.ALLOW
        for check in checks:
            res = check.run(current, stage)
            results.append(res)
            if res.action == Action.REDACT and res.redacted_text is not None:
                current = res.redacted_text
                final = max(final, Action.REDACT)
            elif res.action == Action.BLOCK:
                final = Action.BLOCK
                if self.cfg["fail_fast"]:
                    break
        return Decision(stage, final, "" if final == Action.BLOCK else current, results,
                        (time.perf_counter() - start) * 1000)

    def check_input(self, text: str) -> Decision:
        return self._run(self.input_checks, text, "input")

    def check_output(self, text: str) -> Decision:
        return self._run(self.output_checks, text, "output")


class GuardedLLM:
    def __init__(self, llm: LLMClient, guardrail: Optional[Guardrail] = None):
        self.llm = llm
        self.guardrail = guardrail or Guardrail()
        cfg = self.guardrail.cfg
        rl = cfg["rate_limit"]
        self.limiter = RateLimiter(rl["capacity"], rl["refill_per_sec"]) if rl["enabled"] else None
        a = cfg["audit"]
        self.audit = AuditLogger(a["path"], a["enabled"], a["log_text"])

    def _refusal(self, decision: Decision) -> str:
        blk = decision.blocking_result
        return (blk.user_message if blk and blk.user_message else self.guardrail.cfg["refusal_message"])

    def chat(self, prompt: str, user_id: str = "anon") -> ChatResult:
        cfg = self.guardrail.cfg
        if self.limiter and not self.limiter.allow(user_id):
            return ChatResult("You're sending messages too quickly. Please wait a moment.", True, "rate_limit")

        in_dec = self.guardrail.check_input(prompt)
        self.audit.log(user_id, prompt, in_dec)
        if not in_dec.allowed:
            return ChatResult(self._refusal(in_dec), True, "input", in_dec)

        raw = self.llm.generate(cfg["system_prompt"], in_dec.text)

        out_dec = self.guardrail.check_output(raw)
        self.audit.log(user_id, raw, out_dec)
        if not out_dec.allowed:
            return ChatResult(self._refusal(out_dec), True, "output", in_dec, out_dec)
        return ChatResult(out_dec.text, False, None, in_dec, out_dec)
