"""Append-only JSONL audit log. Stores a hash of the text unless log_text is enabled."""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time

from guardrail.schemas import Decision


class AuditLogger:
    def __init__(self, path: str, enabled: bool = True, log_text: bool = False):
        self.path, self.enabled, self.log_text = path, enabled, log_text
        self._lock = threading.Lock()
        if enabled:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def log(self, user_id: str, original: str, decision: Decision) -> None:
        if not self.enabled:
            return
        rec = {
            "ts": time.time(),
            "user": user_id,
            "stage": decision.stage,
            "action": decision.action.name,
            "latency_ms": round(decision.latency_ms, 2),
            "text_sha256": hashlib.sha256(original.encode()).hexdigest(),
            "triggered": [
                {"check": r.name, "action": r.action.name, "score": r.score, "reason": r.reason}
                for r in decision.results if r.triggered
            ],
        }
        if self.log_text:
            rec["text"] = original
        with self._lock, open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
