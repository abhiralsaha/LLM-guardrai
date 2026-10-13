"""Config loading with deep-merged defaults."""
from __future__ import annotations

import copy
import json
import os
from typing import Any, Dict, Optional, Union

DEFAULTS: Dict[str, Any] = {
    "fail_fast": True,
    "max_input_chars": 8000,
    "system_prompt": "You are a helpful assistant.",
    "refusal_message": "Sorry, I can't help with that request.",
    "rate_limit": {"enabled": True, "capacity": 10, "refill_per_sec": 0.5},
    "injection": {"enabled": True, "threshold": 0.7},
    "harmful": {"enabled": True},
    "pii": {"enabled": True, "input_action": "redact", "output_action": "redact"},
    "secrets": {"enabled": True, "input_action": "block", "output_action": "redact"},
    "toxicity": {"enabled": True, "threshold": 0.8},
    "topics": {"enabled": False, "blocked_keywords": [], "allowed_keywords": []},
    "leak": {"enabled": True, "ngram": 5, "threshold": 0.15},
    "audit": {"enabled": True, "path": "logs/audit.jsonl", "log_text": False},
}


def _merge(base: Dict[str, Any], over: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(source: Union[None, str, Dict[str, Any]] = None) -> Dict[str, Any]:
    """source: None (env GUARDRAIL_CONFIG or defaults), a path to JSON, or a dict."""
    if isinstance(source, dict):
        return _merge(DEFAULTS, source)
    path: Optional[str] = source or os.getenv("GUARDRAIL_CONFIG")
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return _merge(DEFAULTS, json.load(f))
    return copy.deepcopy(DEFAULTS)
