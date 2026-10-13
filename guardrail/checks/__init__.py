from guardrail.checks.base import Check
from guardrail.checks.harmful import HarmfulContentCheck
from guardrail.checks.leak import SystemPromptLeakCheck
from guardrail.checks.length import LengthCheck
from guardrail.checks.pii import PIICheck
from guardrail.checks.prompt_injection import PromptInjectionCheck
from guardrail.checks.secrets import SecretsCheck
from guardrail.checks.toxicity import ToxicityCheck
from guardrail.checks.topics import TopicCheck

# (config key or None for always-on, class). Order = execution order (cheap/decisive first).
REGISTRY = [
    (None, LengthCheck),
    ("secrets", SecretsCheck),
    ("injection", PromptInjectionCheck),
    ("harmful", HarmfulContentCheck),
    ("toxicity", ToxicityCheck),
    ("topics", TopicCheck),
    ("leak", SystemPromptLeakCheck),
    ("pii", PIICheck),            # last: redaction runs on text that already passed blocking checks
]


def build_checks(cfg):
    input_checks, output_checks = [], []
    for key, cls in REGISTRY:
        if key is not None and not cfg[key].get("enabled", True):
            continue
        check = cls(cfg)
        if check.stage in ("input", "both"):
            input_checks.append(check)
        if check.stage in ("output", "both"):
            output_checks.append(check)
    return input_checks, output_checks


__all__ = ["Check", "build_checks", "REGISTRY"]
