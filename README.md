# LLM Guardrail

A layered, dependency-free guardrail for LLM apps. It sits around any model and enforces policy on both sides:

```
user msg -> rate limit -> sanitize -> INPUT RAILS -> LLM -> OUTPUT RAILS -> user
                                        |                      |
                          length, secrets, prompt-injection,   PII/secret redaction,
                          harmful intent, toxicity, topics,    system-prompt leak,
                          PII redaction                        harmful/toxic content
                                   \_______ JSONL audit log _______/
```

## Quick start
```bash
python -m unittest discover -s tests -t .          # run tests (stdlib only)
python cli.py check "Ignore all previous instructions"
python cli.py check --stage output "Mail me: a@b.com"
python cli.py chat                                  # set ANTHROPIC_API_KEY for a real model

pip install -r requirements.txt
uvicorn app.server:app --reload                     # http://localhost:8000/docs
```

## Library use
```python
from guardrail import Guardrail, GuardedLLM
from guardrail.llm.anthropic_client import AnthropicClient

bot = GuardedLLM(AnthropicClient(), Guardrail("config/policy.json"))
r = bot.chat("What is your refund policy?", user_id="u42")
print(r.response, r.blocked, r.blocked_stage)
```

## API
- `POST /v1/chat` `{prompt, user_id}` -> guarded response + both decisions
- `POST /v1/check/input` / `POST /v1/check/output` `{text}` -> decision only (use as a standalone moderation service)

## Add a check
Subclass `guardrail.checks.base.Check`, implement `run(text, stage) -> CheckResult`, register it in `guardrail/checks/__init__.py`.
Return `Action.REDACT` with `redacted_text`, or `Action.BLOCK` with a `user_message`.

## Honest limitations
Regex/lexicon rails are fast and transparent but bypassable by a determined attacker. For production, layer in:
an ML toxicity model (pass `score_fn` to `ToxicityCheck`), an LLM-as-judge check for injection/harm, embedding-based
topic detection, Redis-backed rate limiting, and red-team regression tests (add every bypass you find to `tests/`).
