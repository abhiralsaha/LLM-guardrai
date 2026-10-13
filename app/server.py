"""HTTP API.  Run:  uvicorn app.server:app --reload"""
import os
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel

from guardrail import GuardedLLM, Guardrail
from guardrail.llm import EchoClient

app = FastAPI(title="LLM Guardrail", version="1.0.0")
guard = Guardrail()


def _make_llm():
    if os.getenv("ANTHROPIC_API_KEY"):
        from guardrail.llm.anthropic_client import AnthropicClient
        return AnthropicClient()
    return EchoClient()


guarded = GuardedLLM(_make_llm(), guard)


class TextIn(BaseModel):
    text: str


class ChatIn(BaseModel):
    prompt: str
    user_id: Optional[str] = "anon"


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v1/check/input")
def check_input(body: TextIn):
    return guard.check_input(body.text).to_dict()


@app.post("/v1/check/output")
def check_output(body: TextIn):
    return guard.check_output(body.text).to_dict()


@app.post("/v1/chat")
def chat(body: ChatIn):
    r = guarded.chat(body.prompt, body.user_id or "anon")
    return {
        "response": r.response,
        "blocked": r.blocked,
        "blocked_stage": r.blocked_stage,
        "input": r.input_decision.to_dict() if r.input_decision else None,
        "output": r.output_decision.to_dict() if r.output_decision else None,
    }
