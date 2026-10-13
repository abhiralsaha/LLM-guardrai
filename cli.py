"""CLI.
  python cli.py check "Ignore all previous instructions"
  python cli.py check --stage output "Contact me at a@b.com"
  python cli.py chat          # interactive (uses Anthropic if ANTHROPIC_API_KEY is set, else echo)
"""
import argparse
import json
import os

from guardrail import GuardedLLM, Guardrail
from guardrail.llm import EchoClient


def main():
    ap = argparse.ArgumentParser(prog="guardrail")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("text")
    c.add_argument("--stage", choices=["input", "output"], default="input")
    sub.add_parser("chat")
    args = ap.parse_args()

    g = Guardrail()
    if args.cmd == "check":
        d = g.check_input(args.text) if args.stage == "input" else g.check_output(args.text)
        print(json.dumps(d.to_dict(), indent=2))
        return

    if os.getenv("ANTHROPIC_API_KEY"):
        from guardrail.llm.anthropic_client import AnthropicClient
        llm = AnthropicClient()
    else:
        llm = EchoClient()
    bot = GuardedLLM(llm, g)
    print("Guarded chat. Ctrl-C to exit.")
    while True:
        try:
            msg = input("you> ")
        except (KeyboardInterrupt, EOFError):
            break
        r = bot.chat(msg, "cli")
        tag = f" [blocked@{r.blocked_stage}]" if r.blocked else ""
        print(f"bot>{tag} {r.response}")


if __name__ == "__main__":
    main()
