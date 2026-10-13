from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agent import TxWardenAgent
from .llm import AnthropicLLM
from .models import Tx
from .risk import PolicyConfig, assess
from .simulator import AnvilSimulator


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="txwarden")
    p.add_argument("tx_json", help="path to a JSON file: {sender,to,data,value,chain_id}")
    p.add_argument("--rpc", default="http://127.0.0.1:8545", help="Anvil fork RPC URL")
    p.add_argument("--intent", default="", help="what the user says they want to do")
    p.add_argument("--no-llm", action="store_true", help="skip the LLM; print deterministic findings")
    p.add_argument("--trust-spender", action="append", default=[])
    p.add_argument("--trust-recipient", action="append", default=[])
    p.add_argument("--deny", action="append", default=[])
    a = p.parse_args(argv)

    tx = Tx.from_dict(json.loads(Path(a.tx_json).read_text()))
    policy = PolicyConfig(set(a.trust_spender), set(a.trust_recipient), set(a.deny))
    sim = AnvilSimulator(a.rpc)

    if a.no_llm:
        verdict, findings = assess(tx, sim.simulate(tx), policy)
        print(json.dumps({"verdict": verdict.value, "findings": [f.to_dict() for f in findings]}, indent=2))
        return 0 if verdict.value == "ALLOW" else 2

    review = TxWardenAgent(AnthropicLLM(), sim, policy).review(tx, a.intent)
    print(json.dumps({"verdict": review.verdict.value, "explanation": review.explanation,
                      "findings": [f.to_dict() for f in review.findings]}, indent=2))
    return 0 if review.verdict.value == "ALLOW" else 2


if __name__ == "__main__":
    sys.exit(main())
