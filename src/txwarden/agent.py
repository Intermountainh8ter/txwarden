"""Tool-using agent. The model orchestrates and explains; it cannot change the verdict.

Safety invariant: the verdict is the max over deterministic ``assess`` results recorded by the
tool layer. If the model never calls ``assess_risk`` the agent fails closed (BLOCK).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .llm import LLM
from .models import Finding, Tx, Verdict
from .risk import PolicyConfig, assess
from .simulator import Simulator

SYSTEM = (
    "You are TxWarden, a pre-signature transaction reviewer for Ethereum. "
    "For every request: call simulate_transaction, then assess_risk, then explain the result "
    "in plain language in at most 5 sentences. You cannot approve or override a verdict; the "
    "verdict comes from assess_risk. Never tell the user to proceed if the verdict is BLOCK."
)

TOOLS: list[dict[str, Any]] = [
    {
        "name": "simulate_transaction",
        "description": "Dry-run the transaction on a forked chain. Returns approvals, transfers, swap context, revert status.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "assess_risk",
        "description": "Run the deterministic risk engine on the latest simulation. Returns verdict and findings.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
]

_ORDER = {Verdict.ALLOW: 0, Verdict.WARN: 1, Verdict.BLOCK: 2}


@dataclass
class Review:
    verdict: Verdict
    findings: list[Finding] = field(default_factory=list)
    explanation: str = ""
    tool_calls: list[str] = field(default_factory=list)


class TxWardenAgent:
    def __init__(self, llm: LLM, simulator: Simulator, policy: PolicyConfig | None = None,
                 max_steps: int = 6):
        self.llm, self.simulator = llm, simulator
        self.policy = policy or PolicyConfig()
        self.max_steps = max_steps

    def review(self, tx: Tx, user_intent: str = "") -> Review:
        sim = None
        verdict: Verdict | None = None
        findings: list[Finding] = []
        calls: list[str] = []
        prompt = (f"User intent: {user_intent or '(not stated)'}\n"
                  f"Transaction: {json.dumps(tx.__dict__)}")
        messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]
        text = ""

        for _ in range(self.max_steps):
            reply = self.llm.create(SYSTEM, messages, TOOLS)
            messages.append({"role": "assistant", "content": reply.content})
            text = "".join(b.get("text", "") for b in reply.content if b["type"] == "text")
            uses = [b for b in reply.content if b["type"] == "tool_use"]
            if reply.stop_reason != "tool_use" or not uses:
                break
            results = []
            for u in uses:
                calls.append(u["name"])
                if u["name"] == "simulate_transaction":
                    sim = self.simulator.simulate(tx)
                    out: Any = sim.to_dict()
                elif u["name"] == "assess_risk":
                    if sim is None:
                        out = {"error": "call simulate_transaction first"}
                    else:
                        v, f = assess(tx, sim, self.policy)
                        verdict = v if verdict is None or _ORDER[v] > _ORDER[verdict] else verdict
                        findings = f
                        out = {"verdict": v.value, "findings": [x.to_dict() for x in f]}
                else:
                    out = {"error": f"unknown tool {u['name']}"}
                results.append({"type": "tool_result", "tool_use_id": u["id"],
                                "content": json.dumps(out, default=str)})
            messages.append({"role": "user", "content": results})

        if verdict is None:  # fail closed
            return Review(Verdict.BLOCK, [], text or "No risk assessment was produced; blocked.", calls)
        return Review(verdict, findings, text, calls)
