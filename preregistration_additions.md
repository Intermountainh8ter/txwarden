
## 2026-10-27T00:39:15Z 7702-permit2-fn-audit proposal:b8654efd1afd9b516b7b43d2728e20fec14fded4f637245b346e21044600c5bc

Set: constructed and SIMULATED (not real on-chain transactions, not a public labelled release).
Hypothesis: the engine has no EIP-7702 handling in src, so on constructed malicious 7702
delegation cases its unsafe-ALLOW false-negative rate is at least 0.80, while on constructed
malicious Permit2 cases (unlimited approval or permit to an unknown spender) it is at most 0.20;
overall false-negative rate over all malicious cases lands between 0.30 and 0.70.
Metric: /false_negative_rate/overall (FN = engine verdict ALLOW on a malicious case).
Expected: 0.30 to 0.70, driven by 7702 cases near 1.0 and Permit2 cases near 0.
Falsifier: overall rate outside 0.30-0.70, or 7702 rate below 0.80, or Permit2 rate above 0.20.

## 2026-10-27T00:46:49Z approval-variants-fn-audit proposal:2451b71b5a0b87ca23255b98397f97f245e6db96142be09edcc8dafc9b137613

Set: constructed and SIMULATED (not real on-chain transactions, not a public labelled release).
Hypothesis: on constructed malicious approval-variant cases (unlimited or unbounded grant to an
unknown spender or operator via increaseAllowance, setApprovalForAll, DAI-style permit, Permit2
batch permit, Permit2 approve), the engine's unsafe-ALLOW false-negative rate is at most 0.05 for
every variant, and its false-positive rate (WARN or BLOCK) on matched benign cases (trusted
spender, bounded amount, approved=false revocations) is at most 0.10.
Metric: /false_negative_rate/overall (FN = engine verdict ALLOW on a malicious case).
Expected: at most 0.05, no variant above 0.05.
Falsifier: overall false-negative rate above 0.05, or any single variant above 0.05, or overall
false-positive rate above 0.10.
