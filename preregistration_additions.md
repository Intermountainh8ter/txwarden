
## 2026-10-27T00:39:15Z 7702-permit2-fn-audit proposal:b8654efd1afd9b516b7b43d2728e20fec14fded4f637245b346e21044600c5bc

Set: constructed and SIMULATED (not real on-chain transactions, not a public labelled release).
Hypothesis: the engine has no EIP-7702 handling in src, so on constructed malicious 7702
delegation cases its unsafe-ALLOW false-negative rate is at least 0.80, while on constructed
malicious Permit2 cases (unlimited approval or permit to an unknown spender) it is at most 0.20;
overall false-negative rate over all malicious cases lands between 0.30 and 0.70.
Metric: /false_negative_rate/overall (FN = engine verdict ALLOW on a malicious case).
Expected: 0.30 to 0.70, driven by 7702 cases near 1.0 and Permit2 cases near 0.
Falsifier: overall rate outside 0.30-0.70, or 7702 rate below 0.80, or Permit2 rate above 0.20.
