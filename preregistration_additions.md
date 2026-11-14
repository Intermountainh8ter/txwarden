
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

## 2026-10-27T00:52:38Z intent-swap-fn-audit proposal:87cee481540301ed73de1c876078ae9be12085685312ad720c0e0dc54c8fa347

Set: constructed and SIMULATED (not real on-chain transactions, not a public labelled release).
Hypothesis: the engine has no intent-based-swap handling in src, so on constructed malicious
intent-swap cases (CoW-style setPreSignature, UniswapX-style execute, ERC-4337 handleOps-style
execution, with an unknown receiver or a zero or far-below-fair minimum-out) the unsafe-ALLOW
false-negative rate is at least 0.80 for every intent variant, while the false-positive rate
(WARN or BLOCK) on matched benign orders (receiver equals signer, minimum-out within 1 percent of
fair value) is at most 0.10.
Metric: /false_negative_rate/overall (FN = engine verdict ALLOW on a malicious case).
Expected: at least 0.80, every variant at least 0.80.
Falsifier: overall false-negative rate below 0.80, or any single variant below 0.80, or overall
false-positive rate above 0.10.

## 2026-10-27T07:34:02Z eip712-typed-data-fn-audit proposal:acd476fdca5f7db8b7c3b35be1fb1dfb63fdf68a651a4025289210de6d88cef9

Set: constructed and SIMULATED (not real signing requests, not a public labelled release). Tx has
no typed-data field, so each request is presented through the closest Tx representation (a
constructed 0x1901 payload in data of a Tx to the verifying contract).
Hypothesis: the rule engine cannot flag malicious off-chain EIP-712 requests (free Seaport
listings, unbounded permits, domain-mismatched requests); the overall false-negative rate on
malicious constructed cases is at least 0.5.
Metric: /false_negative_rate/overall (FN = engine verdict ALLOW on a malicious case).
Expected: at least 0.50.
Falsifier: overall false-negative rate below 0.50 with the Wilson interval upper bound under 0.5.

## 2026-11-12T10:35:29Z userop-4337-fn-audit proposal:417d967c777aa2a98d9469fc1b62ee82cb764983c42f8af43d47da66b09f6019

Set: constructed and SIMULATED (not real on-chain transactions, not a public labelled release).
Hypothesis: on constructed handleOps transactions whose UserOperation callData carries an unlimited
ERC-20 approval to an unknown spender, a batch hiding one such approval among benign calls, a
delegatecall-style target change, or an unknown paymaster, the engine's unsafe-ALLOW false-negative
rate is at least 0.60 overall because the engine does not decode UserOperation callData, while the
false-positive rate (WARN or BLOCK) on matched benign UserOperations is at most 0.10.
Metric: /false_negative_rate/overall (FN = engine verdict ALLOW on a malicious case).
Expected: at least 0.60.
Falsifier: overall false-negative rate below 0.60 with the Wilson interval upper bound under 0.60,
or overall false-positive rate above 0.10.

## 2026-11-13T11:10:07Z order-caps-miss-rate proposal:4a28adac826ea4823556e313af60d36c5e39c514242ee43ac29e9034d9dfaa8d

Set: seeded SIMULATED order sequences in a neutral generic schema (no external data).
Hypothesis: on seeded simulated orders, a per-order notional cap alone passes at least 0.80 of order
sequences that are split into sub-cap orders and jointly exceed the exposure cap, while an added
aggregate exposure rule passes at most 0.05 of them, with false-positive rate on matched benign
sequences at most 0.05 for both rules.
Metric: /miss_rate/aggregate_exposure_split (miss = per-order-only rule passes the sequence).
Expected: at least 0.80 (range 0.80 to 1.0); aggregate-rule miss rate at most 0.05.
Falsifier: per-order-only miss rate below 0.80 with Wilson upper bound under 0.80, or aggregate-rule
miss rate above 0.05, or benign false-positive rate above 0.05.

## 2026-11-14T11:39:00Z batch-depth-fn-audit proposal:ec3debca0b58d08d00bfb0919c1edba7028407c55e56042a8afda4746d346ac0

Set: seeded SIMULATED constructed multicall transactions (no external data).
Hypothesis: on seeded constructed multicall transactions (n=400 per depth) hiding an unlimited ERC-20
approval to an unknown spender among benign calls at nesting depths 1 to 6, the engine's non-BLOCK
miss rate is at most 0.05 at depth 2 and at least 0.80 at depth 6 (beyond the decoder's nesting
limit), with a benign nested-multicall BLOCK rate of at most 0.10.
Metric: /batch/miss_rate/depth_6 (miss = engine verdict is not BLOCK on a malicious case).
Expected: at least 0.80 (range 0.80 to 1.0); depth 2 at most 0.05.
Falsifier: depth-6 miss rate below 0.80, or depth-2 miss rate above 0.05, or benign false-positive
rate above 0.10.
