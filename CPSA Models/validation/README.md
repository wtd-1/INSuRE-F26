# Validation of the mentor's mTLS 1.3 models (mtls0, mtls1, mtls2)

Run 2026-10-13, CPSA 4.4.9. Reproduce with `python3 run_validation.py`
(needs `cpsa4` in `~/.local/bin`). It regenerates `models/`, `outputs/`,
`mutant_macros/` and `results.csv`. It prints `78 checks, 0 not as expected`.

The mentor's files in `../` are not modified. Each test model is the mentor's
`mtls13` protocol, copied verbatim from `../mtls2.scm`. A test may remove
named rules and append one goal or skeleton. Mutant tests also swap in a
mutated macro file. Nothing else changes.

## What the mentor stated, and what was checked

| Mentor's statement | Test | Result |
|---|---|---|
| mtls0: legitimate clients and servers do not leak their DH exponents | R_mtls0 | Both goals HOLD, 0.03 s |
| mtls1: the DH secret is not leaked between legitimate parties; legitimacy = the peer's signing key is non-originating | R_mtls1 | Both goals HOLD, 0.1 s |
| mtls2: each skeleton gives one shape in which both parties agree on all variables | R_mtls2 | One shape each: client5+server5 and server5+client4 |
| "Proves the mutual authentication" with injective agreement | B1-B4 | Stated as goals and proven: full agreement on all 9 handshake parameters (B1, B2) and uniqueness of the matching peer strand (B3, B4) |
| The CA's signing key need not be non-originating | B1-B4, S_* | No test assumes anything about `privk ca`. Every positive result holds without it |
| Only the participant's (peer's) key matters | C5, D2, D3 | The server skeleton with only `(invk cpk)` gives the same single shape as mtls2 (D2). With only its own `(invk spk)`, no client appears (D3). The agreement goal with the server's own key instead of the client's is VIOLATED (C5) |
| All files run quickly | every row | Slowest model 1.01 s |

## Additional checks the statement implies

**A: rule soundness at the heights used.** Each rule is applied at a lower
strand height than its goal was proven at. The exponent rules use client 1
and server 2; mtls0 proved them at heights 4 and 5. The DH rules use client 2
and server 3; mtls1 proved them at 4 and 5. Re-proving each lemma at the rule's
own height also HOLDS (A1, A2), so the rules as written are sound.

**C: negative controls.** Removing the peer-key assumption makes every
positive result VIOLATED (C1-C4, C6). So the proofs depend on that
assumption and are not vacuous.

**S: session-key secrecy.** These are the four application-key goals in
mtls2's commented block, restated for mutual authentication: the peer key
replaces the CA key. At CPSA's default strand bound of 12 they stop with
"Strand bound exceeded" (INCOMPLETE). At `-b 30` all four HOLD in under 1 s.
The default bound is too small for these goals. The protocol itself is fine.

**F: the unproven axiom.** `clients-servers-distinct` is assumed, not
proven. The two lemma sets and both agreement goals still HOLD without it
(F1-F3), so no result depends on it.

## Findings to raise with the mentor

1. **On CPSA 4.4.9 the lemma rules do not change any analysis.** With all
   four rules removed, the mtls2 skeletons (E2) and the secrecy goals (E3)
   give the same verdicts with the same skeleton counts. With the old macro
   file (`TLS1.3_macros_old.lisp`), the mtls2 skeletons hit the strand bound
   whether the rules are present or not (E4, E5). With the corrected macros,
   they finish in either case. So the speedup observed here comes from the
   macro correction (our BASELINE F4). It may differ on the mentor's CPSA
   version. Ask which version he uses, and whether the rules were needed
   there before or after the macro fix.
2. **The secrecy goals need `-b 30`.** This should be added to the herald
   (`(bound 30)`) when the goals are uncommented.
3. **Typo in mtls2's commented server-agreement goal.** It writes
   `(p "client" "cpk" z cpk)` and `(p "client" "c" z c)`, which should use
   `z-0`. As written, these two lines constrain the server strand, not the
   client.
4. **mtls2's server skeleton** declares `(non-orig (invk spk) (invk cpk))`.
   By D2 the `(invk spk)` is unnecessary, as his own remark about legitimacy
   predicts.

## M: cross-check against our mutation answer key

`mutant_macros/` deletes a CertificateVerify everywhere it occurs, on the
wire and inside transcripts, as `Mutations/` m1, m6 and m8 do.
m1 deletes the server's signature, m6 the client's, and m8 both.

Each mutant is staged so that a lemma becomes a rule only after it is
re-proven on that mutant:
1. Prove the exponent lemmas with no rules.
2. Prove the DH lemmas, using only the stage-1 lemmas that held.
3. Check agreement and the secrecy goals, using only the lemmas that held.

The 30 expected verdicts were written to `predictions_mutants.csv` and
hashed (`predictions_mutants.sha256`, 11:12 CDT) before any mutant ran. Every
verdict matches its prediction.

| | DH lemma (client / server) | Agreement (client / server) | Secrecy (client / server) | Mutations/ result |
|---|---|---|---|---|
| m1 (server CV deleted) | V / H | V / H | V / H | (mTLS m1 not in Mutations/) |
| m6 (client CV deleted) | H / V | H / V | H / V | M1 H, M2 V, M3-4 H, M5-6 V |
| m8 (both deleted) | V / V | V / V | V / V | all V |

In every mutant the exponent lemmas still hold. Deleting a signature never
exposes an exponent.

So the mentor's model and our independently fixed BASELINE-v2 give the same
verdicts for every mTLS mutant they share. The two differ in how they
handle cross-role certificates: the mentor uses an axiom, we use the F5
role tag.

## Honest limits

- Only the mutant predictions were sealed in advance. The `expected` column
  for the other tests is a regression record. It was written after a first
  exploratory run, though most entries follow directly from the mentor's
  statements.
- Stage 3 and the secrecy goals use `-b 30`. Everything else uses the
  default bound of 12.
- Perfect forward secrecy for mTLS (`Mutations` goal M8) is not covered by
  the mentor's files and is still open.
