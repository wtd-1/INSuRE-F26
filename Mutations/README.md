# TLS 1.3 mutation study (P1, CPSA)

This directory produces TLS 1.3 protocol variants whose correct verdicts are
known by construction, so that P2 (s(CASP)) and P3 (L* automata learning) can
be scored against them. Each variant is a one-line edit of one frozen
baseline. It was analysed by CPSA 4.4.9 under two fixed parameter sets, with
its predicted verdicts sealed before it was run.

- **Answer key:** `results.csv` (one row per variant and goal). `RESULTS.md`
  is a readable grid generated from it.
- **Baseline:** `BASELINE-v2/` (all rows). `BASELINE-v1/` is kept frozen as
  the model Task A ran on.
- **Findings and the rows not to score on** are listed under
  "Findings" below.

The group's original directories (`andrew_m1`, `andrew_m2`, `Aendri_m3`,
`Aendri_m4`, `Pooya_m5`, `Pooya_m6`) are untouched. Their results come from
earlier, different models and are not comparable with `results.csv`.

## Layout

| Path | Contents |
|---|---|
| `BASELINE-v1/`, `BASELINE-v2/` | `TLS1.3_macros.lisp`, `tls13_baseline.scm` (4 protocols, 16 goals), `CHANGELOG.md`, `MANIFEST.sha256`, `FROZEN`, `check_expansion.sh`, `reference_uninstrumented/` |
| `<id>/` (m0 ... m8) | model files, `variant.diff` (unified diff against BASELINE-v2), `VARIANT.md`, `predictions.csv`, `output_{tight,default}.txt`, `shapes_{tight,default}.txt`, `shapes_{tight,default}.xhtml`, `goals_{tight,default}.csv`, `timings.txt`, `run.log` |
| `m0/taskA_on_BASELINE-v1/`, `m5/taskA_on_BASELINE-v1/` | Task A runs on BASELINE-v1 |
| `investigations/B_pfs_anomaly/` | Task B evidence (goal M8) |
| `PREDICTIONS.sha256` | SHA-256 of every `predictions.csv`, sealed before the variants ran |
| `tools/` | `make_variant.py`, `write_predictions.py`, `run_variant.py`, `cpsa_parse.py`, `build_results.py`, `apply_F7F8.py` |
| `results.csv`, `RESULTS.md`, `full_run.log` | Task C output |

## Goals

The baseline `.scm` holds both families, so every run reports all 16 goals.
A variant is scored on its family's eight goals (`in_family = True`); the
other eight are recorded as a leakage check.

| Id | Protocol | Goal |
|---|---|---|
| S1 / M1 | `tls13` / `tls13-mtls` | Client-to-server injective agreement |
| S2 / M2 | same | Server-to-client injective agreement |
| S3 / M3 | same | Client view: secrecy of the client application key |
| S4 / M4 | same | Client view: secrecy of the server application key |
| S5 / M5 | same | Server view: secrecy of the server application key |
| S6 / M6 | same | Server view: secrecy of the client application key |
| S7 / M7 | `tls13fs` / `tls13mtlspfs` | PFS, client view (server key leaked after the session) |
| S8 / M8 | same | PFS, server view (S8: server key leaked; M8: client key leaked) |

S2, S5, S6 and S8 are documented in `tls13_final.scm` as expected failures:
with server-only authentication the server has no evidence about its peer.

## Method

1. **Fixes and mutations are never mixed.** Fixes live in the baseline
   (`BASELINE-v*/CHANGELOG.md`). A variant is the baseline with one line
   changed. `make_variant.py` refuses anything else and writes
   `variant.diff`.
2. **One-line mutations.** A deleted message appears both on the wire and
   inside transcript hashes, so a literal deletion touches several places.
   Refactor R1 routes each mutation point through a named macro whose
   baseline body is the original term. `check_expansion.sh` shows the
   refactor changes nothing: the macro-expanded model is byte-identical to
   the plain fixed model. A variant then redefines one macro body.
   Deletion is written `(^)`, which CPSA splices out of the enclosing list,
   so the message disappears everywhere it occurred. Before any run, every
   variant was checked to change the expanded model; controls do not. This
   check exists because the earlier m3 edited a macro the model never used.
3. **Predictions first.** `predictions.csv` (verdict and rationale per goal)
   was written for all 16 goals of every variant before that variant ran,
   and sealed in `PREDICTIONS.sha256` before any non-control variant ran.
   `run_variant.py` refuses to run without predictions and logs their hash
   and modification time before starting CPSA. Disagreements are reported as
   findings, and predictions are not edited.
4. **Fixed parameters.** Every variant is run twice: tight (`cpsa4 -b 12 -l
   500`) and default (`cpsa4`: strand bound 12, step limit 2000). A goal on
   which the two disagree is flagged `PARAMS_DISAGREE`, not averaged.
5. **Recorded per cell:** verdict, skeletons, shapes, whether the search
   finished, whether a peer strand was ever added, wall-clock seconds for the
   whole run, CPSA version, SHA-256 of both input files. CPSA does not
   report per-goal time; runs were sequential on one machine so the run
   times are comparable.
6. **Verdicts.** HOLDS: the search finished and every shape satisfies the
   goal. VIOLATED: some shape does not satisfy it; a shape is a realized
   execution, so this is conclusive even if the run was later cut off.
   INCOMPLETE: no counterexample and the search did not finish.
7. **Suspect flags** (`flags` column): `HOLDS_BUT_PREDICTED_VIOLATED`,
   `NO_PEER_STRAND` (the search tree never added the peer role; a HOLDS with
   this flag may be vacuous), `PARAMS_DISAGREE`, `INCOMPLETE`,
   `PREDICTION_MISMATCH`.

Reproduce: `python3 tools/make_variant.py <id>`, then
`python3 tools/run_variant.py <id>`, then `python3 tools/build_results.py`.
This needs `cpsa4` 4.4.9 in `~/.local/bin` (`cabal install cpsa`).

## Mutation operators

Dadeau et al. (STVR 2015,
https://onlinelibrary.wiley.com/doi/abs/10.1002/stvr.1531) could not be read
(paywalled). The operator names below are the two confirmed from a secondary
source that summarises their ICST 2011 paper: Ghabri, Maatoug and
Rusinowitch, "Compiling symbolic attacks to protocol implementation tests",
https://arxiv.org/abs/1307.8210 , section 2.3. The error classes are quoted
from the Inria CASSIS 2013 activity report on the same work
(https://radar.inria.fr/rapportsactivite/RA2013/cassis/uid72.html): "re-use
of existing keys, partial checking of received messages, incorrect
formatting of sent messages, use of exponential/xor encryption". 

| Variant | Edit (one line) | Error class (Inria CASSIS 2013) | Named operator |
|---|---|---|---|
| m1 | `ServerCertificateVerify` := `(^)` | partial checking of received messages (the client no longer verifies a server signature) | none confirmed |
| m2 | `ServerSignedMesgs` := ServerHello, Certificate (no ClientHello) | incorrect formatting of sent messages | none confirmed |
| m3 | `FinishedSel` := deleted | partial checking of received messages | none confirmed |
| m3c | `ClientFinishedSel` := deleted | partial checking of received messages | none confirmed |
| m3s | `ServerFinishedSel` := deleted | partial checking of received messages | none confirmed |
| m4 | `ServerDHFresh` := `(^)` | re-use of existing keys | closest: nonce mutant (freshness), but applied at generation, not at the receiver's check |
| m4c | `ClientDHFresh` := `(^)` | re-use of existing keys | as m4 |
| m6 | `ClientCertificateVerify` := `(^)` | partial checking of received messages | none confirmed |
| m7 | `ClientCertificate` := `(^)` | partial checking of received messages | closest: agent identifier mutant (the client's name is no longer bound to anything the server checks). **CPSA rejects this variant; see Findings 6.** |
| m8 | `CertificateVerify` := `(^)` | partial checking of received messages | none confirmed |

## Modelling decisions

These edits change what is modelled rather than correct a transcription.
Each one can move a verdict, so each is stated and justified here.

**F3: which variable names the private key in the PFS protocols.** In
`tls13mtlspfs` the client and server passed the server key in opposite
orders, and the client key was passed so that `privkey-disclose` leaked the
client's public key. That made "the client's signing key is compromised"
meaningless. We adopted the convention of the authors' own `tls13fs`, where
the stored variable is the private key (`(invk spk) spk`), for both keys. The
alternative (keep public-key naming and disclose `(invk cpk)`) is equally
valid but would need a second disclosure role. The convention affects
nothing outside M7 and M8.

**F5: role tag on client certificates.** Server and client certificates were
the same term, `(enc (hash name key) (privk ca))`. CPSA could therefore
explain a server certificate as having come from a client that presented it
as its own, then explain that client's server certificate the same way,
without end. This was the reason the earlier m5/m6 runs never finished. A
client certificate is now signed over `(hash "client" name key)`. This is a
real protocol-level property: X.509 certificates carry an extended key usage,
and a TLS server must not accept a certificate without clientAuth in the
client role (RFC 5280, section 4.2.1.12,
https://www.rfc-editor.org/rfc/rfc5280). It is still a decision: a model
without key-usage checking (an implementation that ignores EKU) would
legitimately allow cross-role certificate reuse. That would be a mutation
worth adding, but CPSA cannot currently analyse it to completion.

**F6: required client height in M2 (5 to 4).** M2 asked that a server which
completed its run can conclude a client completed all five of its events,
including receipt of the server's final response. No protocol can give a
sender that assurance about its last message. Even the unmutated mTLS model
failed M2 because of this, with a counterexample in which the client simply
had not yet received the response. Height 4 (the client sent its request,
which the server received) is the strongest agreement the server can
actually obtain. This weakens the goal, but it was fixed before any
mutation ran, to make it satisfiable by a correct protocol and not to make a
particular variant pass.

**F7: the mTLS client keeps its signing key in storage.** Task B showed that
M8 held vacuously: no client strand could ever appear, because the client's
first use of its key counted as generating it, which contradicted the
key-generation role's uniqueness. The server role already loads its key from
storage. F7 gives the client the same, which is also how real clients hold
their keys. It adds one event to the client role of `tls13mtlspfs` and
renumbers M7. It also removes M7's `(non cpk)`, which CPSA rejects for a
stored key; the storage model supplies that key's secrecy instead. The fix
was made for faithfulness, and its test was that a broken model must now
fail M8: with m6's edit M8 is VIOLATED (evidence E5b).

**F8: when the client key leaks in M8 (node 2 to node 5).** Copying S8's
ordering let the client key leak between the server's own flight and its
verification of the client's signature, so the adversary forged that
signature. That is not forward secrecy; the goal's comment says "after
completion". The earliest point CPSA accepts is the server's next
transmission, node 5, which is after the session has completed.

**Deletion semantics.** A deleted message or field is spliced out of every
message and transcript it appeared in. One exception: in the server-only
family, the client Finished is the whole of the client's last flight. That
flight is replaced by a public constant instead of being removed, so that
node numbers, and therefore every goal, stay unchanged. The constant
carries nothing the adversary cannot produce.

**Freshness mutations (m4, m4c) change the role, not the goals.** Several
goals assume `(ugen x)` or `(ugen y)` for the role under analysis. The
mutation removes freshness from the role only, and goals are the fixed
yardstick. So m4 cannot affect a server-view goal that assumes the server's
exponent is fresh, and m4c likewise for client-view goals. Aendri's earlier
m4 also deleted the goal assumptions, which changes the question rather than
the protocol.

**Baseline versioning instead of a git tag.** The git repository containing
this directory is rooted at the home directory, and `Mutations/` is
untracked. A commit and tag would have swept unrelated files into history,
so each baseline is frozen as a directory with `MANIFEST.sha256` and
`FROZEN`. BASELINE-v1 exists because the task required freezing before Task
B. Task B then added two fixes, and fixes belong in the baseline, so the
rows are built on BASELINE-v2. Nothing in `results.csv` comes from v1.

## Known limitations of the model

- **No negotiated parameters.** Versions, cipher suites, groups and signature
  algorithms are not modelled, so downgrade attacks cannot be expressed.
  This is also why transcript-coverage mutations (m2, m3*) can show no
  effect: in real TLS 1.3 the transcript binds the negotiation.
- **No pre-shared keys, resumption, 0-RTT, HelloRetryRequest or post-handshake
  authentication.** Diffie-Hellman key exchange only (the modes RFC 8773
  uses).
- **Hash is a free symbol.** Hashes are injective and collision-free, so
  transcript-collision attacks such as SLOTH
  (https://www.mitls.org/pages/attacks/SLOTH) are outside the model.
- **Simplified key schedule.** Application keys hash the randoms and the
  master secret, not the full transcript; there is no record layer or
  sequence numbering.
- **Bounded search.** Every verdict is relative to a strand bound of 12 and a
  step limit of 500 or 2000. M8 does not finish under either (see
  Findings), so it can be confirmed VIOLATED but never HOLDS.
- **Goals are CPSA's formulation** (after Cremers et al., CCS 2017,
  https://acmccs.github.io/papers/p1773-cremersA.pdf): agreement is on all
  handshake parameters, including principal names.

## Findings

Task C run: 2026-09-30, CPSA 4.4.9, all 12 variants sequential on one
machine, BASELINE-v2. Grid: `RESULTS.md`. Full log: `full_run.log`. It
includes the crash of the first run at m7, which led to the runner change
recorded below.

**1. Every completed verdict matches its sealed prediction.** This holds for
all 16 goals of every variant that CPSA accepted, in-family and off-family.
No goal differs between the tight and default runs. The remaining flags are
explained in items 5-7.

**2. Answer key for scoring P2 and P3.** Use the in-family verdicts of m0-m4c
(S1-S8) and of m5, m6, m8 (M1-M8), **except**:
- **m7**: every cell is ERROR (item 6).
- **M8 where it is INCOMPLETE** (m5 in-family; off-family in m0-m4): no
  known answer (item 7).

**3. Which messages carry which guarantees (server-only family).**
- Deleting the server CertificateVerify (m1) breaks every client-view goal,
  as does making the server's exponent non-fresh (m4).
- Deleting the ClientHello from the signed transcript (m2), or either or
  both Finished messages (m3, m3c, m3s), changes no verdict. In this model
  the server signature over both DH shares, plus key derivation, carries
  every goal. See the negotiated-parameters limitation above: in real TLS
  1.3 those messages also protect the negotiation, which is not modelled.
- m2 and m3/m3c do change the search (S1: 38 skeletons in m0, 48 in m2, 28
  in m3 and m3c). m3s and m4c leave all skeleton counts unchanged.
- In mutation-testing terms, m2, m3, m3c, m3s and m4c are **equivalent
  mutants** with respect to these goals. They are still useful for P2/P3:
  a tool that reports an attack on them is wrong within this model.

**4. Symmetry check m4 / m4c.** This is asymmetric by design, not a defect.
Client-view goals assume the client's exponent is fresh, and server-view
goals assume the server's.
- m4 (server exponent) breaks every client-view goal in both families and
  no server-view goal.
- m4c (client exponent) breaks no client-view goal. It does break the mTLS
  server-view goals M2, M5, M6 and M8, and in the server-only family those
  goals already fail.

**5. Client authentication (mTLS).** Deleting the client CertificateVerify
(m6) breaks every server-view goal: M2, M5, M6 and M8. M8 is VIOLATED by a
found counterexample, which is the non-vacuity check for fix F7. Deleting
both signatures (m8) breaks all 16 goals.

**6. m7 could not be analysed.** Deleting the client Certificate removes the
only message containing the client name `c`. CPSA then drops `c` from the
roles, and it rejects the file because goals M1 and M2 refer to it:
`tls13_baseline.scm:479:19: Identifier c unknown` (`m7/cpsa_error_*.txt`).
Making it run would need a second edit to the goals, which the one-edit rule
forbids. Therefore **m6 and m7 together do not yet isolate which message
carries client authentication.** m6 shows the signature is necessary; the
role of the certificate is untested. A one-line alternative that keeps `c`
in the trace is to send the client's name and key without the CA signature.
That is a different mutation (an unsigned certificate) and needs a decision
before it is added.

**7. M8 is undecidable within the fixed parameters.** Where no
counterexample exists, M8 reaches the step limit (500 or 2000) under both
parameter sets. This happens in m0, m1, m2, m3, m3c, m3s, m4 and m5. It is
flagged INCOMPLETE and must not be scored as HOLDS. The cause is analysed
in `investigations/B_pfs_anomaly/README.md`. M8 also dominates run time:
in m0 the other 15 goals take a few seconds, and the run takes 394 s. Runs
that hit the limit exit with status 1; every other goal in those runs
finished.

**8. NO_PEER_STRAND flags (44 rows) are all on VIOLATED goals.** They are
S2, S5, S6 and S8 in every variant: the documented server-only failures,
where the counterexample is the adversary playing the client. None is on a
HOLDS verdict, so none indicates a vacuous proof. The one vacuous proof
found in this study was M8 on BASELINE-v1 (Task B).

**9. Cross-checks.**
- m1 and m8 apply the same edit within the server-only family and give
  identical S1-S8 verdicts.
- m0 and m5 are the same file and gave byte-identical outputs on
  BASELINE-v1.
- Between v1 and v2, the analyses of S1-S8 and M1-M6 are byte-identical.

**Runner change after the first run.** When CPSA rejected m7's input, the
runner crashed before m8. It now records ERROR for every goal and saves
CPSA's message. m7 and m8 were then run with the same parameters, and their
predictions were unchanged (see `PREDICTIONS.sha256`).
