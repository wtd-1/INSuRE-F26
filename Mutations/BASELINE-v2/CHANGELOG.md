# BASELINE-v2 CHANGELOG

Frozen 2026-09-30 (see `FROZEN`, `MANIFEST.sha256`). **Every row of
`../results.csv` is generated from this baseline.**

BASELINE-v2 = BASELINE-v1 (fixes F1-F6, refactor R1; see
`../BASELINE-v1/CHANGELOG.md`) + the two Task B fixes below. The macro file is
identical to v1 except for one comment line. `check_expansion.sh` passes on v2.

Classification: **T** = transcription error, **D** = modelling decision (see
`../README.md`, "Modelling decisions").

| Id | Class | Where | Change |
|---|---|---|---|
| F7 | D | `tls13mtlspfs` client role; goal M7 | The client loads its signing key from local storage as its first event, `(load cpriv-stor (pv c cpk (invk cpk)))`, and declares `(gen-st (pv c cpk (invk cpk)))`, exactly as the server role already does. Without it, the client's first use of `cpk` is a transmission, which CPSA counts as generating `cpk`; that contradicts `cert-gen`'s `(uniq-gen pk)`, so no client strand could coexist with the key-disclosure machinery and M8 held vacuously. M7 is renumbered for the extra client node (`z 5`→`6`, `prec z 2`→`3`, `uniq-at cr z 0`→`1`, `uniq-at request z 3`→`4`) and loses `(non cpk)`, which CPSA rejects once the key is carried in state ("non-orig cpk carried"); stored-key secrecy is modelled by `cert-gen` + `privkey-disclose`, as in the authors' `tls13fs`. Adds one node to a protocol role, so it alters the protocol. |
| F8 | T (with a D choice) | goal M8 | Leak ordering `(prec z 2 z-1 0)` became `(prec z 5 z-1 0)`. Node 2 was copied from S8, where it is the server's last use of the leaked key (its own). In M8 the leaked key is the client's, which the server last uses at node 3 (verifying the client flight), so node 2 let the key leak mid-handshake and the adversary forged the client signature. The goal's own comment says "after completion". Node 3 is a receive node and CPSA rejects it as an ordering source ("ordered pairs not well formed"); node 5, the server's next transmission, is the earliest well-formed choice (D). |

Effect on the controls: F7 and F8 touch only `tls13mtlspfs` (goals M7, M8).
m0's in-family goals S1-S8 are unaffected (their analyses are byte-identical
between v1 and v2). m5 changes in M7 (still HOLDS, 38 instead of 20
skeletons) and M8 (no longer vacuous; the search does not finish within
either parameter set). Evidence: `../investigations/B_pfs_anomaly/README.md`.
