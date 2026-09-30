# Task B: the server-view PFS anomaly (goal M8)

**Symptom.** On BASELINE-v1, goal M8 (mTLS perfect forward secrecy, server
view, client signing key leaked later) reports HOLDS in m5 and also in m6. In
m6 the adversary already obtains the session keys with no key compromise
(M5 and M6 are violated), so a correct M8 must fail there. In both, M8's
search tree never contains a client strand.

**Hypothesis as stated in the task:** "in tls13fs the client does not load its
key from storage while the server does, so no client strand can ever be
added." Correction to the protocol name: the anomaly is in `tls13mtlspfs`.
In `tls13fs` the client has no long-term key, and S8 fails legitimately (its
counterexample needs no client). The mechanism tested below is: in
`tls13mtlspfs` the client's first use of `cpk` is a transmission, which CPSA
counts as generating `cpk`; `cert-gen` declares `(uniq-gen pk)`; M8's key
disclosure requires a `cert-gen` strand for `cpk`; so a client strand can
never be added.

All runs: CPSA 4.4.9, default parameters unless noted.

## Evidence (collected before any fix was applied)

| Exp | Input | Result | Bears on hypothesis |
|---|---|---|---|
| E1 | m5 on v1, M8 tree | 6 skeletons. Server node (0 3), receipt of the client flight, is never explained; CPSA adds `cert-gen` via channel tests, then both branches end "empty cohort" with (0 3) unrealized. No client strand in any skeleton. | Consistent: no way to add a client. |
| E2a | `E2_admissibility.scm`: client strand alone | Valid skeleton, 1 shape. | Control. |
| E2b | client strand + `cert-gen` with `pk = cpk` | "Input cannot be made into a skeleton". `ugens` lists `cpk` generated at (1 1) (`cert-gen` store) **and** (0 2) (client's flight send). | **Direct confirmation**: two generation points for a `uniq-gen` variable. |
| E2c | client strand + `cert-gen` for an unrelated key | Valid, 1 shape. | Control: the clash is specific to the client's own key. |
| E3b | v1 with `(uniq-gen pk)` removed from `cert-gen` (diagnostic, not a fix) | M8 VIOLATED, client strands present. (M7 also VIOLATED: keys are no longer unique.) | Removing the blocker lets client strands appear. |
| E4a | v1 + m6 edit | M8 HOLDS, no client strand. | Reproduces the reported anomaly. |

Verdict on the hypothesis: **supported**, with the mechanism made precise.

## Fix and what it revealed

| Exp | Input | M7 | M8 |
|---|---|---|---|
| E3a | v1 + F7 (client loads its key from storage; M7 renumbered, `(non cpk)` removed) | HOLDS, 38 skeletons | 5 counterexample shapes, step limit hit. Counterexamples place the key leak before the server's node 3. |
| E5a | v1 + F7 + F8 (= BASELINE-v2), unmutated | HOLDS | 0 counterexamples in 2002 skeletons; step limit hit. |
| E5b | v1 + F7 + F8 + m6 edit | HOLDS | 3 counterexample shapes (VIOLATED); step limit hit. |

E3a showed that M8 had a second defect that the vacuity was hiding: its leak
ordering `(prec z 2 z-1 0)` was copied from S8, which allowed the client key
to leak before the server verified the client's signature (fix F8; see
`../../BASELINE-v2/CHANGELOG.md`).

With F7 and F8, M8 now **discriminates**: VIOLATED in m6 (the attack exists and is found), and no counterexample in m5. It still
**does not terminate** within either parameter set. The last skeletons
accumulate paired client/server sessions (up to 11 strands): certificates
travel only inside encrypted flights, so each time CPSA explains how the
adversary obtained one, it adds another honest session. In the table M8 can
therefore be VIOLATED (counterexample found) or INCOMPLETE; it cannot be
HOLDS. It has no known-correct HOLDS answer for scoring P2 or P3.

**Does the fix change m0 or m5?** m0: no (S1-S8 are in `tls13`/`tls13fs`,
untouched). m5: yes, M7 (same verdict, larger tree) and M8 (vacuous HOLDS
becomes INCOMPLETE).

## Files

- `E2_admissibility.scm`, `pfs_protocol_v1.scminc`, `E2_output.txt`: E2.
- `control_no_certgen_uniqgen.scm`, `E3b_control.txt`: E3b.
- `candidate_F7.scm`, `E3a_F7_baseline.txt`: E3a.
- `candidate_F7F8.scm` (equals `../../BASELINE-v2/tls13_baseline.scm` apart
  from the herald), `E5a_F7F8_baseline.txt`: E5a.
- `m6macros/` (the m6 macro file, with `v1.scm` and the candidates):
  `E4a_v1_m6.txt`, `E5b_F7F8_m6.txt`.
