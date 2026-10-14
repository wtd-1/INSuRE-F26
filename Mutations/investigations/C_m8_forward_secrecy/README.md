# Task C: resolving goal M8 (mTLS forward secrecy, server view)

**Goal M8.** An honest server completes a session. The client's signing key
is disclosed *after* the session. Can the adversary read the server's
response?

On BASELINE-v2 (Task B), M8 discriminates (VIOLATED in m6) but never finishes
on the unmutated model (m0 = m5). This investigation explains why and gives
M8 an answer, without modifying BASELINE-v2.

Reproduce:
- `python3 run_m8.py` runs the quick checks, about 30 s, and should print
  32 checks, 0 not as expected.
- `python3 run_m8.py --long` adds the step-1 runs, about 25 min.

## Result

**M8 is resolved by decomposition: HOLDS for m0/m5, VIOLATED for m6.**
CPSA cannot decide it in a single run.

M8 is the conjunction of two properties. This is the standard structure of a
forward-secrecy argument:

1. **Authentication before compromise.** When the server receives the
   client's flight (node 3), it is talking to a genuine client run that
   agrees on every parameter, including both DH shares. At that point the
   client's key has not been disclosed. The disclosure comes after node 5.
2. **M8′: secrecy given an authenticated session.** A server run and a client
   run agree on every parameter. The client's key is disclosed after the
   server's node 5. The response stays secret.

| Property | m0 | m6 | Evidence |
|---|---|---|---|
| Step 2 (M8′) | **HOLDS**, no shapes, 0.1 s | HOLDS | `m8prime_*`. Non-vacuity controls: the same setting without a listener has shapes (it is realizable), and a listener on the disclosed key *is* found. |
| Step 1, inside `tls13mtlspfs` (fact `undisclosed cpk`) | INCOMPLETE: no counterexample, step limit (also with the key-separation rule: 1,198 skeletons in 15 min) | **VIOLATED** (counterexample) | `step1_*` (`--long`) |
| Step 1's counterpart in `tls13-mtls` (M2, `non (invk cpk)`) | **HOLDS** (answer key) | **VIOLATED** (answer key) | `../../results.csv` |

**How step 1 transfers from `tls13-mtls`.** Take any M8 execution and cut it
off at the server's node 5. Up to that point:
- the client key has never been sent, because only `privkey-disclose` sends
  it, and it runs after node 5;
- the storage, key-generation and disclosure events send nothing else.

What remains is an execution of the `tls13-mtls` roles in which the client
key is non-originating. Those roles are the same as in `tls13mtlspfs`, minus
the initial key load. M2 therefore applies and gives the matching client
run. Step 2 then applies.

This transfer is a paper argument, not a CPSA run. It should be checked by
the mentor (see below).

For m6, M8 is VIOLATED by a concrete CPSA counterexample. That was already
in the answer key, and this investigation does not change it.

## Why CPSA does not finish

- **Not the forward-secrecy reasoning.** Every session secret is proven
  unavailable under M8's own assumptions: the DH value, both handshake keys,
  the master secret, both application keys and their hash inputs
  (`lemma_session_m0`, 11 lemmas, 1.5 s). The same lemmas are VIOLATED in m6,
  so they discriminate.
- **The authentication of the client's flight.** CPSA must explain the
  client's certificate. Certificates travel only inside encrypted handshake
  flights, so each explanation adds another honest session, with an
  arbitrary server, whose own messages then need explaining. The tree
  widens: 294 open skeletons at depth 19 when it was cut off.
- **Search order does not help.** With `-r` (younger nodes first), the
  response cannot be shown secret until the client's DH share is known to be
  honest. That again requires step 1.
- **Neither rules nor restatements made M8 finish**, singly or together:
  - every proven lemma above, as rules;
  - publishing every certificate at key generation;
  - forbidding a key from serving as both a client and a server signing key
    (X.509 extended key usage; this removed the self-talk branches);
  - also never disclosing the server's key;
  - client-side session-key lemmas.

  Each ran 4–25 minutes and stopped at CPSA's step limit or at our time
  cap, with no counterexample. These scratch runs
  are not part of `run_m8.py`. They are summarised here so nobody repeats
  them.

## A pitfall worth knowing (affects any rule in this protocol)

Fix F7 made each role's first event a key `load`. A client's `load` and a
server's `load` have the same shape, and CPSA assigns strands to roles by
matching trace prefixes. **A rule that mentions `(p "client" z 1)` therefore
also matches every server strand.** Our first role-separation rule silently
pruned *every* skeleton, and M8 "held" in m6, which our counterexample shows
is wrong.

Rules in this protocol must use height ≥ 2. `pitfall_height1_rule` and
`pitfall_height2_rule` demonstrate it on a single server strand.

## For the answer key

| Variant | M8, CPSA alone | M8, resolved |
|---|---|---|
| m0 / m5 | UNDECIDED (INCOMPLETE) | **HOLDS**, by decomposition (M8′ in CPSA + M2 transfer) |
| m6 | VIOLATED | VIOLATED |
| m8 | VIOLATED | VIOLATED |
| m1, m2, m3, m3c, m3s, m4 (off-family) | UNDECIDED | not resolved (leakage check only, not scored) |

For scoring Prongs 2 and 3, keep both columns:
- A tool that reports HOLDS for m0/m5 M8 agrees with the resolved answer,
  which CPSA alone cannot reach.
- A tool that reports an attack there is wrong.

## For the mentor

- Is the decomposition acceptable as a resolution, in particular the
  transfer of M2 from `tls13-mtls` to the prefix of a `tls13mtlspfs`
  execution?
- This also answers our earlier question about how to bound or restate M8:
  it can be restated as M8′ together with M2.
