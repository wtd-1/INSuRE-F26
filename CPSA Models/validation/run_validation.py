"""Validate the mentor's mTLS 1.3 CPSA models (mtls0.scm, mtls1.scm, mtls2.scm).

Every test model is the mentor's mtls13 protocol, taken verbatim from
../mtls2.scm (which carries all four lemma rules), with named rules removed
and a test goal or skeleton appended. Mutants (m1, m6, m8) also swap in a
mutated copy of ../TLS1.3_macros.lisp. Nothing else is changed.

Usage: python3 run_validation.py      (needs cpsa4 4.4.9 in ~/.local/bin)
Writes models/, outputs/, mutant_macros/ and results.csv next to this file.
"""
import csv
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)  # "CPSA Models"
sys.path.insert(0, os.path.join(SRC, "..", "Mutations", "tools"))
from cpsa_parse import forms  # noqa: E402

CPSA = os.path.expanduser("~/.local/bin/cpsa4")
TIMEOUT = 300
MODELS, OUTPUTS, MUTMAC = (os.path.join(HERE, d) for d in ("models", "outputs", "mutant_macros"))

text = open(os.path.join(SRC, "mtls2.scm")).read()
_fs = forms(text)
HERALD = _fs[0]
MS = next(f for f in _fs if f.startswith("(defmacro (MS"))
PROTO = next(f for f in _fs if f.startswith("(defprotocol mtls13"))

AXIOM = "clients-servers-distinct"
EXP_RULES = ["client-exponent-unavailable", "server-exponent-unavailable"]
DH_RULES = ["diffie-hellman-value-between-legitimate-parties-unavailable-1",
            "diffie-hellman-value-between-legitimate-parties-unavailable-2"]
LEMMAS = EXP_RULES + DH_RULES


# ---- model construction ----------------------------------------------------
def protocol(drop):
    p = PROTO
    for sub in forms(PROTO[1:-1]):
        m = re.match(r"\(defrule\s+(\S+)", sub)
        if m and m.group(1) in drop:
            p = p.replace(sub, f";; rule {m.group(1)} removed for this test")
    for r in drop:
        assert f"(defrule {r}" not in p, r
    return p


def write_model(name, drop, body, macros):
    rel = os.path.relpath(macros, MODELS)
    s = "\n\n".join([HERALD, f'(include "{rel}")', MS, protocol(drop), body])
    path = os.path.join(MODELS, name + ".scm")
    open(path, "w").write(s + "\n")
    return path


# ---- goals -----------------------------------------------------------------
def client_noexp(h):  # mtls0 goal 1, client height h
    return f'''(defgoal mtls13 (forall ((x rndx) (z z-0 strd))
  (implies (and (p "client" z {h}) (p "" z-0 2) (p "client" "x" z x)
                (p "" "x" z-0 x) (ugen x)) (false))))'''


def server_noexp(h):  # mtls0 goal 2, server height h
    return f'''(defgoal mtls13 (forall ((y rndx) (z z-0 strd))
  (implies (and (p "server" z {h}) (p "" z-0 2) (p "server" "y" z y)
                (p "" "x" z-0 y) (ugen y)) (false))))'''


def client_nodh(h, keyassm="(non (invk spk))"):  # mtls1 goal 1
    return f'''(defgoal mtls13 (forall
  ((cr random32) (spk akey) (s ca name) (x rndx) (y expt) (z z-0 strd))
  (implies (and (p "client" z {h}) (p "" z-0 2) (p "client" "cr" z cr)
     (p "client" "x" z x) (p "client" "y" z y)
     (p "" "x" z-0 (exp (gen) (mul x y))) (p "client" "s" z s)
     (p "client" "ca" z ca) (p "client" "spk" z spk)
     {keyassm} (ugen x) (uniq-at cr z 0)) (false))))'''


def server_nodh(h, keyassm="(non (invk cpk))"):  # mtls1 goal 2
    return f'''(defgoal mtls13 (forall
  ((sr random32) (cpk akey) (c ca name) (y rndx) (x expt) (z z-0 strd))
  (implies (and (p "server" z {h}) (p "" z-0 2) (p "server" "sr" z sr)
     (p "server" "x" z x) (p "server" "y" z y)
     (p "" "x" z-0 (exp (gen) (mul x y))) (p "server" "c" z c)
     (p "server" "ca" z ca) (p "server" "cpk" z cpk)
     {keyassm} (ugen y) (uniq-at sr z 1)) (false))))'''


VARS = ["cr", "sr", "spk", "s", "cpk", "c", "ca", "x", "y"]
CLIENT_FRESH = "(uniq-at cr z 0) (ugen x)"
SERVER_FRESH = "(uniq-at sr z 1) (ugen y)"


def sorts(pov):
    return "(x rndx) (y expt)" if pov == "client" else "(x expt) (y rndx)"


def agree(pov, peer, h_peer, assm):
    """A complete pov strand implies a peer strand of height h_peer that
    agrees on every handshake parameter (no CA assumption anywhere)."""
    pv = "\n      ".join(f'(p "{pov}" "{v}" z {v})' for v in VARS)
    qv = "\n        ".join(f'(p "{peer}" "{v}" z-0 {v})' for v in VARS)
    return f'''(defgoal mtls13 (forall
  ((cr sr random32) (spk cpk akey) (s c ca name) {sorts(pov)} (z strd))
  (implies (and (p "{pov}" z 5)
      {pv}
      {assm})
    (exists ((z-0 strd)) (and (p "{peer}" z-0 {h_peer})
        {qv})))))'''


def injective(pov, peer, h_peer, own, assm):
    """Two peer strands with the same fresh exponent are one strand. With
    full agreement (which includes the exponents) this gives injectivity.
    CPSA rejects equating x/y across roles (rndx vs expt), hence this form."""
    return f'''(defgoal mtls13 (forall
  ((cr sr random32) (spk cpk akey) (w rndx) {sorts(pov)} (z z1 z2 strd))
  (implies (and (p "{pov}" z 5) (p "{pov}" "cr" z cr) (p "{pov}" "sr" z sr)
      (p "{pov}" "x" z x) (p "{pov}" "y" z y)
      (p "{pov}" "spk" z spk) (p "{pov}" "cpk" z cpk)
      (p "{peer}" z1 {h_peer}) (p "{peer}" "{own}" z1 w)
      (p "{peer}" z2 {h_peer}) (p "{peer}" "{own}" z2 w)
      {assm})
    (= z1 z2))))'''


def secrecy(pov, label, assm):
    """Session-key secrecy: mtls2's commented goals, with the peer key
    assumption appropriate to mutual authentication and no CA assumption."""
    peerv = '(p "client" "spk" z spk) (p "client" "s" z s)' if pov == "client" \
        else '(p "server" "cpk" z cpk) (p "server" "c" z c)'
    keyv = "(spk akey) (s ca name)" if pov == "client" else "(cpk akey) (c ca name)"
    fresh = CLIENT_FRESH if pov == "client" else SERVER_FRESH
    return f'''(defgoal mtls13 (forall
  ((cr sr random32) {keyv} {sorts(pov)} (z z-0 strd))
  (implies (and (p "{pov}" z 5) (p "" z-0 2) (p "{pov}" "cr" z cr)
      (p "{pov}" "sr" z sr) {peerv}
      (p "{pov}" "ca" z ca) (p "{pov}" "x" z x) (p "{pov}" "y" z y)
      (p "" "x" z-0 (hash "{label}" cr sr (hash (exp (gen) (mul x y)) "derived")))
      {assm} {fresh}) (false))))'''


def skel(pov, nonorig):
    var = "cr" if pov == "client" else "sr"
    return f'''(defskeleton mtls13 (vars ({var} random32) (spk cpk akey))
  (defstrand {pov} 5 ({var} {var}) (spk spk) (cpk cpk))
  (uniq-orig {var}) {nonorig})'''


SPK, CPK = "(non (invk spk))", "(non (invk cpk))"
C_AGREE = agree("client", "server", 5, f"{CLIENT_FRESH} {SPK}")
S_AGREE = agree("server", "client", 4, f"{SERVER_FRESH} {CPK}")
SECRECY = [("client_secrecy_c", secrecy("client", "c ap traffic", SPK)),
           ("client_secrecy_s", secrecy("client", "s ap traffic", SPK)),
           ("server_secrecy_s", secrecy("server", "s ap traffic", CPK)),
           ("server_secrecy_c", secrecy("server", "c ap traffic", CPK))]
MTLS2_SKELETONS = (skel("client", "(non-orig (invk spk))") + "\n\n" +
                   skel("server", "(non-orig (invk spk) (invk cpk))"))


# ---- mutants ---------------------------------------------------------------
def _tok(s):
    return re.findall(r'\(|\)|"[^"]*"|[^\s()]+', re.sub(r";[^\n]*", "", s))


def _parse(toks):
    out, stack = [], []
    for t in toks:
        if t == "(":
            stack.append(out)
            out = []
        elif t == ")":
            done, out = out, stack.pop()
            out.append(done)
        else:
            out.append(t)
    return out


def _show(x):
    return "(" + " ".join(_show(y) for y in x) + ")" if isinstance(x, list) else x


def _drop_cv(x, keys, hits):
    if not isinstance(x, list):
        return x
    if x and x[0] == "CertificateVerify" and x[-1] in keys:
        hits[x[-1]] = hits.get(x[-1], 0) + 1
        return ["^"]  # spliced out of the enclosing term by CPSA
    return [_drop_cv(y, keys, hits) for y in x]


MUTANTS = {"m1": {"serverprivkey"}, "m6": {"clientprivkey"},
           "m8": {"serverprivkey", "clientprivkey"}}


def mutant_macros():
    """Delete the CertificateVerify signed by the given key everywhere it
    occurs (wire and transcripts), as Mutations/ m1, m6, m8 do."""
    tree = _parse(_tok(open(os.path.join(SRC, "TLS1.3_macros.lisp")).read()))
    paths = {"m0": os.path.join(SRC, "TLS1.3_macros.lisp")}
    for name, keys in MUTANTS.items():
        hits = {}
        body = [_drop_cv(f, keys, hits) for f in tree]
        assert set(hits) == keys, (name, hits)
        p = os.path.join(MUTMAC, f"TLS1.3_macros_{name}.lisp")
        open(p, "w").write(f";; {name}: CertificateVerify signed with {sorted(keys)} "
                           f"deleted ({hits} occurrences)\n\n" +
                           "\n\n".join(_show(f) for f in body) + "\n")
        paths[name] = p
    return paths


# ---- running and reading CPSA ----------------------------------------------
def analyses(path):
    """One record per analysis block in a cpsa4 output file."""
    blocks = []
    for f in forms(open(path).read()):
        head = f[1:].split(None, 1)[0]
        if head == "defprotocol":
            blocks.append(dict(sk=[], fin=False))
        elif head == "defskeleton" and blocks:
            blocks[-1]["sk"].append(f)
        elif head == "comment" and blocks and "Nothing left to do" in f:
            blocks[-1]["fin"] = True
    out = []
    for b in blocks:
        is_goal = bool(b["sk"]) and "(goals" in b["sk"][0]
        shapes = [s for s in b["sk"] if "(shape)" in s]
        bad = [s for s in shapes if not re.search(r"\(satisfies\s+yes\)", s)]
        if not is_goal:
            v = "SHAPES" if b["fin"] else "INCOMPLETE"
        elif bad:
            v = "VIOLATED"  # a shape is a realized execution: conclusive
        elif not b["fin"]:
            v = "INCOMPLETE"
        else:
            v = "HOLDS"
        roles = ["+".join(f"{r}{h}" for r, h in re.findall(r"\(defstrand (\w+) (\d+)", s))
                 for s in shapes]
        out.append(dict(verdict=v, finished=b["fin"], skeletons=len(b["sk"]),
                        shapes=len(shapes), shape_strands=" | ".join(roles)))
    return out


def run_cpsa(name, bound):
    out = os.path.join(OUTPUTS, name + ".txt")
    cmd = [CPSA, "-o", out] + (["-b", str(bound)] if bound else []) + [name + ".scm"]
    t = time.time()
    try:
        # cpsa4 resolves (include ...) against its working directory
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT, cwd=MODELS)
        err = r.stderr.strip().replace("\n", " ")
    except subprocess.TimeoutExpired:
        err = f"TIMEOUT {TIMEOUT}s"
    secs = round(time.time() - t, 2)
    return (analyses(out) if os.path.exists(out) else []), secs, err


ROWS = []


def test(tid, desc, expect, drop, body, macros, bound=None):
    """Run one model; expect is a list with one verdict per analysis."""
    write_model(tid, drop, body, macros)
    res, secs, err = run_cpsa(tid, bound)
    for i, e in enumerate(expect):
        r = res[i] if i < len(res) else dict(verdict="ERROR", finished=False, skeletons=0,
                                              shapes=0, shape_strands="")
        ROWS.append(dict(test=tid if len(expect) == 1 else f"{tid}#{i}", description=desc,
                         bound=bound or 12, expected=e, verdict=r["verdict"],
                         match="yes" if e == r["verdict"] else "NO",
                         finished=r["finished"], skeletons=r["skeletons"], shapes=r["shapes"],
                         shape_strands=r["shape_strands"], seconds=secs,
                         rules_removed=" ".join(drop), cpsa_stderr=err))
    return [r["verdict"] for r in res]


def main():
    for d in (MODELS, OUTPUTS, MUTMAC):
        os.makedirs(d, exist_ok=True)
    mac = mutant_macros()
    m0 = mac["m0"]
    old = os.path.join(SRC, "TLS1.3_macros_old.lisp")
    B = 30  # strand bound needed by secrecy and client injectivity (see README)

    # R. Reproduce the mentor's three files exactly as delivered.
    for f, exp in (("mtls0", ["HOLDS"] * 2), ("mtls1", ["HOLDS"] * 2), ("mtls2", ["SHAPES"] * 2)):
        model = os.path.join(MODELS, f"R_{f}.scm")
        open(model, "w").write(open(os.path.join(SRC, f + ".scm")).read()
                               .replace('(include "TLS1.3_macros.lisp")',
                                        f'(include "{os.path.relpath(m0, MODELS)}")'))
        res, secs, err = run_cpsa(f"R_{f}", None)
        for i, e in enumerate(exp):
            r = res[i]
            ROWS.append(dict(test=f"R_{f}#{i}", description=f"{f}.scm as delivered",
                             bound=12, expected=e, verdict=r["verdict"],
                             match="yes" if e == r["verdict"] else "NO",
                             finished=r["finished"], skeletons=r["skeletons"],
                             shapes=r["shapes"], shape_strands=r["shape_strands"],
                             seconds=secs, rules_removed="", cpsa_stderr=err))

    # A. Each lemma re-proven at the (lower) height at which its rule is used.
    test("A1_exp_lemmas_at_rule_height", "mtls0 goals at client 1 / server 2",
         ["HOLDS"] * 2, LEMMAS, client_noexp(1) + "\n\n" + server_noexp(2), m0)
    test("A2_dh_lemmas_at_rule_height", "mtls1 goals at client 2 / server 3",
         ["HOLDS"] * 2, DH_RULES, client_nodh(2) + "\n\n" + server_nodh(3), m0)
    # B. Mutual authentication as goals: full agreement and injectivity.
    test("B1_client_agreement", "client: server5 agrees on all 9 params; peer key only",
         ["HOLDS"], [], C_AGREE, m0)
    test("B2_server_agreement", "server: client4 agrees on all 9 params; peer key only",
         ["HOLDS"], [], S_AGREE, m0)
    test("B3_client_injective", "client: matching server strand is unique",
         ["HOLDS"], [], injective("client", "server", 5, "y", f"{CLIENT_FRESH} {SPK}"), m0, B)
    test("B4_server_injective", "server: matching client strand is unique",
         ["HOLDS"], [], injective("server", "client", 4, "x", f"{SERVER_FRESH} {CPK}"), m0, B)
    # C. Negative controls: drop the peer-key assumption.
    test("C1_dh_client_no_peer_key", "mtls1 client goal without non(invk spk)",
         ["VIOLATED"], DH_RULES, client_nodh(4, ""), m0)
    test("C2_dh_server_no_peer_key", "mtls1 server goal without non(invk cpk)",
         ["VIOLATED"], DH_RULES, server_nodh(5, ""), m0)
    test("C3_client_agreement_no_key", "B1 without non(invk spk)",
         ["VIOLATED"], [], agree("client", "server", 5, CLIENT_FRESH), m0)
    test("C4_server_agreement_no_key", "B2 without non(invk cpk)",
         ["VIOLATED"], [], agree("server", "client", 4, SERVER_FRESH), m0)
    test("C5_server_agreement_own_key", "B2 with server's OWN key instead of client's",
         ["VIOLATED"], [], agree("server", "client", 4, f"{SERVER_FRESH} {SPK}"), m0)
    test("C6_secrecy_no_peer_key", "client c-ap / server s-ap secrecy, no peer key",
         ["VIOLATED"] * 2, [], secrecy("client", "c ap traffic", "") + "\n\n" +
         secrecy("server", "s ap traffic", ""), m0, B)
    # D. Which key the skeletons need (mtls2's server skeleton also has spk).
    test("D1_client_skel_spk_only", "client skeleton, non-orig (invk spk)",
         ["SHAPES"], [], skel("client", "(non-orig (invk spk))"), m0)
    test("D2_server_skel_cpk_only", "server skeleton, non-orig (invk cpk) only",
         ["SHAPES"], [], skel("server", "(non-orig (invk cpk))"), m0)
    test("D3_server_skel_spk_only", "server skeleton, non-orig (invk spk) only",
         ["SHAPES"], [], skel("server", "(non-orig (invk spk))"), m0)
    # S. Session-key secrecy (commented out in mtls2), mutual-auth assumptions.
    for tid, g in SECRECY:
        test(f"S_{tid}_b12", "secrecy at default strand bound 12", ["INCOMPLETE"], [], g, m0)
        test(f"S_{tid}_b30", "secrecy at strand bound 30", ["HOLDS"], [], g, m0, B)
    # E. Effect of the lemma rules.
    test("E1_mtls2_skel_no_dh_rules", "mtls2 skeletons, DH rules removed",
         ["SHAPES"] * 2, DH_RULES, MTLS2_SKELETONS, m0)
    test("E2_mtls2_skel_no_lemma_rules", "mtls2 skeletons, all 4 lemma rules removed",
         ["SHAPES"] * 2, LEMMAS, MTLS2_SKELETONS, m0)
    for tid, g in SECRECY:
        test(f"E3_{tid}_no_lemma_rules", "secrecy b30, all 4 lemma rules removed",
             ["HOLDS"], LEMMAS, g, m0, B)
    test("E4_old_macros_all_rules", "mtls2 skeletons on TLS1.3_macros_old.lisp",
         ["INCOMPLETE"], [], MTLS2_SKELETONS, old)
    test("E5_old_macros_no_lemma_rules", "as E4, all 4 lemma rules removed",
         ["INCOMPLETE"], LEMMAS, MTLS2_SKELETONS, old)
    # F. The one unproven axiom, clients-servers-distinct.
    test("F1_exp_lemmas_no_axiom", "A1 without the axiom",
         ["HOLDS"] * 2, [AXIOM] + LEMMAS, client_noexp(1) + "\n\n" + server_noexp(2), m0)
    test("F2_dh_lemmas_no_axiom", "A2 without the axiom",
         ["HOLDS"] * 2, [AXIOM] + DH_RULES, client_nodh(2) + "\n\n" + server_nodh(3), m0)
    test("F3_agreement_no_axiom", "B1, B2 without the axiom",
         ["HOLDS"] * 2, [AXIOM], C_AGREE + "\n\n" + S_AGREE, m0)

    # M. Mutants, staged: a lemma is used as a rule only if it held on that
    # mutant. Expected verdicts are the sealed predictions_mutants.csv. Stage 3
    # uses bound 30 throughout (m6 client agreement needs more than 12).
    pred = {(r["mutant"], r["test"]): r["predicted"]
            for r in csv.DictReader(open(os.path.join(HERE, "predictions_mutants.csv")))}
    for m in ["m1", "m6", "m8"]:
        P = lambda t: pred[(m, t)]  # noqa: E731
        v = test(f"M_{m}_1_exp_lemmas", "stage 1: exponent lemmas, no lemma rules",
                 [P("exp_lemmas")] * 2, LEMMAS,
                 client_noexp(1) + "\n\n" + server_noexp(2), mac[m])
        bad_exp = [r for r, x in zip(EXP_RULES, v) if x != "HOLDS"]
        held = {}
        for rule, tid, g in ((DH_RULES[0], "dh_lemma_client", client_nodh(2)),
                             (DH_RULES[1], "dh_lemma_server", server_nodh(3))):
            held[rule] = test(f"M_{m}_2_{tid}", "stage 2: DH lemma, proven exp rules only",
                              [P(tid)], DH_RULES + bad_exp, g, mac[m])[0] == "HOLDS"
        drop = bad_exp + [r for r in DH_RULES if not held[r]]
        test(f"M_{m}_3_client_agreement", "stage 3", [P("client_agreement")], drop, C_AGREE, mac[m], B)
        test(f"M_{m}_3_server_agreement", "stage 3", [P("server_agreement")], drop, S_AGREE, mac[m], B)
        for tid, g in SECRECY:
            test(f"M_{m}_3_{tid}", "stage 3", [P(tid.rsplit("_", 1)[0])], drop, g, mac[m], B)

    with open(os.path.join(HERE, "results.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(ROWS[0]))
        w.writeheader()
        w.writerows(ROWS)
    bad = [r for r in ROWS if r["match"] != "yes"]
    print(f"{len(ROWS)} checks, {len(bad)} not as expected; "
          f"slowest {max(r['seconds'] for r in ROWS)} s")
    for r in bad:
        print("  UNEXPECTED", r["test"], r["expected"], "->", r["verdict"], r["cpsa_stderr"][:80])


if __name__ == "__main__":
    main()
