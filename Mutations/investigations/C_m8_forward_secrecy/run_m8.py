"""Task C: resolving goal M8 (mTLS forward secrecy, server view, client key
leaked after the session).

Every model is built from BASELINE-v2's tls13mtlspfs protocol (unchanged),
with the m0 (BASELINE-v2) or m6 (Mutations/m6) macro file. Lemmas are added as
rules only after they are proven, and only to models of the same protocol and
variant they were proven on.

  python3 run_m8.py          quick checks (seconds)
  python3 run_m8.py --long   also the step-1 runs (about 25 minutes)

Writes models/, outputs/ and results.csv next to this file.
"""
import csv
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
MUT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(MUT, "tools"))
from cpsa_parse import forms  # noqa: E402

CPSA = os.path.expanduser("~/.local/bin/cpsa4")
MODELS, OUTPUTS = os.path.join(HERE, "models"), os.path.join(HERE, "outputs")
MACROS = {"m0": os.path.join(MUT, "BASELINE-v2", "TLS1.3_macros.lisp"),
          "m6": os.path.join(MUT, "m6", "TLS1.3_macros.lisp")}

_fs = forms(open(os.path.join(MUT, "BASELINE-v2", "tls13_baseline.scm")).read())
DEFMACROS = [f for f in _fs if f.startswith("(defmacro")]
PROTO = next(f for f in _fs if f.startswith("(defprotocol tls13mtlspfs"))
M7, M8 = [f for f in _fs if f.startswith("(defgoal tls13mtlspfs")]
M8_BODY = M8[len("(defgoal tls13mtlspfs"):-1].strip()

# ---- lemmas ------------------------------------------------------------------
# Heights: the client's first event (a key load) has the same shape as the
# server's, so a height-1 role predicate matches both roles. Every role
# predicate below therefore uses height >= 2.
L_EXP_CLIENT = '''(forall ((x rndx) (z z-0 strd))
      (implies (and (p "client" z 2) (p "" z-0 2) (p "client" "x" z x)
                    (p "" "x" z-0 x) (ugen x)) (false)))'''
L_EXP_SERVER = '''(forall ((y rndx) (z z-0 strd))
      (implies (and (p "server" z 3) (p "" z-0 2) (p "server" "y" z y)
                    (p "" "x" z-0 y) (ugen y)) (false)))'''
DH = "(exp (gen) (mul x y))"
DERIVED = {
    "dh": DH,
    "chs-key": f'(hash {DH} "c hs traffic" cr sr)',
    "chs-pre": f'(cat {DH} "c hs traffic" cr sr)',
    "shs-key": f'(hash {DH} "s hs traffic" cr sr)',
    "shs-pre": f'(cat {DH} "s hs traffic" cr sr)',
    "ms": f'(hash {DH} "derived")',
    "ms-pre": f'(cat {DH} "derived")',
    "sap-key": f'(hash "s ap traffic" cr sr (hash {DH} "derived"))',
    "sap-pre": f'(cat "s ap traffic" cr sr (hash {DH} "derived"))',
    "cap-key": f'(hash "c ap traffic" cr sr (hash {DH} "derived"))',
    "cap-pre": f'(cat "c ap traffic" cr sr (hash {DH} "derived"))',
}


def l_pfs(term):
    """M8's antecedent with the listener on a session secret instead of the
    response."""
    return f'''(forall ((cr sr random32) (cpk akey) (self name) (priv-stor locn) (y rndx) (x expt)
               (z z-0 z-1 strd))
      (implies (and (p "server" z 6) (p "" z-0 2) (p "privkey-disclose" z-1 3)
                    (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "cpk" z cpk)
                    (p "server" "y" z y) (p "server" "x" z x)
                    (p "" "x" z-0 {term})
                    (p "privkey-disclose" "pk" z-1 cpk)
                    (p "privkey-disclose" "self" z-1 self)
                    (p "privkey-disclose" "priv-stor" z-1 priv-stor)
                    (prec z 5 z-1 0) (ugen y) (uniq-at sr z 2)) (false)))'''


KEYSEP = '''(forall ((z0 z1 strd) (k akey))
      (implies (and (p "client" z0 2) (p "client" "cpk" z0 k)
                    (p "server" z1 2) (p "server" "spk" z1 k)) (false)))'''

V = ["cr", "sr", "spk", "s", "cpk", "c", "ca", "x", "y"]
STEP1 = (f'''(forall ((cr sr random32) (spk cpk akey) (s c ca name) (x expt) (y rndx) (z strd))
    (implies (and (p "server" z 4) {" ".join(f'(p "server" "{v}" z {v})' for v in V)}
                  (fact undisclosed cpk) (non (privk ca)) (ugen y) (uniq-at sr z 2))
      (exists ((z-0 strd)) (and (p "client" z-0 4)
        {" ".join(f'(p "client" "{v}" z-0 {v})' for v in V)}))))''')

M8_PRIME = '''(defskeleton tls13mtlspfs
  (vars (cr sr random32) (request response text) (spk cpk akey)
        (s c ca self name) (priv-stor priv-stor-0 locn) (x y rndx))
  (defstrand server 6 (cr cr) (sr sr) (request request) (response response)
             (spk spk) (cpk cpk) (s s) (c c) (ca ca) (x x) (y y) (priv-stor priv-stor-0))
  (defstrand client 5 (cr cr) (sr sr) (request request)
             (spk spk) (cpk cpk) (s s) (c c) (ca ca) (x x) (y y))
  (deflistener response)
  (defstrand privkey-disclose 3 (pk cpk) (self self) (priv-stor priv-stor))
  (precedes ((0 5) (3 0)) ((0 5) (2 0)))
  (non-orig (privk ca))
  (uniq-orig sr response)
  (uniq-gen x y))'''
# Controls: the setting is realizable (no listener), and a listener on a
# secret that really leaks (the disclosed key) is found.
M8_PRIME_V1 = M8_PRIME.replace("  (deflistener response)\n", "").replace(
    "(precedes ((0 5) (3 0)) ((0 5) (2 0)))", "(precedes ((0 5) (2 0)))")
M8_PRIME_V2 = M8_PRIME.replace("(deflistener response)", "(deflistener cpk)").replace(
    "(precedes ((0 5) (3 0)) ((0 5) (2 0)))", "(precedes ((0 5) (3 0)) ((3 2) (2 0)))")


def model(name, variant, rules, body, herald_opts="(bound 30)"):
    p = PROTO
    if rules:
        i = p.rindex("(lang")
        p = p[:i] + "\n\n  ".join(f"(defrule {n}\n    {b})" for n, b in rules) + "\n\n  " + p[i:]
    parts = [f'(herald "M8 investigation: {name}" {herald_opts})',
             f'(include "{os.path.relpath(MACROS[variant], MODELS)}")'] + DEFMACROS + [p, body]
    open(os.path.join(MODELS, name + ".scm"), "w").write("\n\n".join(parts) + "\n")


def goals(*bodies):
    return "\n\n".join(f"(defgoal tls13mtlspfs\n  {b})" for b in bodies)


def analyses(path):
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
            v = ("NO_SHAPES" if not shapes else "SHAPES") if b["fin"] else "INCOMPLETE"
        else:
            v = "VIOLATED" if bad else ("HOLDS" if b["fin"] else "INCOMPLETE")
        out.append((v, b["fin"], len(b["sk"]), len(shapes)))
    return out


ROWS = []


def run(name, expect, timeout=120):
    out = os.path.join(OUTPUTS, name + ".txt")
    t = time.time()
    try:
        r = subprocess.run([CPSA, "-o", out, name + ".scm"], cwd=MODELS,
                           capture_output=True, text=True, timeout=timeout)
        err = r.stderr.strip()
    except subprocess.TimeoutExpired:
        err = f"TIMEOUT {timeout}s"
    secs = round(time.time() - t, 1)
    res = analyses(out) if os.path.exists(out) else []
    for i, e in enumerate(expect):
        v, fin, sk, sh = res[i] if i < len(res) else ("ERROR", False, 0, 0)
        ROWS.append(dict(test=f"{name}#{i}", expected=e, verdict=v, match="yes" if v == e else "NO",
                         finished=fin, skeletons=sk, shapes=sh, seconds=secs,
                         cpsa_stderr=err.replace("\n", " ")[:120]))
        print(f"{name}#{i}: {v} (expected {e}) finished={fin} skeletons={sk} shapes={sh} {secs}s",
              flush=True)


def main(long_runs):
    os.makedirs(MODELS, exist_ok=True)
    os.makedirs(OUTPUTS, exist_ok=True)
    exp_rules = [("client-exponent-unavailable", L_EXP_CLIENT),
                 ("server-exponent-unavailable", L_EXP_SERVER)]

    # 1. Lemma chain, original M8 setting (no restatement, no extra rules).
    for v in ("m0", "m6"):
        model(f"lemma_exp_{v}", v, [], goals(L_EXP_CLIENT, L_EXP_SERVER))
        run(f"lemma_exp_{v}", ["HOLDS", "HOLDS"])
        model(f"lemma_session_{v}", v, exp_rules, goals(*[l_pfs(t) for t in DERIVED.values()]))
        run(f"lemma_session_{v}", ["HOLDS" if v == "m0" else "VIOLATED"] * len(DERIVED))

    # 2. Step 2 (M8'): secrecy given an authenticated session, plus controls.
    for v in ("m0", "m6"):
        model(f"m8prime_{v}", v, [], M8_PRIME)
        run(f"m8prime_{v}", ["NO_SHAPES"])
    model("m8prime_control_realizable_m0", "m0", [], M8_PRIME_V1)
    run("m8prime_control_realizable_m0", ["SHAPES"])
    model("m8prime_control_leak_found_m0", "m0", [], M8_PRIME_V2)
    run("m8prime_control_leak_found_m0", ["SHAPES"])

    # 3. Pitfall: with a height-1 role predicate, a rule silently matches the
    #    other role's first event (both are key loads) and prunes everything.
    lone = ('(defskeleton tls13mtlspfs (vars (spk cpk akey)) '
            '(defstrand server 6 (spk spk) (cpk cpk)))')
    model("pitfall_height1_rule", "m0",
          [("bad", '(forall ((z0 strd)) (implies (p "client" z0 1) (false)))')], lone)
    run("pitfall_height1_rule", ["NO_SHAPES"])
    model("pitfall_height2_rule", "m0",
          [("ok", '(forall ((z0 strd)) (implies (p "client" z0 2) (false)))')], lone)
    run("pitfall_height2_rule", ["SHAPES"])

    if long_runs:
        # 4. Step 1: authentication before compromise, inside tls13mtlspfs.
        for v, e in (("m0", "INCOMPLETE"), ("m6", "VIOLATED")):
            model(f"step1_{v}", v, [], goals(STEP1))
            run(f"step1_{v}", [e], timeout=900)
        # 5. The original M8 with every proven lemma as a rule still does not
        #    finish: the lemmas cover secrecy, not authentication.
        model("m8_with_lemmas_m0", "m0",
              exp_rules + [(f"server-{k}-unavailable-pfs", l_pfs(t)) for k, t in DERIVED.items()],
              goals(M8_BODY))
        run("m8_with_lemmas_m0", ["INCOMPLETE"], timeout=900)

    with open(os.path.join(HERE, "results.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(ROWS[0]))
        w.writeheader()
        w.writerows(ROWS)
    bad = [r for r in ROWS if r["match"] != "yes"]
    print(f"{len(ROWS)} checks, {len(bad)} not as expected")


if __name__ == "__main__":
    main("--long" in sys.argv)
