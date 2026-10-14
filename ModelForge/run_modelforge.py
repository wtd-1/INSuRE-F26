"""ModelForge-style experiment: natural-language spec -> LLM -> CPSA model,
scored against the validated reference model (the mentor's mtls13).

Stages (run in order; each is re-runnable):
  python3 run_modelforge.py truth      ground-truth verdicts on the reference model
  python3 run_modelforge.py generate   query the LLMs (needs the `claude` CLI)
  python3 run_modelforge.py evaluate   run CPSA on every generated model, score it
  python3 run_modelforge.py report     print the summary tables

The LLM runs in an empty sandbox directory with every tool disabled, so it sees
only the prompt: the spec, the interface contract and, in the "examples"
condition, two stock CPSA examples (neither is TLS). It never sees our models,
goals or verdicts.
"""
import csv
import json
import os
import re
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "Mutations", "tools"))
sys.path.insert(0, os.path.join(ROOT, "CPSA Models", "validation"))
from cpsa_parse import forms  # noqa: E402
import run_validation as rv  # noqa: E402  (reference protocol and mutant macros)

CPSA = os.path.expanduser("~/.local/bin/cpsa4")
GEN, EVAL = os.path.join(HERE, "generated"), os.path.join(HERE, "evaluation")
TRUTH = os.path.join(HERE, "ground_truth")

MODELS = ["claude-sonnet-5-5"]  # Haiku 5.5 exceeds the CLI 1.0.100 8192-token output cap; see README
CONDITIONS = ["zeroshot", "examples"]
VARIANTS = ["m0", "m1", "m6", "m8"]
SAMPLES = 3
BOUND = 30
TIMEOUT = 180

VARIANT_TEXT = {
    "m0": "",
    "m1": ("\n\n## Variant\n\nIn this variant the server does **not** send a "
           "CertificateVerify message. Nothing in the handshake is signed with the "
           "server's private key. Every transcript that would have contained the "
           "server CertificateVerify is computed without it. Everything else is "
           "unchanged."),
    "m6": ("\n\n## Variant\n\nIn this variant the client does **not** send a "
           "CertificateVerify message. Nothing in the handshake is signed with the "
           "client's private key. Every transcript that would have contained the "
           "client CertificateVerify is computed without it. Everything else is "
           "unchanged."),
    "m8": ("\n\n## Variant\n\nIn this variant **neither** the server nor the "
           "client sends a CertificateVerify message. Nothing in the handshake is "
           "signed with either principal's private key. Every transcript that "
           "would have contained a CertificateVerify is computed without it. "
           "Everything else is unchanged."),
}

GOALS = [("client_agreement", "client"), ("server_agreement", "server"),
         ("client_request_secrecy", "client"), ("server_response_secrecy", "server")]
VARS = ["cr", "sr", "spk", "s", "cpk", "c", "ca", "x", "y"]


# ---- goals (independent of how the model derives its keys) ------------------
def goals(rsort):
    """Four goals plus two executability skeletons. rsort is the sort of
    cr/sr: `text` in generated models, `random32` in the reference model."""
    def agree(pov, peer, h_peer, assm):
        sorts = "(x rndx) (y expt)" if pov == "client" else "(x expt) (y rndx)"
        pv = " ".join(f'(p "{pov}" "{v}" z {v})' for v in VARS)
        qv = " ".join(f'(p "{peer}" "{v}" z-0 {v})' for v in VARS)
        return (f'(defgoal mtls13 (forall ((cr sr {rsort}) (spk cpk akey) (s c ca name) '
                f'{sorts} (z strd)) (implies (and (p "{pov}" z 5) {pv} {assm}) '
                f'(exists ((z-0 strd)) (and (p "{peer}" z-0 {h_peer}) {qv})))))')

    req = (f'(defgoal mtls13 (forall ((cr {rsort}) (request text) (spk akey) (x rndx) '
           f'(z z-0 strd)) (implies (and (p "client" z 5) (p "" z-0 2) '
           f'(p "client" "cr" z cr) (p "client" "x" z x) (p "client" "spk" z spk) '
           f'(p "client" "request" z request) (p "" "x" z-0 request) '
           f'(non (invk spk)) (ugen x) (uniq-at cr z 0) (uniq-at request z 3)) (false))))')
    resp = (f'(defgoal mtls13 (forall ((sr {rsort}) (response text) (cpk akey) (y rndx) '
            f'(z z-0 strd)) (implies (and (p "server" z 5) (p "" z-0 2) '
            f'(p "server" "sr" z sr) (p "server" "y" z y) (p "server" "cpk" z cpk) '
            f'(p "server" "response" z response) (p "" "x" z-0 response) '
            f'(non (invk cpk)) (ugen y) (uniq-at sr z 1) (uniq-at response z 4)) (false))))')
    skel = (f'(defskeleton mtls13 (vars (spk cpk akey)) (defstrand client 5 (spk spk) (cpk cpk)) '
            f'(non-orig (invk spk) (invk cpk)))\n\n'
            f'(defskeleton mtls13 (vars (spk cpk akey)) (defstrand server 5 (spk spk) (cpk cpk)) '
            f'(non-orig (invk spk) (invk cpk)))')
    return "\n\n".join([
        agree("client", "server", 5, "(uniq-at cr z 0) (ugen x) (non (invk spk))"),
        agree("server", "client", 4, "(uniq-at sr z 1) (ugen y) (non (invk cpk))"),
        req, resp, skel])


def analyse(scm, cwd):
    """Run cpsa4; return (error, [verdict per analysis], seconds)."""
    out = os.path.join(cwd, scm[:-4] + ".txt")
    t = time.time()
    try:
        r = subprocess.run([CPSA, "-b", str(BOUND), "-o", out, scm], cwd=cwd,
                           capture_output=True, text=True, timeout=TIMEOUT)
        err = r.stderr.strip()
    except subprocess.TimeoutExpired:
        err = f"TIMEOUT {TIMEOUT}s"
    secs = round(time.time() - t, 2)
    res = rv.analyses(out) if os.path.exists(out) else []
    return err, res, secs


def verdicts_of(res):
    v = [r["verdict"] for r in res[:4]]
    # executability: each role can run to completion (its skeleton has a
    # shape). Without this, an unrunnable role would make every goal HOLD.
    ex = [r["shapes"] > 0 for r in res[4:6]]
    return v, ex


# ---- stage: ground truth ----------------------------------------------------
def truth():
    os.makedirs(TRUTH, exist_ok=True)
    mac = rv.mutant_macros()
    rows = []
    for m in VARIANTS:
        rel = os.path.relpath(mac[m], TRUTH)
        body = "\n\n".join([rv.HERALD, f'(include "{rel}")', rv.MS, rv.PROTO, goals("random32")])
        scm = os.path.join(TRUTH, f"reference_{m}.scm")
        open(scm, "w").write(body + "\n")
        err, res, secs = analyse(os.path.basename(scm), TRUTH)
        v, ex = verdicts_of(res)
        assert len(v) == 4, (m, err)
        rows.append(dict(variant=m, **dict(zip([g for g, _ in GOALS], v)),
                         client_executable=ex[0], server_executable=ex[1], seconds=secs))
        print(m, v, ex, secs, err[:60])
    with open(os.path.join(HERE, "ground_truth.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


# ---- stage: generate --------------------------------------------------------
def prompt(variant, condition):
    spec = open(os.path.join(HERE, "spec", "mtls13_spec.md")).read() + VARIANT_TEXT[variant]
    contract = open(os.path.join(HERE, "spec", "interface_contract.md")).read()
    parts = ["You are translating a protocol specification into a protocol definition "
             "for CPSA 4 (the Cryptographic Protocol Shapes Analyzer), written in its "
             "s-expression input language.\n",
             "# Specification\n\n" + spec, "\n" + contract]
    if condition == "examples":
        ex = os.path.join(HERE, "reference_examples")
        for f in ("sts.scm", "plaindh.scm"):
            parts.append(f"\n# Reference CPSA example: {f}\n\n```scheme\n"
                         + open(os.path.join(ex, f)).read() + "\n```\n")
    parts.append("\nWrite the CPSA model now. Transcripts repeat earlier messages, so "
                 "define repeated terms once with defmacro rather than writing them out; "
                 "keep the answer under about 250 lines. Reply with the code block only.")
    return "\n".join(parts)


def call_llm(model, text):
    with tempfile.TemporaryDirectory() as sandbox:  # empty: nothing to read
        r = subprocess.run(
            ["claude", "-p", "--model", model, "--output-format", "json",
             "--strict-mcp-config", "--disallowedTools",
             "Bash Read Write Edit Glob Grep WebFetch WebSearch Agent NotebookEdit Skill TodoWrite"],
            input=text, capture_output=True, text=True, cwd=sandbox, timeout=900,
            env={**os.environ, "CLAUDE_CODE_MAX_OUTPUT_TOKENS": "32000"})
    d = json.loads(r.stdout)
    return d.get("result", ""), d.get("total_cost_usd", 0.0)


def extract(reply):
    blocks = re.findall(r"```[a-zA-Z]*\n(.*?)```", reply, re.S)
    return max(blocks, key=len) if blocks else reply


def generate():
    os.makedirs(GEN, exist_ok=True)
    log = os.path.join(GEN, "generation_log.csv")
    done = set()
    if os.path.exists(log):
        done = {r["id"] for r in csv.DictReader(open(log))}
    new = not os.path.exists(log)
    with open(log, "a", newline="") as fh:
        w = csv.writer(fh)
        if new:
            w.writerow(["id", "model", "condition", "variant", "sample", "cost_usd", "seconds"])
        for model in MODELS:
            for cond in CONDITIONS:
                for m in VARIANTS:
                    for k in range(SAMPLES):
                        gid = f"{model.replace('claude-', '')}__{cond}__{m}__s{k}"
                        if gid in done:
                            continue
                        p = prompt(m, cond)
                        open(os.path.join(GEN, gid + ".prompt.md"), "w").write(p)
                        t = time.time()
                        reply, cost = call_llm(model, p)
                        open(os.path.join(GEN, gid + ".reply.md"), "w").write(reply)
                        open(os.path.join(GEN, gid + ".scm"), "w").write(extract(reply))
                        w.writerow([gid, model, cond, m, k, round(cost, 4), round(time.time() - t, 1)])
                        fh.flush()
                        print(gid, round(cost, 3), flush=True)


# ---- stage: evaluate --------------------------------------------------------
HERALD = '(herald "ModelForge-style generated model" (bound 30) (algebra diffie-hellman))'


def assemble(body):
    return "\n\n".join([HERALD, body.strip(), goals("text")]) + "\n"


def repair(gid, model, body, err):
    """One self-repair round (ModelForge's post-processor role): feed CPSA's
    error back to the same model."""
    p = (open(os.path.join(GEN, gid + ".prompt.md")).read() +
         "\n\n# Your previous answer\n\n```scheme\n" + body + "\n```\n\n"
         "# CPSA rejected it with this error\n\n```\n" + err[:1500] + "\n```\n\n"
         "Fix the model so CPSA accepts it, keeping to the specification and the "
         "interface. Reply with the code block only.")
    reply, cost = call_llm(model, p)
    open(os.path.join(GEN, gid + ".repair.reply.md"), "w").write(reply)
    return extract(reply), cost


def evaluate(do_repair=True):
    os.makedirs(EVAL, exist_ok=True)
    gt = {r["variant"]: r for r in csv.DictReader(open(os.path.join(HERE, "ground_truth.csv")))}
    gen = list(csv.DictReader(open(os.path.join(GEN, "generation_log.csv"))))
    rows = []
    for g in gen:
        gid = g["id"]
        body = open(os.path.join(GEN, gid + ".scm")).read()
        attempts = [("initial", body)]
        rep_cost = 0.0
        for stage, b in attempts:
            scm = f"{gid}__{stage}.scm"
            open(os.path.join(EVAL, scm), "w").write(assemble(b))
            err, res, secs = analyse(scm, EVAL)
            v, ex = verdicts_of(res)
            accepted = len(res) == 6 or (len(res) > 0 and not err.startswith(scm))
            parse_error = (len(res) == 0)
            row = dict(id=gid, model=g["model"], condition=g["condition"], variant=g["variant"],
                       sample=g["sample"], stage=stage, accepted_by_cpsa=not parse_error,
                       cpsa_error=err.replace("\n", " ")[:200], seconds=secs)
            truth_v = [gt[g["variant"]][name] for name, _ in GOALS]
            for (name, _), tv, i in zip(GOALS, truth_v, range(4)):
                row[name] = v[i] if i < len(v) else "-"
            row["client_executable"] = ex[0] if ex else False
            row["server_executable"] = ex[1] if len(ex) > 1 else False
            decided = [i for i in range(len(v)) if v[i] in ("HOLDS", "VIOLATED")]
            row["goals_matching_truth"] = sum(1 for i in range(len(v)) if v[i] == truth_v[i])
            row["exact_match"] = (not parse_error and row["goals_matching_truth"] == 4
                                  and row["client_executable"] and row["server_executable"])
            row["decided_goals"] = len(decided)
            rows.append(row)
            if parse_error and stage == "initial" and do_repair:
                fixed_path = os.path.join(GEN, gid + ".repair.scm")
                if not os.path.exists(fixed_path):
                    fixed, rep_cost = repair(gid, g["model"], b, err)
                    open(fixed_path, "w").write(fixed)
                    with open(os.path.join(GEN, "repair_log.csv"), "a") as fh:
                        fh.write(f"{gid},{round(rep_cost, 4)}\n")
                attempts.append(("repaired", open(fixed_path).read()))
        print(gid, [r["stage"] + ":" + str(r["goals_matching_truth"]) + ("*" if r["exact_match"] else "")
                    for r in rows if r["id"] == gid], flush=True)
    with open(os.path.join(HERE, "results.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


# ---- stage: report ----------------------------------------------------------
def report():
    rows = list(csv.DictReader(open(os.path.join(HERE, "results.csv"))))
    final = {}
    for r in rows:  # last stage per id = the result after optional repair
        final[r["id"]] = r
    initial = {r["id"]: r for r in rows if r["stage"] == "initial"}

    def pct(n, d):
        return f"{n}/{d} ({100 * n // d if d else 0}%)"

    print("| model | condition | accepted (first try) | accepted (after repair) | executable | "
          "goals matching truth | exact match |")
    print("|---|---|---|---|---|---|---|")
    for model in MODELS:
        for cond in CONDITIONS:
            ids = [i for i, r in final.items() if r["model"] == model and r["condition"] == cond]
            n = len(ids)
            a0 = sum(initial[i]["accepted_by_cpsa"] == "True" for i in ids)
            a1 = sum(final[i]["accepted_by_cpsa"] == "True" for i in ids)
            ex = sum(final[i]["client_executable"] == "True" and final[i]["server_executable"] == "True"
                     for i in ids)
            gm = sum(int(final[i]["goals_matching_truth"]) for i in ids)
            em = sum(final[i]["exact_match"] == "True" for i in ids)
            print(f"| {model.replace('claude-', '')} | {cond} | {pct(a0, n)} | {pct(a1, n)} | "
                  f"{pct(ex, n)} | {pct(gm, 4 * n)} | {pct(em, n)} |")
    print()
    print("| variant | exact matches (all models and conditions) |")
    print("|---|---|")
    for m in VARIANTS:
        ids = [i for i, r in final.items() if r["variant"] == m]
        print(f"| {m} | {pct(sum(final[i]['exact_match'] == 'True' for i in ids), len(ids))} |")
    cost = sum(float(r["cost_usd"]) for r in csv.DictReader(open(os.path.join(GEN, "generation_log.csv"))))
    rp = os.path.join(GEN, "repair_log.csv")
    if os.path.exists(rp):
        cost += sum(float(l.split(",")[1]) for l in open(rp) if l.strip())
    print(f"\nTotal LLM cost: ${cost:.2f}")


if __name__ == "__main__":
    {"truth": truth, "generate": generate, "evaluate": evaluate, "report": report}[sys.argv[1]]()
