"""Run one variant under both parameter sets and record per-goal results.

Usage: python3 run_variant.py <id> [<id> ...]

Refuses to run unless <id>/predictions.csv exists with a prediction for all
16 goals. Before cpsa4 starts, the prediction file's SHA-256 and modification
time are written to <id>/run.log, so a later edit to the prediction is
detectable. Both parameter sets are always run:

  tight    cpsa4 -b 12 -l 500
  default  cpsa4            (strand bound 12, step limit 2000)

Outputs per parameter set P: output_P.txt, shapes_P.txt, shapes_P.xhtml,
goals_P.csv; plus timings.txt and run.log.
"""
import csv, datetime, hashlib, os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
MUT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from cpsa_parse import GOALS, parse  # noqa: E402

BIN = os.path.expanduser("~/.local/bin")
PARAMS = {"tight": ["-b", "12", "-l", "500"], "default": []}
MACROS, SCM = "TLS1.3_macros.lisp", "tls13_baseline.scm"


def sha256(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def run(vid):
    d = os.path.join(MUT, vid)
    pred = os.path.join(d, "predictions.csv")
    rows = list(csv.DictReader(open(pred)))
    assert [r["goal"] for r in rows] == [g[0] for g in GOALS], f"{vid}: predictions.csv must list all 16 goals in order"
    assert all(r["predicted"] in ("HOLDS", "VIOLATED") for r in rows), f"{vid}: predicted must be HOLDS or VIOLATED"
    log = open(os.path.join(d, "run.log"), "a")
    log.write(f"{now()} prediction {sha256(pred)} mtime "
              f"{datetime.datetime.fromtimestamp(os.path.getmtime(pred), datetime.timezone.utc).isoformat(timespec='seconds')}\n")
    log.write(f"{now()} inputs {MACROS} {sha256(os.path.join(d, MACROS))} {SCM} {sha256(os.path.join(d, SCM))}\n")
    timings = []
    for tag, flags in PARAMS.items():
        out = f"output_{tag}.txt"
        t0 = time.perf_counter()
        p = subprocess.run([os.path.join(BIN, "cpsa4"), *flags, "-o", out, SCM],
                           cwd=d, capture_output=True, text=True)
        secs = time.perf_counter() - t0
        log.write(f"{now()} cpsa4 {' '.join(flags) or '(defaults)'} exit={p.returncode} "
                  f"seconds={secs:.3f} stderr={p.stderr.strip()!r}\n")
        if os.path.exists(os.path.join(d, out)):
            subprocess.run([os.path.join(BIN, "cpsa4shapes"), "-o", f"shapes_{tag}.txt", out], cwd=d, check=True)
            subprocess.run([os.path.join(BIN, "cpsa4graph"), "-o", f"shapes_{tag}.xhtml", f"shapes_{tag}.txt"], cwd=d, check=True)
            version, recs = parse(os.path.join(d, out))
        else:
            # cpsa4 rejected the input before analysing anything.
            v = subprocess.run([os.path.join(BIN, "cpsa4"), "--version"], capture_output=True, text=True)
            version = v.stdout.split()[-1] if v.stdout.strip() else "?"
            recs = [dict(goal=g, proto=pr, name=nm, verdict="ERROR", search_complete=False,
                         skeletons=0, shapes=0, peer_strand_added=False)
                    for g, pr, _, nm in GOALS]
            open(os.path.join(d, f"cpsa_error_{tag}.txt"), "w").write(p.stderr)
        with open(os.path.join(d, f"goals_{tag}.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(recs[0].keys()))
            w.writeheader()
            w.writerows(recs)
        timings.append(f"{tag}\tflags={' '.join(flags) or '(defaults)'}\texit={p.returncode}\t"
                       f"seconds={secs:.3f}\tcpsa={version}")
        print(f"{vid} {tag}: exit={p.returncode} {secs:.2f}s " +
              " ".join(f"{r['goal']}={r['verdict'][0]}" for r in recs))
    open(os.path.join(d, "timings.txt"), "w").write("\n".join(timings) + "\n")
    log.close()


if __name__ == "__main__":
    for v in sys.argv[1:]:
        run(v)
