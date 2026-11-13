#!/usr/bin/env python
"""Summarize state machine inference results into CSV tables.

Run through ../../summarize-results.sh (inside the tls-test-bed/automaton2dot
image, which provides pylstar-tls v0.5's analysis code).

Usage: summarize.py <directory> [--no-bdist]

Every folder below <directory> that looks like an inference result (it has
N.stats, final.automaton or run.tsv) is one run. Writes <directory>/analysis/:

  runs.csv          one row per run: identity, status, states, rounds, model
                    hash, BDist, timings (learning vs equivalence check), costs,
                    automaton2dot's "working" flag and security results
  compare.csv       L* (pylstar-tls) vs L# (pylstar-tls-lsharp) pairs
  timing.csv        per inferer: count, mean, median, p10, p90 (as in the paper)
  classes-*.csv     runs grouped by identical state machine, per kind/scenario
  distinguishers-*.txt  input sequences separating the classes (fingerprints)
  findings.csv      runs with security results or a non-working handshake
  failed.tsv        failed / timed out runs, ready for run-experiments.sh,
                    with --timeout 3 added
"""

import csv
import glob
import os
import re
import statistics
import sys
import time

V05_SRC = os.environ.get("PYLSTAR_TLS_V05_SRC", "/opt/pylstar-tls-v0.5/src")
sys.path.insert(0, V05_SRC)

# pylint: disable=wrong-import-position
from automata.automata import fingerprint_automata, load_automaton_from_file
import automaton2dot

LSTAR = "pylstar-tls"
LSHARP = "pylstar-tls-lsharp"
INFERERS = (LSTAR, LSHARP)

TIME_RE = re.compile(r"time spent so far:\s*([0-9.]+)")
COUNTER_RE = re.compile(r"(n_states|n_queries|n_submitted_queries|n_letters|n_submitted_letters)[=:]\s*([0-9]+)")
LSHARP_RE = re.compile(
    r"L# learning rounds: (\d+), learning time: ([0-9.]+)s, equivalence query time: ([0-9.]+)s"
)
RUNNER_NAME_RE = re.compile(
    r"^(?P<kind>server|srv-auth|client)--(?P<stack>[^-].*?)--(?P<scenario>[^-]+(?:-[^-]+)*?)"
    r"--v(?P<tls_version>[0-9.]+)(?:--(?P<extra>.+?))?--(?P<inferer>pylstar-tls(?:-lsharp)?)--r(?P<repeat>\d+)$"
)
INFER_SH_NAME_RE = re.compile(
    r"^(?P<kind>server|srv-auth|client)--(?P<stack>.+?)--(?P<scenario>[a-z0-9-]+?)"
    r"(?:--(?P<inferer>pylstar-tls(?:-lsharp)?))?--(?P<stamp>\d{8}-\d{6}-\w+)$"
)


# ---------------------------------------------------------------------------
# Reading one run folder
# ---------------------------------------------------------------------------


def read_stats(filename):
    """time spent so far + counters from a *.stats / *.counterexample file."""
    result = {}
    with open(filename, encoding="utf-8", errors="replace") as fd:
        content = fd.read()
    match = TIME_RE.search(content)
    if match:
        result["time"] = float(match.group(1))
    for name, value in COUNTER_RE.findall(content):
        result[name] = int(value)
    return result


def read_run_tsv(folder):
    meta = {}
    path = os.path.join(folder, "run.tsv")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fd:
            for line in fd:
                key, _, value = line.rstrip("\n").partition("\t")
                meta[key] = value
    return meta


def identify(folder, meta):
    """kind, stack, scenario, inferer... from run.tsv, else from the folder name."""
    name = os.path.basename(folder)
    info = {"name": name, "kind": "", "stack": "", "scenario": "", "tls_version": "",
            "extra_args": "", "inferer": "", "repeat": "1", "pair_key": name}
    if meta.get("kind"):
        info.update(
            kind=meta["kind"],
            stack=meta.get("image", "").replace("tls-test-bed/", "").replace(":", "_"),
            scenario=meta.get("scenario", ""),
            tls_version=meta.get("tls_version", ""),
            extra_args=meta.get("extra_args", ""),
            inferer=meta.get("inferer", ""),
            repeat=meta.get("repeat", "1"),
        )
    elif RUNNER_NAME_RE.match(name):
        info.update({k: v or "" for k, v in RUNNER_NAME_RE.match(name).groupdict().items()})
    elif INFER_SH_NAME_RE.match(name):
        groups = INFER_SH_NAME_RE.match(name).groupdict()
        info.update(kind=groups["kind"], stack=groups["stack"], scenario=groups["scenario"],
                    inferer=groups["inferer"] or LSTAR)
    else:
        # Free-form names such as "server-openssl-3.0.2-tls13--pylstar-tls-lsharp"
        base, _, last = name.rpartition("--")
        if last in INFERERS:
            info["inferer"] = last
            name = base
        info["kind"] = next((k for k in ("srv-auth", "server", "client") if name.startswith(k)), "")
        match = re.search(r"(tls1[0-3]|bb-oracle|freak)", name)
        info["scenario"] = match.group(1) if match else ""
        info["stack"] = name
    info["pair_key"] = "|".join(
        [info["kind"], info["stack"], info["scenario"], info["tls_version"], info["extra_args"], info["repeat"]]
    )
    return info


def automaton2dot_key(kind, scenario):
    """Scenario name used by pylstar-tls's automaton2dot.py tables."""
    if kind == "client":
        return f"client.{scenario}"
    if kind == "srv-auth" and scenario in ("tls10", "tls11", "tls12", "tls13"):
        return f"server.{scenario}-auth"
    return f"server.{scenario}"


def analyse_automaton(filename, key, with_bdist):
    """States, hash, BDist, working flag and security results of an automaton."""
    automaton = load_automaton_from_file(filename)
    result = {
        "states": len(automaton.states),
        "model_hash": automaton.compute_hash().hex(),
        "bdist": "",
        "working": "",
        "security_results": "",
    }
    if with_bdist:
        try:
            result["bdist"] = automaton.compute_bdist()[0]
        except Exception as exc:  # pylint: disable=broad-except
            result["bdist"] = f"error: {exc}"
    # automaton2dot's checks work on the abbreviated message names
    renamed = automaton
    try:
        if key in automaton2dot.mappings:
            renamed = automaton.rename_input_vocabulary(automaton2dot.mappings[key][0])
            renamed = renamed.rename_output_vocabulary(automaton2dot.mappings[key][1])
        if key in automaton2dot.working_tests:
            result["working"] = bool(automaton2dot.working_tests[key](renamed))
        if key in automaton2dot.security_tests and key in automaton2dot.mappings:
            findings = [test(renamed) for test in automaton2dot.security_tests[key]]
            result["security_results"] = "; ".join(f for f in findings if f)
    except Exception as exc:  # pylint: disable=broad-except
        result["security_results"] = f"analysis error: {exc}"
    return result, automaton


def timing_split(folder):
    """Learning time vs equivalence-check time, from the hypothesis files.

    N.stats is written when hypothesis N is submitted to the equivalence check,
    N.counterexample when the check refutes it, final.stats when it accepts it.
    """
    rounds = sorted(
        int(os.path.basename(f).split(".")[0])
        for f in glob.glob(os.path.join(folder, "*.stats"))
        if os.path.basename(f).split(".")[0].isdigit()
    )
    final = os.path.join(folder, "final.stats")
    total = read_stats(final).get("time") if os.path.exists(final) else None
    eq_time = 0.0
    last_time = None
    for n in rounds:
        submitted = read_stats(os.path.join(folder, f"{n}.stats")).get("time")
        if submitted is None:
            continue
        last_time = submitted
        refuted = os.path.join(folder, f"{n}.counterexample")
        if os.path.exists(refuted):
            end = read_stats(refuted).get("time")
        elif n == rounds[-1] and total is not None:
            end = total
        else:
            end = None
        if end is not None:
            eq_time += end - submitted
            last_time = end
    learn_time = (total - eq_time) if total is not None else None
    return {
        "rounds": len(rounds),
        "total_time_s": total,
        "learning_time_s": learn_time,
        "equivalence_time_s": eq_time if rounds else None,
        "last_progress_s": last_time,
    }


def console_text(folder):
    texts = []
    for candidate in (os.path.join(folder, "console.log"), folder.rstrip("/") + ".log"):
        if os.path.exists(candidate):
            with open(candidate, encoding="utf-8", errors="replace") as fd:
                texts.append(fd.read())
    return "\n".join(texts)


def read_run(folder, with_bdist):
    meta = read_run_tsv(folder)
    info = identify(folder, meta)
    row = dict(info)
    row.update(
        campaign=meta.get("campaign", ""),
        eq_method=meta.get("eq_method", ""),
        status=meta.get("status", ""),
        exit_code=meta.get("exit_code", ""),
        wall_s=meta.get("wall_seconds", ""),
        jobs=meta.get("jobs", ""),
        loadavg_start=meta.get("loadavg_start", ""),
        start_epoch=meta.get("start_epoch", ""),
    )
    row.update(timing_split(folder))

    final = os.path.join(folder, "final.stats")
    counters = read_stats(final) if os.path.exists(final) else {}
    if not counters:  # unfinished: use the latest hypothesis
        latest = sorted(glob.glob(os.path.join(folder, "[0-9]*.stats")), key=os.path.getmtime)
        counters = read_stats(latest[-1]) if latest else {}
    for name in ("n_queries", "n_submitted_queries", "n_letters", "n_submitted_letters"):
        row[name] = counters.get(name, "")

    match = LSHARP_RE.search(console_text(folder))
    row["lsharp_rounds"], row["lsharp_learning_s"], row["lsharp_equivalence_s"] = (
        match.groups() if match else ("", "", "")
    )

    automaton_file = os.path.join(folder, "final.automaton")
    automaton = None
    if os.path.exists(automaton_file):
        analysis, automaton = analyse_automaton(
            automaton_file, automaton2dot_key(row["kind"], row["scenario"]), with_bdist
        )
        row.update(analysis)
        row["converged"] = True
        row["status"] = row["status"] or "ok"
    else:
        row.update(states="", model_hash="", bdist="", working="", security_results="", converged=False)
        if not row["status"]:
            row["status"] = "unfinished"
        if row["status"] == "unfinished" and row["start_epoch"]:
            row["elapsed_s"] = round(time.time() - float(row["start_epoch"]))
    row.setdefault("elapsed_s", "")
    return row, automaton, meta


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------

RUN_COLUMNS = [
    "name", "campaign", "kind", "stack", "tls_version", "scenario", "extra_args", "eq_method", "inferer",
    "repeat", "status", "exit_code", "converged", "states", "rounds", "model_hash", "bdist",
    "total_time_s", "learning_time_s", "equivalence_time_s", "wall_s", "elapsed_s",
    "n_queries", "n_submitted_queries", "n_letters", "n_submitted_letters",
    "lsharp_rounds", "lsharp_learning_s", "lsharp_equivalence_s",
    "working", "security_results", "jobs", "loadavg_start",
]


def write_csv(path, rows, columns):
    with open(path, "w", newline="", encoding="utf-8") as fd:
        writer = csv.DictWriter(fd, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: ("" if row.get(k) is None else row.get(k)) for k in columns})


def number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def ratio(a, b):
    a, b = number(a), number(b)
    return round(b / a, 3) if a and b is not None else ""


def compare_table(rows):
    pairs = {}
    for row in rows:
        if row["inferer"] in INFERERS:
            pairs.setdefault(row["pair_key"], {})[row["inferer"]] = row
    table = []
    for key, pair in sorted(pairs.items()):
        if LSTAR not in pair or LSHARP not in pair:
            continue
        lstar, lsharp = pair[LSTAR], pair[LSHARP]
        entry = {
            "kind": lstar["kind"], "stack": lstar["stack"], "tls_version": lstar["tls_version"],
            "scenario": lstar["scenario"], "extra_args": lstar["extra_args"], "repeat": lstar["repeat"],
            "lstar_status": lstar["status"], "lsharp_status": lsharp["status"],
            "same_model": (lstar["model_hash"] == lsharp["model_hash"]) if lstar["model_hash"] and lsharp["model_hash"] else "",
            "lstar_states": lstar["states"], "lsharp_states": lsharp["states"],
        }
        for metric in ("n_submitted_queries", "n_submitted_letters", "learning_time_s",
                       "equivalence_time_s", "total_time_s", "wall_s"):
            entry[f"lstar_{metric}"] = lstar.get(metric, "")
            entry[f"lsharp_{metric}"] = lsharp.get(metric, "")
            entry[f"ratio_{metric}"] = ratio(lstar.get(metric), lsharp.get(metric))
        table.append(entry)
    return table


COMPARE_COLUMNS = (
    ["kind", "stack", "tls_version", "scenario", "extra_args", "repeat", "lstar_status", "lsharp_status",
     "same_model", "lstar_states", "lsharp_states"]
    + [f"{p}_{m}" for m in ("n_submitted_queries", "n_submitted_letters", "learning_time_s",
                            "equivalence_time_s", "total_time_s", "wall_s")
       for p in ("lstar", "lsharp", "ratio")]
)


def percentile(values, p):
    values = sorted(values)
    if not values:
        return ""
    k = (len(values) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(values) - 1)
    return round(values[lo] + (values[hi] - values[lo]) * (k - lo), 1)


def timing_table(rows):
    table = []
    for inferer in sorted({r["inferer"] for r in rows if r["inferer"]}):
        for metric in ("total_time_s", "learning_time_s", "equivalence_time_s", "wall_s",
                       "n_submitted_queries", "n_submitted_letters"):
            values = [number(r[metric]) for r in rows
                      if r["inferer"] == inferer and r["converged"] and number(r.get(metric)) is not None]
            table.append({
                "inferer": inferer, "metric": metric, "count": len(values),
                "mean": round(statistics.mean(values), 1) if values else "",
                "median": round(statistics.median(values), 1) if values else "",
                "p10": percentile(values, 0.10), "p90": percentile(values, 0.90),
                "total": round(sum(values), 1) if values else "",
            })
    return table


def classes(rows, automata, out_dir):
    """Group converged runs by identical state machine, per kind and scenario."""
    groups = {}
    for row in rows:
        if row["converged"]:
            groups.setdefault((row["kind"], row["tls_version"], row["scenario"]), []).append(row)
    summary = []
    for (kind, version, scenario), members in sorted(groups.items()):
        label = "-".join(x for x in (kind, f"v{version}" if version else "", scenario) if x)
        by_hash = {}
        for row in members:
            by_hash.setdefault(row["model_hash"], []).append(row)
        class_rows = []
        for index, (model_hash, rows_in_class) in enumerate(
            sorted(by_hash.items(), key=lambda item: sorted(r["stack"] for r in item[1])[0]), 1
        ):
            stacks = sorted({r["stack"] for r in rows_in_class})
            class_rows.append({
                "class": index, "states": rows_in_class[0]["states"], "model_hash": model_hash,
                "n_stacks": len(stacks), "stacks": " ".join(stacks),
                "inferers": " ".join(sorted({r["inferer"] for r in rows_in_class})),
                "security_results": rows_in_class[0]["security_results"],
            })
        write_csv(os.path.join(out_dir, f"classes-{label}.csv"), class_rows,
                  ["class", "states", "model_hash", "n_stacks", "stacks", "inferers", "security_results"])

        # Fingerprints: sequences separating one representative of each class
        representatives = [automata[rows_in_class[0]["name"]] for rows_in_class in
                           (by_hash[r["model_hash"]] for r in class_rows)]
        text = f"{len(class_rows)} classes\n"
        if len(representatives) >= 2:
            try:
                fingerprints = fingerprint_automata(representatives)
                text += f"{len(fingerprints)} distinguishing sequences:\n"
                text += "".join(f"  {', '.join(sequence)}\n" for sequence, _ in fingerprints)
            except Exception as exc:  # pylint: disable=broad-except
                text += f"fingerprinting failed: {exc!r}\n"
        with open(os.path.join(out_dir, f"distinguishers-{label}.txt"), "w", encoding="utf-8") as fd:
            fd.write(text)
        summary.append(f"  {label}: {len(members)} runs, {len(class_rows)} classes")
    return summary


def failed_rows(rows, metas):
    lines = []
    for row in rows:
        meta = metas[row["name"]]
        if row["status"] in ("failed", "timeout", "build-failed") and meta.get("kind"):
            extra = meta.get("extra_args", "")
            if "--timeout" not in extra:
                extra = (extra + " --timeout 3").strip()
            image = meta.get("image", "").replace("tls-test-bed/", "")
            lines.append(f"{meta['kind']}\t{image}\t{meta.get('tls_version', '')}\t{meta.get('scenario', '')}\t{extra}"
                         f"\t# {row['status']}: {row['name']}")
    return lines


# ---------------------------------------------------------------------------


def find_runs(root):
    runs = []
    for folder, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ("analysis", ".runner")]
        if "run.tsv" in files or "final.automaton" in files or any(f.endswith(".stats") for f in files):
            runs.append(folder)
            dirs[:] = []
    return sorted(runs)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 1:
        sys.exit("usage: summarize.py <directory> [--no-bdist]")
    root = args[0]
    with_bdist = "--no-bdist" not in sys.argv
    out_dir = os.path.join(root, "analysis")
    os.makedirs(out_dir, exist_ok=True)

    rows, automata, metas = [], {}, {}
    for folder in find_runs(root):
        try:
            row, automaton, meta = read_run(folder, with_bdist)
        except Exception as exc:  # pylint: disable=broad-except
            print(f"warning: cannot read {folder}: {exc!r}", file=sys.stderr)
            continue
        # unique names when folders from several sub-directories share a name
        relative = os.path.relpath(folder, root)
        row["name"] = relative
        rows.append(row)
        metas[relative] = meta
        if automaton is not None:
            automata[relative] = automaton

    write_csv(os.path.join(out_dir, "runs.csv"), rows, RUN_COLUMNS)
    comparisons = compare_table(rows)
    write_csv(os.path.join(out_dir, "compare.csv"), comparisons, COMPARE_COLUMNS)
    write_csv(os.path.join(out_dir, "timing.csv"), timing_table(rows),
              ["inferer", "metric", "count", "mean", "median", "p10", "p90", "total"])
    class_summary = classes(rows, automata, out_dir)
    findings = [r for r in rows if r["security_results"] or r["working"] is False]
    write_csv(os.path.join(out_dir, "findings.csv"), findings,
              ["name", "kind", "stack", "tls_version", "scenario", "inferer", "states", "working", "security_results"])
    failed = failed_rows(rows, metas)
    with open(os.path.join(out_dir, "failed.tsv"), "w", encoding="utf-8") as fd:
        fd.write("# Failed or timed-out runs, with --timeout 3 added. Rerun with:\n")
        fd.write("#   ./run-experiments.sh --campaign <name>-retry analysis/failed.tsv\n")
        fd.write("".join(line + "\n" for line in failed))

    statuses = {}
    for row in rows:
        statuses[row["status"]] = statuses.get(row["status"], 0) + 1
    print(f"{len(rows)} runs: " + ", ".join(f"{n} {s}" for s, n in sorted(statuses.items())))
    same = sum(1 for c in comparisons if c["same_model"] is True)
    print(f"{len(comparisons)} L*/L# pairs, {same} with identical state machines")
    print("Classes (identical state machines):")
    print("\n".join(class_summary) if class_summary else "  none")
    print(f"{len(findings)} runs with findings, {len(failed)} failed or timed out")
    print(f"Tables written to {out_dir}/")


if __name__ == "__main__":
    main()
