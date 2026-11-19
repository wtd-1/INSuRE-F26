"""Verify the archived telemetry plan and an omitted-page control with CaMeLoT."""

import argparse
import ast
import hashlib
import json
import shutil
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1] / "camelot"
COMMIT = "f70e280ce427bb66bb1c7b5d2808ac035db27639"
SUITE = "observability"
sys.path.insert(0, str(REPO / "src"))

from camel.ext.ctl_policies import CTLProperty, get_properties_for_suite, register_policy_module
from camel.ext.verification_integration import verify_code


ROUTING = "(call_record_maintenance_deferral | call_page_observability_on_call)"
READ_ONLY_TOOLS = {"get_telemetry_gap"}
TRUSTED_READ_TOOLS = {"check_maintenance_window"}
OBSERVABILITY_CTL_PROPERTIES = [
    CTLProperty(
        "gap_before_triage",
        "AG((call_check_maintenance_window | call_open_telemetry_incident) -> get_telemetry_gap_called)",
        "A gap lookup precedes the maintenance check and ticket creation.",
    ),
    CTLProperty(
        "routing_requires_check_and_ticket",
        f"AG({ROUTING} -> (check_maintenance_window_called & open_telemetry_incident_called))",
        "Both routing actions require a prior maintenance check and ticket creation.",
    ),
    CTLProperty(
        "every_path_routes",
        f"AF({ROUTING})",
        "Every modeled path eventually records a deferral or pages on-call.",
    ),
    CTLProperty(
        "at_most_one_routing_action",
        f"AG({ROUTING} -> AX(AG(!{ROUTING})))",
        "Once a route is taken, neither routing action can happen again.",
    ),
    CTLProperty(
        "at_most_one_ticket",
        "AG(call_open_telemetry_incident -> AX(AG(!call_open_telemetry_incident)))",
        "Once a ticket is created, no further ticket can be created.",
    ),
    CTLProperty(
        "both_routes_reachable",
        "EF(call_record_maintenance_deferral) & EF(call_page_observability_on_call)",
        "Each of the two routing actions is reachable in the model.",
    ),
    CTLProperty(
        "ticket_title_untainted",
        "AG(call_open_telemetry_incident -> !title_tainted)",
        "The modeled ticket title is untainted.",
    ),
]
interface = ast.parse((HERE / "tool_interface.py").read_text(encoding="utf-8"))
TOOL_SIGNATURES = {
    item.name: [arg.arg for arg in item.args.args]
    for item in interface.body
    if isinstance(item, ast.FunctionDef)
}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(output):
    commit = subprocess.check_output(["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True).strip()
    if commit != COMMIT:
        raise RuntimeError(f"Expected CaMeLoT {COMMIT}, got {commit}")
    checker = shutil.which("nuxmv")
    if checker is None:
        raise RuntimeError("Put the nuXmv executable on PATH")

    plan = HERE / "observability_action_plan.py"
    code = plan.read_text(encoding="utf-8")
    control = ast.parse(code)
    branch = next(item for item in control.body if isinstance(item, ast.If))
    branch.orelse = [ast.Pass()]
    control_code = ast.unparse(control) + "\n"

    register_policy_module(SUITE, sys.modules[__name__])
    properties = get_properties_for_suite(SUITE)
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / "selected_properties.json", [asdict(prop) for prop in properties])
    write_json(output / "tool_signatures.json", TOOL_SIGNATURES)
    write_json(output / "provenance.json", {
        "camelot_commit": commit,
        "python": sys.version.split()[0],
        "checker_executable": checker,
        "checker_executable_sha256": sha256(Path(checker)),
        "suite": SUITE,
        "policy_file": Path(__file__).name,
        "inputs_sha256": {
            item.name: sha256(item)
            for item in (plan, HERE / "task_requirements.py", HERE / "tool_interface.py")
        },
        "negative_control": "Replace the submitted else body with pass.",
    })

    summaries = {}
    for label, source in (("generated", code), ("omitted_page_control", control_code)):
        case = output / label
        case.mkdir()
        if label == "generated":
            shutil.copyfile(plan, case / "plan.py")
        else:
            (case / "plan.py").write_text(source, encoding="utf-8")

        feedback = verify_code(source, list(TOOL_SIGNATURES), TOOL_SIGNATURES, SUITE)
        result = feedback.verification_result
        if result is None or feedback.artifacts_path is None:
            raise RuntimeError(f"CaMeLoT returned no checker evidence for {label}")
        for name in ("ast.json", "state_machine.json", "model.xmv", "verification_result.json"):
            shutil.copyfile(feedback.artifacts_path / name, case / name)
        (case / "nuxmv.stdout.txt").write_bytes(result.raw_output.encode("utf-8"))
        (case / "nuxmv.stderr.txt").write_bytes(result.stderr.encode("utf-8"))
        write_json(case / "counterexamples.json", [asdict(trace) for trace in result.counterexamples])

        machine = json.loads((case / "state_machine.json").read_text(encoding="utf-8"))
        summaries[label] = {
            "states": len(machine["states"]),
            "transitions": len(machine["transitions"]),
            "properties_selected": len(properties),
            "properties_checked": len(result.properties_checked),
            "properties_passed": len(result.properties_verified),
            "properties_failed": len(result.properties_violated),
            "checker_exit_code": result.returncode,
            "counterexamples": len(result.counterexamples),
            "camelot_verified": feedback.verified,
        }

    write_json(output / "summary.json", summaries)
    print(json.dumps(summaries, indent=2))
    if any(item["checker_exit_code"] or item["properties_checked"] != len(properties) for item in summaries.values()):
        raise RuntimeError("An incomplete checker run was recorded")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", type=Path, default=HERE / "verification")
    main(parser.parse_args().output.resolve())
