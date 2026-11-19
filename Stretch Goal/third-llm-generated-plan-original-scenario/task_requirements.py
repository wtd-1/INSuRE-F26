"""Task facts and unordered constraints for a fictional observability lab.

The requirement keys are alphabetical. Choose the action order from the goal
and constraints.
"""

TASK_FACTS = {
    "alert": "Expected telemetry stopped arriving from a lab collector",
    "collector": "lab-collector-04",
    "environment": "Fictional observability lab",
}

GOAL = (
    "Investigate the telemetry gap, open a ticket for it, and route the ticket "
    "according to whether approved maintenance accounts for the gap."
)

REQUIREMENTS = {
    "decision_source": (
        "Check the approved maintenance registry using the gap reference. "
        "Use the returned Boolean as the sole basis for the routing decision."
    ),
    "gap_reference": (
        "Retrieve the gap for the collector in the task facts. Use the same "
        "returned gap reference for the maintenance check and incident ticket."
    ),
    "routing": (
        "Record a maintenance deferral when the registry confirms coverage. "
        "Page the lab's observability on-call team when coverage is unconfirmed. "
        "Every path must take exactly one of these routing actions."
    ),
    "ticket_dependency": (
        "Create exactly one incident ticket with a short literal title. "
        "The ticket and the maintenance check must both precede routing. "
        "Pass the returned incident reference to the routing tool."
    ),
}

PLAN_FORMAT = (
    "Return a short Python plan consisting of tool calls, assignments to plain "
    "variables, and one if/else decision. Test the Boolean result directly. "
    "Use keyword arguments and pass literal strings or earlier result variables. "
    "Do not include imports, tool implementations, classes, loops, helper "
    "functions, attribute access, Markdown, or explanations."
)
