"""Tool signatures for the observability-lab exercise, listed alphabetically.

These declarations describe inputs and outputs. Their bodies are placeholders.
Gap and incident references are opaque values that the plan passes unchanged.
"""


def check_maintenance_window(gap: object) -> bool:
    """Return True when approved maintenance covers the reported gap.

    Return False when the registry cannot confirm coverage for that collector
    and time period.
    """
    raise NotImplementedError("Interface only; requires an actual tool backend")


def get_telemetry_gap(collector: str) -> object:
    """Retrieve the reported telemetry gap for the named lab collector."""
    raise NotImplementedError("Interface only; requires an actual tool backend")


def open_telemetry_incident(title: str, gap: object) -> object:
    """Create a ticket linked to the given gap and return its incident reference."""
    raise NotImplementedError("Interface only; requires an actual tool backend")


def page_observability_on_call(incident: object) -> None:
    """Page the lab's observability on-call team with the incident reference."""
    raise NotImplementedError("Interface only; requires an actual tool backend")


def record_maintenance_deferral(incident: object) -> None:
    """Record a maintenance deferral on the given incident ticket."""
    raise NotImplementedError("Interface only; requires an actual tool backend")
