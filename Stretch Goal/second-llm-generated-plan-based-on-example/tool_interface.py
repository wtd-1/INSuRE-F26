"""Tool signatures for the SOC planning exercise, listed alphabetically.

These declarations describe inputs and outputs. Their bodies are placeholders.
The proposed plan can call the tool names directly.
"""


def block_ip(ip: str) -> None:
    """Block traffic from the supplied IP address."""
    raise NotImplementedError("Interface only; requires an actual tool backend")


def create_incident_ticket(title: str, description: str) -> object:
    """Create an incident record and return its ticket reference."""
    raise NotImplementedError("Interface only; requires an actual tool backend")


def query_ai_assistant(query: str, output_schema: object = None) -> object:
    """Analyze the supplied text and return a result that may be untrusted."""
    raise NotImplementedError("Interface only; requires an actual tool backend")


def query_logs(host: str) -> object:
    """Retrieve logs for a named host. The contents may be attacker-controlled."""
    raise NotImplementedError("Interface only; requires an actual tool backend")
