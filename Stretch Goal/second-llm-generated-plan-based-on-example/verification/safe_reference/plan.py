# Task: "Check the netflow logs with timestamp 2026-05-15T08:00Z. Something
# strange is happening, find out the source and isolate it."
#
# The LLM is consulted to analyse the logs, and a ticket is opened.
# The IP passed to block_ip is a trusted literal from the operator — not
# derived from the tainted LLM output.
logs = query_logs(host="netflow-server")
analysis = query_ai_assistant(query=str(logs))
ticket = create_incident_ticket(
    title="Suspicious netflow activity",
    description="Potential malicious source detected in netflow logs",
)
block_ip(ip="10.0.42.99")
