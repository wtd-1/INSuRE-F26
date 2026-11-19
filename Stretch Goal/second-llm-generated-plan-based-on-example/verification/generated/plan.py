logs = query_logs(host="netflow-lab")
analysis = query_ai_assistant(query=str(logs))
incident = create_incident_ticket(title="Suspicious network activity on netflow-lab", description="Investigated suspicious network activity in laboratory netflow logs from netflow-lab and preparing to block operator-supplied IP 192.0.2.44.")
block_ip(ip="192.0.2.44")
