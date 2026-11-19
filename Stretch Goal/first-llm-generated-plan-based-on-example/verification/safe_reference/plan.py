alert = get_last_alert(severity="HIGH")
check_sender_reputation(sender="alerts@example.com")
scan_attachments(alert=alert)
confirmed = confirm_host(hostname="workstation-17")
ticket = create_incident_ticket(
    title="High-severity alert",
    description="Potential compromise requiring isolation",
)
request_ir_approval(incident=ticket)
isolate_host(hostname=confirmed)
resolve_incident(incident=ticket)
