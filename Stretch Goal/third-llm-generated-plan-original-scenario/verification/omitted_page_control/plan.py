gap = get_telemetry_gap(collector='lab-collector-04')
maintenance_covered = check_maintenance_window(gap=gap)
incident = open_telemetry_incident(title='Telemetry gap on lab-collector-04', gap=gap)
if maintenance_covered:
    record_maintenance_deferral(incident=incident)
else:
    pass
