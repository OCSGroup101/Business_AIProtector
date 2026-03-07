# OpenClaw Integration SDK

Helpers for connecting OpenClaw to SIEMs, SOAR platforms, and ticketing systems.

## Planned Integrations (Phase 3)

- **Splunk HEC** — forward incidents as Splunk events
- **Elasticsearch** — index telemetry and incidents
- **Microsoft Sentinel** — CEF/Syslog and Sentinel workspace integration
- **MISP** — bi-directional IOC sharing
- **Webhook** — generic JSON webhook for custom integrations (available Phase 2)

## Webhook Schema

```json
{
  "event": "incident.created",
  "timestamp": "2026-03-04T10:00:00Z",
  "tenant_id": "ten_01JRXXXXXX",
  "incident": {
    "id": "inc_01JRXXXXXX",
    "severity": "HIGH",
    "rule_name": "Office Document Spawning Command Shell",
    "hostname": "WORKSTATION-042",
    "mitre_techniques": ["T1059.001"]
  }
}
```

## Development Status

Integration SDK is planned for Phase 3. Subscribe to [GitHub releases](https://github.com/omni-cyber-solutions/openclaw/releases) for updates.
