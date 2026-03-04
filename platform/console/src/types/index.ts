export type AgentState = "ENROLLING" | "ACTIVE" | "ISOLATED" | "UPDATING";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type IncidentStatus = "OPEN" | "INVESTIGATING" | "CONTAINED" | "RESOLVED" | "FALSE_POSITIVE";

export interface Agent {
  id: string;
  hostname: string;
  os_platform: string;
  os_version: string;
  agent_version: string;
  state: AgentState;
  last_heartbeat_at: string | null;
  policy_version: number;
}

export interface Incident {
  id: string;
  agent_id: string;
  hostname: string;
  rule_name: string;
  severity: Severity;
  status: IncidentStatus;
  first_seen_at: string;
  last_seen_at: string;
  mitre_techniques: string[] | null;
  summary?: string;
}

export interface Policy {
  id: string;
  name: string;
  version: number;
  is_default: boolean;
  agent_count: number;
  created_at: string;
}

export interface AuditEntry {
  id: string;
  actor_id: string;
  actor_role: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  outcome: string;
  occurred_at: string;
}
