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

export interface DetectionRule {
  id: string;
  rule_id: string;
  name: string;
  enabled: boolean;
  severity: Severity;
  mitre_techniques: string[] | null;
  match_type: "ioc" | "behavioral" | "heuristic" | "sequence" | "threshold";
}

export interface ThreatFeed {
  id: string;
  name: string;
  source: string;
  ioc_count: number;
  last_ingested_at: string | null;
  next_scheduled_at: string | null;
  status: "healthy" | "degraded" | "error" | "pending";
  error_message: string | null;
}

// Rules
export type RuleMatchType = "ioc" | "behavioral" | "heuristic" | "sequence" | "threshold";

export interface RuleFile {
  id: string;
  rule_id: string;
  name: string;
  pack: string;
  match_type: RuleMatchType;
  severity: Severity;
  enabled: boolean;
  last_modified: string;
  valid: boolean;
  validation_errors: string[] | null;
  content_toml?: string;
}

export interface CreateRuleRequest {
  content_toml: string;
  pack?: string;
}

export interface RuleValidationResult {
  valid: boolean;
  errors: string[];
}

export interface RuleTestResult {
  matched: boolean;
  match_count: number;
  matched_events: unknown[];
  errors: string[];
}

// Reports
export type ReportType = "incident_summary" | "executive_summary";
export type ReportStatus = "pending" | "generating" | "complete" | "failed";

export interface Report {
  id: string;
  type: ReportType;
  period_days: number;
  status: ReportStatus;
  created_at: string;
  completed_at: string | null;
  error_message: string | null;
}

// SIEM Connectors
export type SiemConnectorType = "splunk" | "elasticsearch" | "sentinel";

export interface SiemConnector {
  id: string;
  name: string;
  type: SiemConnectorType;
  enabled: boolean;
  ssl_verify: boolean;
  last_test_at: string | null;
  last_test_ok: boolean | null;
  last_test_error: string | null;
  config: Record<string, string>;
}

export interface CreateSiemConnectorRequest {
  name: string;
  type: SiemConnectorType;
  ssl_verify: boolean;
  config: Record<string, string>;
}
