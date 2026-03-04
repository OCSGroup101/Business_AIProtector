// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
// Typed API client for the OpenClaw platform API.

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "";

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    credentials: "include",
  });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`API ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

// ─── Types ───────────────────────────────────────────────────────────────────

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type IncidentStatus =
  | "OPEN"
  | "INVESTIGATING"
  | "CONTAINED"
  | "RESOLVED"
  | "FALSE_POSITIVE";

export interface IncidentSummary {
  id: string;
  agent_id: string;
  hostname: string;
  rule_name: string;
  severity: Severity;
  status: IncidentStatus;
  first_seen_at: string;
  last_seen_at: string;
  mitre_techniques: string[] | null;
}

export interface IncidentDetail extends IncidentSummary {
  summary: string | null;
  containment_status: string | null;
  containment_actions: string[] | null;
  events: Record<string, unknown>[];
}

export interface AgentSummary {
  id: string;
  hostname: string;
  os_platform: string;
  os_version: string;
  agent_version: string;
  state: string;           // ACTIVE | ENROLLING | ISOLATED | UPDATING
  last_heartbeat_at: string | null;
  policy_version: number;
}

export interface FeedStatus {
  name: string;
  interval: string;
  status: "active" | "pending" | "error";
}

// ─── Incidents ────────────────────────────────────────────────────────────────

export interface ListIncidentsParams {
  severity?: Severity;
  status?: IncidentStatus;
  agent_id?: string;
  limit?: number;
  offset?: number;
}

export async function listIncidents(
  params: ListIncidentsParams = {}
): Promise<IncidentSummary[]> {
  const qs = new URLSearchParams();
  if (params.severity) qs.set("severity", params.severity);
  if (params.status) qs.set("status", params.status);
  if (params.agent_id) qs.set("agent_id", params.agent_id);
  if (params.limit) qs.set("limit", String(params.limit));
  if (params.offset) qs.set("offset", String(params.offset));
  const query = qs.toString() ? `?${qs}` : "";
  return apiFetch<IncidentSummary[]>(`/api/v1/incidents${query}`);
}

export async function getIncident(id: string): Promise<IncidentDetail> {
  return apiFetch<IncidentDetail>(`/api/v1/incidents/${id}`);
}

export async function updateIncident(
  id: string,
  patch: { status?: IncidentStatus; assigned_to?: string }
): Promise<IncidentSummary> {
  return apiFetch<IncidentSummary>(`/api/v1/incidents/${id}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

// ─── Agents ──────────────────────────────────────────────────────────────────

export async function listAgents(): Promise<AgentSummary[]> {
  return apiFetch<AgentSummary[]>("/api/v1/agents");
}

// ─── Intelligence ────────────────────────────────────────────────────────────

export async function listFeeds(): Promise<{ feeds: FeedStatus[] }> {
  return apiFetch<{ feeds: FeedStatus[] }>("/api/v1/intel/feeds");
}
