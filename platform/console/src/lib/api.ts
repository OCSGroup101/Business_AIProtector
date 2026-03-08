// Copyright 2024 Omni Cyber Solutions LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import axios from "axios";
import type {
  CreateRuleRequest,
  CreateSiemConnectorRequest,
  MspSummary,
  TenantSummary,
  TenantDetailSummary,
  ProvisionTenantRequest,
  MspAlert,
  AuditEntry,
} from "@/types";

export const PLATFORM_URL =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8888";

export const apiClient = axios.create({
  baseURL: PLATFORM_URL,
  timeout: 15_000,
  headers: {
    "Content-Type": "application/json",
  },
});

// Auth interceptor: attach Keycloak token (or dev token) on every request
apiClient.interceptors.request.use((config) => {
  if (typeof window !== "undefined") {
    const token =
      sessionStorage.getItem("kc_token") ?? localStorage.getItem("dev_token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  }
  return config;
});

// Retry on 401: clear token so next request forces re-auth
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      sessionStorage.removeItem("kc_token");
    }
    return Promise.reject(error);
  }
);

// ─── Rules ────────────────────────────────────────────────────────────────────

export const listRules = () =>
  apiClient.get("/api/v1/rules").then((r) => r.data);
export const getRule = (id: string) =>
  apiClient.get(`/api/v1/rules/${id}`).then((r) => r.data);
export const createRule = (data: CreateRuleRequest) =>
  apiClient.post("/api/v1/rules", data);
export const updateRule = (id: string, data: Partial<CreateRuleRequest>) =>
  apiClient.patch(`/api/v1/rules/${id}`, data);
export const deleteRule = (id: string) =>
  apiClient.delete(`/api/v1/rules/${id}`);
export const validateRule = (toml: string) =>
  apiClient.post("/api/v1/rules/validate", { content_toml: toml });
export const testRule = (toml: string, events: unknown[]) =>
  apiClient.post("/api/v1/rules/test", { content_toml: toml, events });

// ─── Reports ──────────────────────────────────────────────────────────────────

export const listReports = () =>
  apiClient.get("/api/v1/reports").then((r) => r.data);
export const generateReport = (type: string, period_days: number) =>
  apiClient.post("/api/v1/reports", { type, period_days });
export const getReportDownloadUrl = (id: string) =>
  `${PLATFORM_URL}/api/v1/reports/${id}/download`;

// ─── SIEM ─────────────────────────────────────────────────────────────────────

export const listSiemConnectors = () =>
  apiClient.get("/api/v1/siem/connectors").then((r) => r.data);
export const createSiemConnector = (data: CreateSiemConnectorRequest) =>
  apiClient.post("/api/v1/siem/connectors", data);
export const deleteSiemConnector = (id: string) =>
  apiClient.delete(`/api/v1/siem/connectors/${id}`);
export const testSiemConnector = (id: string) =>
  apiClient.post(`/api/v1/siem/connectors/${id}/test`);

// ─── MSP ──────────────────────────────────────────────────────────────────────

export const getMspSummary = (): Promise<MspSummary> =>
  apiClient.get("/api/v1/msp/summary").then((r) => r.data);

export const getMspTenants = (): Promise<TenantSummary[]> =>
  apiClient.get("/api/v1/msp/tenants").then((r) => r.data);

export const getMspTenantSummary = (tenantId: string): Promise<TenantDetailSummary> =>
  apiClient.get(`/api/v1/msp/tenants/${tenantId}/summary`).then((r) => r.data);

export const provisionTenant = (data: ProvisionTenantRequest): Promise<{ id: string; name: string }> =>
  apiClient.post("/api/v1/msp/tenants", data).then((r) => r.data);

export const generateEnrollmentToken = (
  tenantId: string
): Promise<{ token: string; tenant_id: string }> =>
  apiClient
    .post(`/api/v1/msp/tenants/${tenantId}/enrollment-token`)
    .then((r) => r.data);

export const getMspAlerts = (tenantId?: string): Promise<MspAlert[]> =>
  apiClient
    .get("/api/v1/msp/alerts", { params: tenantId ? { tenant_id: tenantId } : {} })
    .then((r) => r.data);

export const getMspAudit = (params: {
  tenant_id?: string;
  offset?: number;
  limit?: number;
}): Promise<{ entries: (AuditEntry & { tenant_name?: string })[]; total: number }> =>
  apiClient.get("/api/v1/msp/audit", { params }).then((r) => r.data);
