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
import type { CreateRuleRequest, CreateSiemConnectorRequest } from "@/types";

export const PLATFORM_URL =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8888";

export const apiClient = axios.create({
  baseURL: PLATFORM_URL,
  timeout: 15_000,
  headers: {
    "Content-Type": "application/json",
  },
});

// Attach auth token from Keycloak on each request
apiClient.interceptors.request.use((config) => {
  if (typeof window !== "undefined") {
    const token = sessionStorage.getItem("kc_token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  }
  return config;
});

// Retry on 401 (token refresh)
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      // Phase 1: trigger Keycloak token refresh
      sessionStorage.removeItem("kc_token");
    }
    return Promise.reject(error);
  }
);

// Rules
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

// Reports
export const listReports = () =>
  apiClient.get("/api/v1/reports").then((r) => r.data);
export const generateReport = (type: string, period_days: number) =>
  apiClient.post("/api/v1/reports", { type, period_days });
export const getReportDownloadUrl = (id: string) =>
  `${PLATFORM_URL}/api/v1/reports/${id}/download`;

// SIEM
export const listSiemConnectors = () =>
  apiClient.get("/api/v1/siem/connectors").then((r) => r.data);
export const createSiemConnector = (data: CreateSiemConnectorRequest) =>
  apiClient.post("/api/v1/siem/connectors", data);
export const deleteSiemConnector = (id: string) =>
  apiClient.delete(`/api/v1/siem/connectors/${id}`);
export const testSiemConnector = (id: string) =>
  apiClient.post(`/api/v1/siem/connectors/${id}/test`);
