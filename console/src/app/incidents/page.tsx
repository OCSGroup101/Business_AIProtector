"use client";
// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { formatDistanceToNow } from "date-fns";
import { listIncidents, type IncidentStatus, type Severity } from "@/lib/api";
import { SeverityBadge } from "@/components/SeverityBadge";
import { StatusBadge } from "@/components/StatusBadge";

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const STATUSES: IncidentStatus[] = [
  "OPEN",
  "INVESTIGATING",
  "CONTAINED",
  "RESOLVED",
  "FALSE_POSITIVE",
];

export default function IncidentsPage() {
  const router = useRouter();
  const [severity, setSeverity] = useState<Severity | "">("");
  const [status, setStatus] = useState<IncidentStatus | "">("");

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["incidents", severity, status],
    queryFn: () =>
      listIncidents({
        severity: severity || undefined,
        status: status || undefined,
        limit: 100,
      }),
  });

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Incidents</h1>
        <div className="flex gap-3">
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value as Severity | "")}
            className="text-sm border border-gray-300 rounded-md px-3 py-1.5 bg-white"
          >
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value as IncidentStatus | "")}
            className="text-sm border border-gray-300 rounded-md px-3 py-1.5 bg-white"
          >
            <option value="">All statuses</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
      </div>

      {isLoading && (
        <div className="text-gray-500 text-sm py-12 text-center">
          Loading incidents...
        </div>
      )}

      {isError && (
        <div className="text-red-600 text-sm py-4 px-4 bg-red-50 rounded-md border border-red-200">
          {error instanceof Error ? error.message : "Failed to load incidents"}
        </div>
      )}

      {data && data.length === 0 && (
        <div className="text-gray-500 text-sm py-12 text-center">
          No incidents found.
        </div>
      )}

      {data && data.length > 0 && (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                {["Severity", "Rule", "Host", "Status", "MITRE", "First seen", "Last seen"].map(
                  (h) => (
                    <th
                      key={h}
                      className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                    >
                      {h}
                    </th>
                  )
                )}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {data.map((incident) => (
                <tr
                  key={incident.id}
                  className="table-row-link"
                  onClick={() => router.push(`/incidents/${incident.id}`)}
                >
                  <td className="px-4 py-3 whitespace-nowrap">
                    <SeverityBadge severity={incident.severity} />
                  </td>
                  <td className="px-4 py-3 text-sm font-medium text-gray-900 max-w-xs truncate">
                    {incident.rule_name}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600 font-mono">
                    {incident.hostname}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <StatusBadge status={incident.status} />
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500 max-w-xs truncate">
                    {incident.mitre_techniques?.join(", ") ?? "—"}
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500 whitespace-nowrap">
                    {formatDistanceToNow(new Date(incident.first_seen_at), {
                      addSuffix: true,
                    })}
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500 whitespace-nowrap">
                    {formatDistanceToNow(new Date(incident.last_seen_at), {
                      addSuffix: true,
                    })}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
