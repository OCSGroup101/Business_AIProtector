"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { RefreshCw } from "lucide-react";
import { apiClient } from "@/lib/api";
import type { Incident, IncidentStatus, Severity } from "@/types";

const STATUS_TABS: { label: string; value: IncidentStatus | "ALL" }[] = [
  { label: "All", value: "ALL" },
  { label: "Open", value: "OPEN" },
  { label: "Investigating", value: "INVESTIGATING" },
  { label: "Contained", value: "CONTAINED" },
  { label: "Resolved", value: "RESOLVED" },
  { label: "False Positive", value: "FALSE_POSITIVE" },
];

const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: "bg-red-500 text-white",
  HIGH: "bg-orange-500 text-white",
  MEDIUM: "bg-yellow-500 text-black",
  LOW: "bg-green-600 text-white",
  INFO: "bg-gray-600 text-white",
};

const STATUS_COLOR: Record<IncidentStatus, string> = {
  OPEN: "text-red-400",
  INVESTIGATING: "text-yellow-400",
  CONTAINED: "text-orange-400",
  RESOLVED: "text-green-400",
  FALSE_POSITIVE: "text-gray-500",
};

function fmt(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function IncidentsPage() {
  const [statusFilter, setStatusFilter] = useState<IncidentStatus | "ALL">("OPEN");
  const queryClient = useQueryClient();

  const { data: incidents = [], isLoading, dataUpdatedAt, refetch } = useQuery<Incident[]>({
    queryKey: ["incidents", statusFilter],
    queryFn: () =>
      apiClient
        .get("/api/v1/incidents", {
          params: {
            status: statusFilter === "ALL" ? undefined : statusFilter,
            limit: 200,
          },
        })
        .then((r) => r.data),
    refetchInterval: 30_000,
  });

  const updateStatus = useMutation({
    mutationFn: ({ id, status }: { id: string; status: IncidentStatus }) =>
      apiClient.patch(`/api/v1/incidents/${id}/status`, { status }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["incidents"] }),
  });

  const isolateAgent = useMutation({
    mutationFn: (agentId: string) =>
      apiClient.post(`/api/v1/agents/${agentId}/isolate`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["agents"] });
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
    },
  });

  const lastRefreshed = dataUpdatedAt
    ? new Date(dataUpdatedAt).toLocaleTimeString()
    : "—";

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Incidents</h1>
        <div className="flex items-center gap-3">
          <span className="text-xs text-gray-500">Updated {lastRefreshed}</span>
          <button
            onClick={() => refetch()}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-300 bg-gray-800 rounded-lg hover:bg-gray-700 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      {/* Status filter tabs */}
      <div className="flex gap-1 border-b border-gray-800">
        {STATUS_TABS.map((tab) => (
          <button
            key={tab.value}
            onClick={() => setStatusFilter(tab.value)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              statusFilter === tab.value
                ? "border-orange-500 text-orange-400"
                : "border-transparent text-gray-500 hover:text-gray-300"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="bg-gray-900 rounded-xl overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-gray-500 text-sm">Loading…</div>
        ) : incidents.length === 0 ? (
          <div className="p-8 text-center text-gray-500 text-sm">
            No incidents matching this filter
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-xs text-gray-500 uppercase tracking-wider">
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Rule</th>
                <th className="px-4 py-3">Host</th>
                <th className="px-4 py-3">MITRE</th>
                <th className="px-4 py-3">First Seen</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((incident) => (
                <IncidentRow
                  key={incident.id}
                  incident={incident}
                  onUpdateStatus={(status) =>
                    updateStatus.mutate({ id: incident.id, status })
                  }
                  onIsolate={() => isolateAgent.mutate(incident.agent_id)}
                />
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function IncidentRow({
  incident,
  onUpdateStatus,
  onIsolate,
}: {
  incident: Incident;
  onUpdateStatus: (status: IncidentStatus) => void;
  onIsolate: () => void;
}) {
  return (
    <tr className="border-b border-gray-800 last:border-0 hover:bg-gray-800/40 transition-colors">
      {/* Severity */}
      <td className="px-4 py-3">
        <span
          className={`inline-block px-2 py-0.5 rounded text-xs font-bold ${SEVERITY_COLOR[incident.severity]}`}
        >
          {incident.severity}
        </span>
      </td>

      {/* Rule name */}
      <td className="px-4 py-3 text-gray-200 max-w-xs truncate">
        {incident.rule_name}
      </td>

      {/* Hostname */}
      <td className="px-4 py-3 text-gray-400 font-mono text-xs">
        {incident.hostname}
      </td>

      {/* MITRE techniques */}
      <td className="px-4 py-3">
        <div className="flex flex-wrap gap-1">
          {(incident.mitre_techniques ?? []).slice(0, 3).map((t) => (
            <span
              key={t}
              className="px-1.5 py-0.5 rounded bg-gray-700 text-gray-300 text-xs font-mono"
            >
              {t}
            </span>
          ))}
        </div>
      </td>

      {/* First seen */}
      <td className="px-4 py-3 text-gray-500 text-xs whitespace-nowrap">
        {fmt(incident.first_seen_at)}
      </td>

      {/* Status */}
      <td className="px-4 py-3">
        <span className={`text-xs font-medium ${STATUS_COLOR[incident.status]}`}>
          {incident.status.replace("_", " ")}
        </span>
      </td>

      {/* Actions */}
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          {incident.status === "OPEN" && (
            <ActionButton
              onClick={() => onUpdateStatus("INVESTIGATING")}
              label="Investigate"
              className="text-yellow-400 border-yellow-800 hover:bg-yellow-900/30"
            />
          )}
          {(incident.status === "OPEN" || incident.status === "INVESTIGATING") && (
            <ActionButton
              onClick={onIsolate}
              label="Isolate"
              className="text-red-400 border-red-900 hover:bg-red-900/30"
            />
          )}
          {incident.status === "INVESTIGATING" && (
            <ActionButton
              onClick={() => onUpdateStatus("RESOLVED")}
              label="Resolve"
              className="text-green-400 border-green-900 hover:bg-green-900/30"
            />
          )}
          {incident.status === "OPEN" && (
            <ActionButton
              onClick={() => onUpdateStatus("FALSE_POSITIVE")}
              label="FP"
              className="text-gray-400 border-gray-700 hover:bg-gray-800"
            />
          )}
        </div>
      </td>
    </tr>
  );
}

function ActionButton({
  onClick,
  label,
  className,
}: {
  onClick: () => void;
  label: string;
  className: string;
}) {
  return (
    <button
      onClick={onClick}
      className={`px-2 py-0.5 rounded border text-xs transition-colors ${className}`}
    >
      {label}
    </button>
  );
}
