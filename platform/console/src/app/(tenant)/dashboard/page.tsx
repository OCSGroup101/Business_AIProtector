"use client";

import { useQuery } from "@tanstack/react-query";
import { apiClient } from "@/lib/api";

export default function DashboardPage() {
  const { data: agents, isLoading: agentsLoading } = useQuery({
    queryKey: ["agents"],
    queryFn: () => apiClient.get("/api/v1/agents").then((r) => r.data),
  });

  const { data: incidents } = useQuery({
    queryKey: ["incidents", "open"],
    queryFn: () =>
      apiClient
        .get("/api/v1/incidents", { params: { status: "OPEN", limit: 10 } })
        .then((r) => r.data),
  });

  const activeAgents = agents?.filter((a: any) => a.state === "ACTIVE").length ?? 0;
  const isolatedAgents = agents?.filter((a: any) => a.state === "ISOLATED").length ?? 0;
  const openIncidents = incidents?.length ?? 0;
  const criticalIncidents =
    incidents?.filter((i: any) => i.severity === "CRITICAL").length ?? 0;

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold text-white">Dashboard</h1>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Active Agents" value={activeAgents} color="green" />
        <StatCard label="Isolated Agents" value={isolatedAgents} color="orange" />
        <StatCard label="Open Incidents" value={openIncidents} color="yellow" />
        <StatCard label="Critical Incidents" value={criticalIncidents} color="red" />
      </div>

      {/* Recent incidents */}
      <div className="bg-gray-900 rounded-xl p-4">
        <h2 className="text-lg font-semibold text-white mb-4">Recent Open Incidents</h2>
        {incidents?.length === 0 && (
          <p className="text-gray-500 text-sm">No open incidents</p>
        )}
        {incidents?.map((incident: any) => (
          <IncidentRow key={incident.id} incident={incident} />
        ))}
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: "green" | "orange" | "yellow" | "red";
}) {
  const colorMap = {
    green: "text-green-400",
    orange: "text-orange-400",
    yellow: "text-yellow-400",
    red: "text-red-400",
  };
  return (
    <div className="bg-gray-900 rounded-xl p-4">
      <div className={`text-3xl font-bold ${colorMap[color]}`}>{value}</div>
      <div className="text-sm text-gray-400 mt-1">{label}</div>
    </div>
  );
}

function IncidentRow({ incident }: { incident: any }) {
  const severityColor: Record<string, string> = {
    CRITICAL: "bg-red-500",
    HIGH: "bg-orange-500",
    MEDIUM: "bg-yellow-500",
    LOW: "bg-green-500",
    INFO: "bg-gray-500",
  };
  return (
    <div className="flex items-center gap-3 py-2 border-b border-gray-800 last:border-0">
      <span
        className={`w-2 h-2 rounded-full flex-shrink-0 ${severityColor[incident.severity] ?? "bg-gray-500"}`}
      />
      <span className="flex-1 text-sm text-gray-200 truncate">{incident.rule_name}</span>
      <span className="text-xs text-gray-500">{incident.hostname}</span>
    </div>
  );
}
