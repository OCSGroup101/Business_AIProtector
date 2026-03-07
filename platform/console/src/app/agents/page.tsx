"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Search } from "lucide-react";
import { apiClient } from "@/lib/api";
import type { Agent, AgentState } from "@/types";

const STATE_COLOR: Record<AgentState, string> = {
  ACTIVE: "bg-green-500/20 text-green-400 border border-green-800",
  ISOLATED: "bg-red-500/20 text-red-400 border border-red-800",
  ENROLLING: "bg-yellow-500/20 text-yellow-400 border border-yellow-800",
  UPDATING: "bg-blue-500/20 text-blue-400 border border-blue-800",
};

const STATE_FILTERS: { label: string; value: AgentState | "ALL" }[] = [
  { label: "All", value: "ALL" },
  { label: "Active", value: "ACTIVE" },
  { label: "Isolated", value: "ISOLATED" },
  { label: "Enrolling", value: "ENROLLING" },
  { label: "Updating", value: "UPDATING" },
];

function timeSince(iso: string | null): string {
  if (!iso) return "Never";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "Just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export default function AgentsPage() {
  const [stateFilter, setStateFilter] = useState<AgentState | "ALL">("ALL");
  const [search, setSearch] = useState("");
  const queryClient = useQueryClient();

  const { data: agents = [], isLoading } = useQuery<Agent[]>({
    queryKey: ["agents"],
    queryFn: () => apiClient.get("/api/v1/agents").then((r) => r.data),
    refetchInterval: 30_000,
  });

  const isolate = useMutation({
    mutationFn: (id: string) => apiClient.post(`/api/v1/agents/${id}/isolate`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["agents"] }),
  });

  const unisolate = useMutation({
    mutationFn: (id: string) => apiClient.post(`/api/v1/agents/${id}/unisolate`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["agents"] }),
  });

  const filtered = agents.filter((a) => {
    const matchesState = stateFilter === "ALL" || a.state === stateFilter;
    const matchesSearch =
      !search ||
      a.hostname.toLowerCase().includes(search.toLowerCase()) ||
      a.os_platform.toLowerCase().includes(search.toLowerCase());
    return matchesState && matchesSearch;
  });

  // Summary counts
  const counts = agents.reduce(
    (acc, a) => ({ ...acc, [a.state]: (acc[a.state] ?? 0) + 1 }),
    {} as Record<AgentState, number>
  );

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Agents</h1>
        <span className="text-sm text-gray-500">{agents.length} enrolled</span>
      </div>

      {/* Summary stat row */}
      <div className="grid grid-cols-4 gap-3">
        {(["ACTIVE", "ISOLATED", "ENROLLING", "UPDATING"] as AgentState[]).map((state) => (
          <div key={state} className="bg-gray-900 rounded-xl px-4 py-3">
            <div
              className={`text-2xl font-bold ${
                state === "ACTIVE"
                  ? "text-green-400"
                  : state === "ISOLATED"
                  ? "text-red-400"
                  : state === "ENROLLING"
                  ? "text-yellow-400"
                  : "text-blue-400"
              }`}
            >
              {counts[state] ?? 0}
            </div>
            <div className="text-xs text-gray-500 mt-0.5 capitalize">
              {state.toLowerCase()}
            </div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        {/* State tabs */}
        <div className="flex gap-1">
          {STATE_FILTERS.map((f) => (
            <button
              key={f.value}
              onClick={() => setStateFilter(f.value)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                stateFilter === f.value
                  ? "bg-orange-500/10 text-orange-400"
                  : "text-gray-500 hover:text-gray-300 hover:bg-gray-800"
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="flex items-center gap-2 ml-auto bg-gray-800 rounded-lg px-3 py-1.5">
          <Search className="w-3.5 h-3.5 text-gray-500" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search hostname…"
            className="bg-transparent text-sm text-gray-200 placeholder-gray-600 outline-none w-48"
          />
        </div>
      </div>

      {/* Table */}
      <div className="bg-gray-900 rounded-xl overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-gray-500 text-sm">Loading…</div>
        ) : filtered.length === 0 ? (
          <div className="p-8 text-center text-gray-500 text-sm">No agents found</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-xs text-gray-500 uppercase tracking-wider">
                <th className="px-4 py-3">Hostname</th>
                <th className="px-4 py-3">OS</th>
                <th className="px-4 py-3">Version</th>
                <th className="px-4 py-3">State</th>
                <th className="px-4 py-3">Last Seen</th>
                <th className="px-4 py-3">Policy</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((agent) => (
                <tr
                  key={agent.id}
                  className="border-b border-gray-800 last:border-0 hover:bg-gray-800/40 transition-colors"
                >
                  <td className="px-4 py-3 font-mono text-xs text-gray-200">
                    {agent.hostname}
                  </td>
                  <td className="px-4 py-3 text-gray-400 text-xs">
                    {agent.os_platform} {agent.os_version}
                  </td>
                  <td className="px-4 py-3 text-gray-500 text-xs font-mono">
                    {agent.agent_version}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`px-2 py-0.5 rounded text-xs font-medium ${STATE_COLOR[agent.state]}`}
                    >
                      {agent.state}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-500 text-xs">
                    {timeSince(agent.last_heartbeat_at)}
                  </td>
                  <td className="px-4 py-3 text-gray-500 text-xs">
                    v{agent.policy_version}
                  </td>
                  <td className="px-4 py-3">
                    {agent.state === "ACTIVE" && (
                      <button
                        onClick={() => isolate.mutate(agent.id)}
                        disabled={isolate.isPending}
                        className="px-2 py-0.5 rounded border border-red-900 text-xs text-red-400 hover:bg-red-900/30 transition-colors disabled:opacity-50"
                      >
                        Isolate
                      </button>
                    )}
                    {agent.state === "ISOLATED" && (
                      <button
                        onClick={() => unisolate.mutate(agent.id)}
                        disabled={unisolate.isPending}
                        className="px-2 py-0.5 rounded border border-green-900 text-xs text-green-400 hover:bg-green-900/30 transition-colors disabled:opacity-50"
                      >
                        Unisolate
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
