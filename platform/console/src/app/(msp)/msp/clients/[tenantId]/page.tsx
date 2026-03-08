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

"use client";

import { use } from "react";
import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { ArrowLeft, ExternalLink, Monitor, AlertTriangle, ShieldAlert } from "lucide-react";
import { StatCard } from "@/components/ui/StatCard";
import { Badge } from "@/components/ui/Badge";
import { Skeleton } from "@/components/ui/Skeleton";
import { getMspTenantSummary } from "@/lib/api";
import { useTenant } from "@/contexts/TenantContext";
import type { TenantDetailSummary } from "@/types";

interface PageProps {
  params: Promise<{ tenantId: string }>;
}

export default function TenantDetailPage({ params }: PageProps) {
  const { tenantId } = use(params);
  const router = useRouter();
  const { setActiveTenant } = useTenant();

  const { data, isLoading } = useQuery<TenantDetailSummary>({
    queryKey: ["msp-tenant-summary", tenantId],
    queryFn: () => getMspTenantSummary(tenantId),
  });

  const handleViewConsole = () => {
    if (data) {
      setActiveTenant(tenantId, data.name);
    }
    router.push("/incidents");
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <button
            onClick={() => router.push("/msp/clients")}
            className="p-1.5 rounded-lg text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            {isLoading ? (
              <Skeleton className="h-6 w-40 mb-1" />
            ) : (
              <h1 className="text-xl font-bold text-slate-100">
                {data?.name ?? tenantId}
              </h1>
            )}
            <p className="text-xs text-slate-500 font-mono">{tenantId}</p>
          </div>
        </div>
        <button
          onClick={handleViewConsole}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium transition-colors"
        >
          <ExternalLink className="w-4 h-4" />
          View Console
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
        {isLoading ? (
          Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-24 rounded-xl" />
          ))
        ) : (
          <>
            <StatCard
              icon={Monitor}
              label="Active Agents"
              value={data?.agent_count ?? 0}
              iconColor="text-green-400"
            />
            <StatCard
              icon={AlertTriangle}
              label="Open Incidents"
              value={data?.open_incidents ?? 0}
              iconColor="text-yellow-400"
            />
            <StatCard
              icon={ShieldAlert}
              label="Critical"
              value={data?.critical_incidents ?? 0}
              iconColor="text-red-400"
            />
          </>
        )}
      </div>

      {/* Recent incidents */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-700">
          <h2 className="text-sm font-semibold text-slate-200">
            Recent Incidents
          </h2>
        </div>
        {isLoading ? (
          <div className="p-4 space-y-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <Skeleton key={i} className="h-8" />
            ))}
          </div>
        ) : (data?.recent_incidents ?? []).length === 0 ? (
          <p className="px-5 py-8 text-center text-sm text-slate-500">
            No recent incidents
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700">
                {["Severity", "Rule", "Host", "Status", "First Seen"].map((h) => (
                  <th
                    key={h}
                    className="px-4 py-3 text-left text-xs text-slate-500 font-medium uppercase tracking-wider"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(data?.recent_incidents ?? []).map((inc) => (
                <tr
                  key={inc.id}
                  className="border-b border-slate-700/50 last:border-0"
                >
                  <td className="px-4 py-3">
                    <Badge
                      variant={
                        inc.severity === "CRITICAL"
                          ? "danger"
                          : inc.severity === "HIGH"
                          ? "warning"
                          : "default"
                      }
                    >
                      {inc.severity}
                    </Badge>
                  </td>
                  <td className="px-4 py-3 text-slate-300 text-xs">
                    {inc.rule_name}
                  </td>
                  <td className="px-4 py-3 text-slate-500 text-xs font-mono">
                    {inc.hostname}
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs text-slate-400">{inc.status}</span>
                  </td>
                  <td className="px-4 py-3 text-slate-500 text-xs whitespace-nowrap">
                    {new Date(inc.first_seen_at).toLocaleString(undefined, {
                      month: "short",
                      day: "numeric",
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Recent agents */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-700">
          <h2 className="text-sm font-semibold text-slate-200">
            Enrolled Agents
          </h2>
        </div>
        {isLoading ? (
          <div className="p-4 space-y-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <Skeleton key={i} className="h-8" />
            ))}
          </div>
        ) : (data?.agents ?? []).length === 0 ? (
          <p className="px-5 py-8 text-center text-sm text-slate-500">
            No agents enrolled
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700">
                {["Hostname", "OS", "Version", "State", "Last Seen"].map((h) => (
                  <th
                    key={h}
                    className="px-4 py-3 text-left text-xs text-slate-500 font-medium uppercase tracking-wider"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(data?.agents ?? []).map((agent) => (
                <tr
                  key={agent.id}
                  className="border-b border-slate-700/50 last:border-0"
                >
                  <td className="px-4 py-3 font-mono text-xs text-slate-200">
                    {agent.hostname}
                  </td>
                  <td className="px-4 py-3 text-slate-400 text-xs">
                    {agent.os_platform}
                  </td>
                  <td className="px-4 py-3 text-slate-500 text-xs font-mono">
                    {agent.agent_version}
                  </td>
                  <td className="px-4 py-3">
                    <Badge
                      variant={
                        agent.state === "ACTIVE"
                          ? "success"
                          : agent.state === "ISOLATED"
                          ? "danger"
                          : "warning"
                      }
                    >
                      {agent.state}
                    </Badge>
                  </td>
                  <td className="px-4 py-3 text-slate-500 text-xs">
                    {agent.last_heartbeat_at
                      ? new Date(agent.last_heartbeat_at).toLocaleString()
                      : "Never"}
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
