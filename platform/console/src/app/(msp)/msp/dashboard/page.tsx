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

import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import {
  Building2,
  Monitor,
  AlertTriangle,
  ShieldAlert,
  RefreshCw,
} from "lucide-react";
import { StatCard } from "@/components/ui/StatCard";
import { Badge } from "@/components/ui/Badge";
import { Skeleton } from "@/components/ui/Skeleton";
import { getMspSummary, getMspTenants } from "@/lib/api";
import type { MspSummary, TenantSummary } from "@/types";
import { useTenant } from "@/contexts/TenantContext";

function healthBadge(t: TenantSummary) {
  if (t.open_incidents === 0) return <Badge variant="success">Healthy</Badge>;
  if (t.critical_incidents > 0) return <Badge variant="danger">Critical</Badge>;
  return <Badge variant="warning">Warning</Badge>;
}

export default function MspDashboardPage() {
  const router = useRouter();
  const { setActiveTenant } = useTenant();

  const {
    data: summary,
    isLoading: summaryLoading,
    refetch,
    dataUpdatedAt,
  } = useQuery<MspSummary>({
    queryKey: ["msp-summary"],
    queryFn: getMspSummary,
    refetchInterval: 30_000,
  });

  const { data: tenants = [], isLoading: tenantsLoading } = useQuery<TenantSummary[]>({
    queryKey: ["msp-tenants"],
    queryFn: getMspTenants,
    refetchInterval: 30_000,
  });

  const lastRefreshed = dataUpdatedAt
    ? new Date(dataUpdatedAt).toLocaleTimeString()
    : "—";

  const handleDrillIn = (tenant: TenantSummary) => {
    setActiveTenant(tenant.id, tenant.name);
    router.push(`/msp/clients/${tenant.id}`);
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">MSP Dashboard</h1>
          <p className="text-sm text-slate-500 mt-0.5">
            Aggregate view across all managed clients
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-600">Updated {lastRefreshed}</span>
          <button
            onClick={() => refetch()}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-slate-400 bg-slate-800 border border-slate-700 rounded-lg hover:bg-slate-700 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {summaryLoading ? (
          Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-24 rounded-xl" />
          ))
        ) : (
          <>
            <StatCard
              icon={Building2}
              label="Total Clients"
              value={summary?.total_tenants ?? 0}
              iconColor="text-blue-400"
            />
            <StatCard
              icon={Monitor}
              label="Total Agents"
              value={summary?.total_agents ?? 0}
              iconColor="text-green-400"
            />
            <StatCard
              icon={AlertTriangle}
              label="Open Incidents"
              value={summary?.total_open_incidents ?? 0}
              iconColor="text-yellow-400"
            />
            <StatCard
              icon={ShieldAlert}
              label="Critical Alerts"
              value={summary?.critical_incidents ?? 0}
              iconColor="text-red-400"
            />
          </>
        )}
      </div>

      {/* Tenants table */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-700">
          <h2 className="text-sm font-semibold text-slate-200">
            Client Overview
          </h2>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-700">
              {["Client", "Agents", "Open Incidents", "Critical", "Health", ""].map(
                (h) => (
                  <th
                    key={h}
                    className="px-4 py-3 text-left text-xs text-slate-500 font-medium uppercase tracking-wider"
                  >
                    {h}
                  </th>
                )
              )}
            </tr>
          </thead>
          <tbody>
            {tenantsLoading ? (
              Array.from({ length: 4 }).map((_, i) => (
                <tr key={i} className="border-b border-slate-700/50">
                  {Array.from({ length: 6 }).map((__, j) => (
                    <td key={j} className="px-4 py-3">
                      <Skeleton className="h-4" />
                    </td>
                  ))}
                </tr>
              ))
            ) : tenants.length === 0 ? (
              <tr>
                <td
                  colSpan={6}
                  className="px-4 py-10 text-center text-slate-500 text-sm"
                >
                  No clients provisioned yet
                </td>
              </tr>
            ) : (
              tenants.map((t) => (
                <tr
                  key={t.id}
                  className="border-b border-slate-700/50 last:border-0 hover:bg-slate-700/20 transition-colors"
                >
                  <td className="px-4 py-3 font-medium text-slate-200">
                    {t.name}
                  </td>
                  <td className="px-4 py-3 text-slate-400">{t.agent_count}</td>
                  <td className="px-4 py-3 text-slate-400">
                    {t.open_incidents}
                  </td>
                  <td className="px-4 py-3">
                    {t.critical_incidents > 0 ? (
                      <span className="text-red-400 font-semibold">
                        {t.critical_incidents}
                      </span>
                    ) : (
                      <span className="text-slate-600">0</span>
                    )}
                  </td>
                  <td className="px-4 py-3">{healthBadge(t)}</td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => handleDrillIn(t)}
                      className="px-3 py-1 text-xs bg-blue-600/20 text-blue-400 border border-blue-700/50 rounded-lg hover:bg-blue-600/30 transition-colors"
                    >
                      Drill In
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
