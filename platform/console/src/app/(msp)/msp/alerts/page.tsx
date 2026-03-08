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
import { Badge } from "@/components/ui/Badge";
import { Skeleton } from "@/components/ui/Skeleton";
import { TenantSelector } from "@/components/msp/TenantSelector";
import { getMspAlerts, getMspTenants } from "@/lib/api";
import { useTenant } from "@/contexts/TenantContext";
import type { MspAlert, TenantSummary } from "@/types";

export default function MspAlertsPage() {
  const router = useRouter();
  const { activeTenantId, setActiveTenant } = useTenant();

  const { data: tenants = [] } = useQuery<TenantSummary[]>({
    queryKey: ["msp-tenants"],
    queryFn: getMspTenants,
  });

  const { data: alerts = [], isLoading } = useQuery<MspAlert[]>({
    queryKey: ["msp-alerts", activeTenantId],
    queryFn: () => getMspAlerts(activeTenantId ?? undefined),
    refetchInterval: 30_000,
  });

  const handleRowClick = (alert: MspAlert) => {
    const tenant = tenants.find((t) => t.id === alert.tenant_id);
    if (tenant) setActiveTenant(tenant.id, tenant.name);
    router.push(`/incidents/${alert.id}`);
  };

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Alerts</h1>
          <p className="text-sm text-slate-500 mt-0.5">
            Unified incident feed across all clients
          </p>
        </div>
        <TenantSelector tenants={tenants} />
      </div>

      <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-700">
              {["Severity", "Client", "Rule", "Host", "Status", "First Seen"].map((h) => (
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
            {isLoading ? (
              Array.from({ length: 8 }).map((_, i) => (
                <tr key={i} className="border-b border-slate-700/50">
                  {Array.from({ length: 6 }).map((__, j) => (
                    <td key={j} className="px-4 py-3">
                      <Skeleton className="h-4" />
                    </td>
                  ))}
                </tr>
              ))
            ) : alerts.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-10 text-center text-sm text-slate-500">
                  No alerts found
                </td>
              </tr>
            ) : (
              alerts.map((alert) => (
                <tr
                  key={alert.id}
                  onClick={() => handleRowClick(alert)}
                  className="border-b border-slate-700/50 last:border-0 hover:bg-slate-700/20 cursor-pointer transition-colors"
                >
                  <td className="px-4 py-3">
                    <Badge
                      variant={
                        alert.severity === "CRITICAL"
                          ? "danger"
                          : alert.severity === "HIGH"
                          ? "warning"
                          : "default"
                      }
                    >
                      {alert.severity}
                    </Badge>
                  </td>
                  <td className="px-4 py-3 text-slate-300 text-xs font-medium">
                    {alert.tenant_name}
                  </td>
                  <td className="px-4 py-3 text-slate-300 text-xs">
                    {alert.rule_name}
                  </td>
                  <td className="px-4 py-3 text-slate-500 text-xs font-mono">
                    {alert.hostname}
                  </td>
                  <td className="px-4 py-3 text-slate-400 text-xs">
                    {alert.status}
                  </td>
                  <td className="px-4 py-3 text-slate-500 text-xs whitespace-nowrap">
                    {new Date(alert.first_seen_at).toLocaleString(undefined, {
                      month: "short",
                      day: "numeric",
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
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
