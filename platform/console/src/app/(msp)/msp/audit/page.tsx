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

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Download } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Skeleton } from "@/components/ui/Skeleton";
import { TenantSelector } from "@/components/msp/TenantSelector";
import { getMspTenants, getMspAudit } from "@/lib/api";
import { useTenant } from "@/contexts/TenantContext";
import type { TenantSummary, AuditEntry } from "@/types";

const OUTCOME_COLOR: Record<string, string> = {
  SUCCESS: "text-green-400",
  FAILURE: "text-red-400",
  DENIED: "text-orange-400",
};

const PAGE_SIZE = 50;

export default function MspAuditPage() {
  const { activeTenantId } = useTenant();
  const [page, setPage] = useState(0);

  const { data: tenants = [] } = useQuery<TenantSummary[]>({
    queryKey: ["msp-tenants"],
    queryFn: getMspTenants,
  });

  const { data, isLoading } = useQuery<{ entries: (AuditEntry & { tenant_name?: string })[]; total: number }>({
    queryKey: ["msp-audit", activeTenantId, page],
    queryFn: () =>
      getMspAudit({
        tenant_id: activeTenantId ?? undefined,
        offset: page * PAGE_SIZE,
        limit: PAGE_SIZE,
      }),
  });

  const entries = data?.entries ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.ceil(total / PAGE_SIZE);

  const handleExport = () => {
    if (!entries.length) return;
    const header = "time,actor,role,action,resource,outcome,tenant\n";
    const rows = entries
      .map(
        (e) =>
          `"${e.occurred_at}","${e.actor_id}","${e.actor_role}","${e.action}","${e.resource_type}","${e.outcome}","${e.tenant_name ?? ""}"`
      )
      .join("\n");
    const blob = new Blob([header + rows], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "msp_audit.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Audit Log</h1>
          <p className="text-sm text-slate-500 mt-0.5">
            Cross-tenant audit trail — {total} entries
          </p>
        </div>
        <div className="flex items-center gap-3">
          <TenantSelector tenants={tenants} />
          <Button variant="secondary" size="sm" onClick={handleExport} disabled={!entries.length}>
            <Download className="w-4 h-4" />
            Export CSV
          </Button>
        </div>
      </div>

      <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-700">
              {["Time", "Client", "Actor", "Action", "Resource", "Outcome"].map((h) => (
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
            ) : entries.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-10 text-center text-sm text-slate-500">
                  No audit entries
                </td>
              </tr>
            ) : (
              entries.map((e) => (
                <tr
                  key={e.id}
                  className="border-b border-slate-700/50 last:border-0 hover:bg-slate-700/10 transition-colors"
                >
                  <td className="px-4 py-2.5 text-slate-500 text-xs font-mono whitespace-nowrap">
                    {new Date(e.occurred_at).toLocaleString(undefined, {
                      month: "short",
                      day: "numeric",
                      hour: "2-digit",
                      minute: "2-digit",
                      second: "2-digit",
                    })}
                  </td>
                  <td className="px-4 py-2.5 text-slate-400 text-xs">
                    {e.tenant_name ?? "—"}
                  </td>
                  <td className="px-4 py-2.5 text-slate-300 text-xs font-mono truncate max-w-[8rem]">
                    {e.actor_id}
                  </td>
                  <td className="px-4 py-2.5 text-slate-200 text-xs font-medium">
                    {e.action}
                  </td>
                  <td className="px-4 py-2.5 text-slate-500 text-xs">
                    {e.resource_type}
                    {e.resource_id && (
                      <span className="text-slate-600 font-mono ml-1">
                        {e.resource_id.slice(0, 8)}…
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2.5">
                    <span
                      className={`text-xs font-medium ${
                        OUTCOME_COLOR[e.outcome] ?? "text-slate-400"
                      }`}
                    >
                      {e.outcome}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="px-4 py-3 border-t border-slate-700 flex items-center justify-between text-xs text-slate-500">
            <span>
              Page {page + 1} of {totalPages} ({total} entries)
            </span>
            <div className="flex gap-2">
              <button
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={page === 0}
                className="px-2 py-1 rounded bg-slate-700 hover:bg-slate-600 disabled:opacity-40 transition-colors"
              >
                Prev
              </button>
              <button
                onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                disabled={page >= totalPages - 1}
                className="px-2 py-1 rounded bg-slate-700 hover:bg-slate-600 disabled:opacity-40 transition-colors"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
