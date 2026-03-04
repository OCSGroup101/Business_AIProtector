"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { apiClient } from "@/lib/api";
import type { AuditEntry } from "@/types";

const OUTCOME_COLOR: Record<string, string> = {
  SUCCESS: "text-green-400",
  FAILURE: "text-red-400",
  DENIED: "text-orange-400",
};

const PAGE_SIZE = 50;

function fmt(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export default function AuditPage() {
  const [page, setPage] = useState(0);
  const [outcomeFilter, setOutcomeFilter] = useState<string>("ALL");

  const { data, isLoading } = useQuery<{ entries: AuditEntry[]; total: number }>({
    queryKey: ["audit", page, outcomeFilter],
    queryFn: () =>
      apiClient
        .get("/api/v1/audit", {
          params: {
            offset: page * PAGE_SIZE,
            limit: PAGE_SIZE,
            outcome: outcomeFilter === "ALL" ? undefined : outcomeFilter,
          },
        })
        .then((r) => r.data),
  });

  const entries = data?.entries ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Audit Log</h1>
        <span className="text-sm text-gray-500">{total} entries</span>
      </div>

      {/* Outcome filter */}
      <div className="flex gap-1">
        {["ALL", "SUCCESS", "FAILURE", "DENIED"].map((outcome) => (
          <button
            key={outcome}
            onClick={() => {
              setOutcomeFilter(outcome);
              setPage(0);
            }}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              outcomeFilter === outcome
                ? "bg-orange-500/10 text-orange-400"
                : "text-gray-500 hover:text-gray-300 hover:bg-gray-800"
            }`}
          >
            {outcome === "ALL" ? "All" : outcome.charAt(0) + outcome.slice(1).toLowerCase()}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="bg-gray-900 rounded-xl overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-gray-500 text-sm">Loading…</div>
        ) : entries.length === 0 ? (
          <div className="p-8 text-center text-gray-500 text-sm">No audit entries found</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-xs text-gray-500 uppercase tracking-wider">
                <th className="px-4 py-3">Time</th>
                <th className="px-4 py-3">Actor</th>
                <th className="px-4 py-3">Role</th>
                <th className="px-4 py-3">Action</th>
                <th className="px-4 py-3">Resource</th>
                <th className="px-4 py-3">Outcome</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <tr
                  key={entry.id}
                  className="border-b border-gray-800 last:border-0 hover:bg-gray-800/40 transition-colors"
                >
                  <td className="px-4 py-2.5 text-gray-500 text-xs whitespace-nowrap font-mono">
                    {fmt(entry.occurred_at)}
                  </td>
                  <td className="px-4 py-2.5 text-gray-300 text-xs font-mono truncate max-w-[10rem]">
                    {entry.actor_id}
                  </td>
                  <td className="px-4 py-2.5 text-gray-500 text-xs">
                    {entry.actor_role}
                  </td>
                  <td className="px-4 py-2.5 text-gray-200 text-xs font-medium">
                    {entry.action}
                  </td>
                  <td className="px-4 py-2.5 text-xs">
                    <span className="text-gray-500">{entry.resource_type}</span>
                    {entry.resource_id && (
                      <span className="text-gray-600 font-mono ml-1 text-xs">
                        {entry.resource_id.slice(0, 8)}…
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2.5">
                    <span
                      className={`text-xs font-medium ${
                        OUTCOME_COLOR[entry.outcome] ?? "text-gray-400"
                      }`}
                    >
                      {entry.outcome}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between text-xs text-gray-500">
          <span>
            Page {page + 1} of {totalPages} ({total} entries)
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
              className="p-1.5 rounded hover:bg-gray-800 disabled:opacity-40 transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
              disabled={page >= totalPages - 1}
              className="p-1.5 rounded hover:bg-gray-800 disabled:opacity-40 transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
