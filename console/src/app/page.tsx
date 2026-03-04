"use client";
// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.

import { useQuery } from "@tanstack/react-query";
import { formatDistanceToNow } from "date-fns";
import Link from "next/link";
import clsx from "clsx";

import { getDashboardStats } from "@/lib/api";
import type { Severity } from "@/lib/api";
import { SeverityBadge } from "@/components/SeverityBadge";
import { StatusBadge } from "@/components/StatusBadge";

// ─── Severity summary card ────────────────────────────────────────────────────

const SEVERITY_CARD: Record<
  Severity,
  { label: string; bg: string; text: string; border: string }
> = {
  CRITICAL: { label: "Critical",  bg: "bg-red-50",    text: "text-red-700",    border: "border-red-300" },
  HIGH:     { label: "High",      bg: "bg-orange-50", text: "text-orange-700", border: "border-orange-300" },
  MEDIUM:   { label: "Medium",    bg: "bg-yellow-50", text: "text-yellow-700", border: "border-yellow-300" },
  LOW:      { label: "Low",       bg: "bg-blue-50",   text: "text-blue-700",   border: "border-blue-300" },
  INFO:     { label: "Info",      bg: "bg-gray-50",   text: "text-gray-600",   border: "border-gray-200" },
};

function SeverityCard({ severity, count }: { severity: Severity; count: number }) {
  const s = SEVERITY_CARD[severity];
  return (
    <Link
      href={`/incidents?severity=${severity}`}
      className={clsx(
        "flex flex-col items-center justify-center rounded-lg border p-4 transition hover:shadow-md",
        s.bg, s.border
      )}
    >
      <span className={clsx("text-3xl font-bold", s.text)}>{count}</span>
      <span className={clsx("mt-1 text-xs font-medium uppercase tracking-wide", s.text)}>
        {s.label}
      </span>
    </Link>
  );
}

// ─── Feed health dot ──────────────────────────────────────────────────────────

function FeedDot({ status }: { status: string }) {
  return (
    <span
      className={clsx("inline-block h-2 w-2 rounded-full", {
        "bg-green-500": status === "active",
        "bg-yellow-400": status === "pending",
        "bg-red-500":   status === "error",
      })}
    />
  );
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

export default function DashboardPage() {
  const { data, isLoading, isError, error, dataUpdatedAt } = useQuery({
    queryKey: ["dashboard"],
    queryFn: getDashboardStats,
    refetchInterval: 30_000,
  });

  const updatedAt = dataUpdatedAt
    ? formatDistanceToNow(new Date(dataUpdatedAt), { addSuffix: true })
    : null;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        {updatedAt && (
          <span className="text-xs text-gray-400">Updated {updatedAt}</span>
        )}
      </div>

      {isError && (
        <div className="text-red-600 text-sm py-3 px-4 bg-red-50 rounded border border-red-200">
          {error instanceof Error ? error.message : "Failed to load dashboard"}
        </div>
      )}

      {/* Severity summary row */}
      <section>
        <h2 className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-3">
          Open Incidents
        </h2>
        {isLoading ? (
          <div className="grid grid-cols-5 gap-3">
            {(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as Severity[]).map((s) => (
              <div key={s} className="h-20 rounded-lg bg-gray-100 animate-pulse" />
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-5 gap-3">
            {(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as Severity[]).map((s) => (
              <SeverityCard
                key={s}
                severity={s}
                count={data?.incidentsBySeverity[s] ?? 0}
              />
            ))}
          </div>
        )}
      </section>

      {/* Summary metrics row */}
      <div className="grid grid-cols-3 gap-4">
        {/* Total open incidents */}
        <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
          <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">
            Total Open
          </div>
          <div className="mt-1 text-3xl font-bold text-gray-900">
            {isLoading ? "—" : (data?.openTotal ?? 0)}
          </div>
          <Link href="/incidents" className="mt-2 text-xs text-indigo-600 hover:underline">
            View all incidents →
          </Link>
        </div>

        {/* Active agents */}
        <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
          <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">
            Active Agents
          </div>
          <div className="mt-1 text-3xl font-bold text-gray-900">
            {isLoading
              ? "—"
              : `${data?.activeAgents ?? 0} / ${data?.totalAgents ?? 0}`}
          </div>
          <Link href="/agents" className="mt-2 text-xs text-indigo-600 hover:underline">
            View agents →
          </Link>
        </div>

        {/* Intel feeds */}
        <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
          <div className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">
            Intel Feeds
          </div>
          {isLoading ? (
            <div className="space-y-1">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-4 w-32 bg-gray-100 rounded animate-pulse" />
              ))}
            </div>
          ) : (
            <ul className="space-y-1">
              {(data?.feeds ?? []).map((f) => (
                <li key={f.name} className="flex items-center gap-2 text-xs text-gray-600">
                  <FeedDot status={f.status} />
                  {f.name}
                </li>
              ))}
            </ul>
          )}
          <Link href="/intel" className="mt-2 text-xs text-indigo-600 hover:underline block">
            View feeds →
          </Link>
        </div>
      </div>

      {/* Recent incidents table */}
      <section>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-gray-500 uppercase tracking-wide">
            Recent Incidents
          </h2>
          <Link href="/incidents" className="text-xs text-indigo-600 hover:underline">
            See all →
          </Link>
        </div>

        {isLoading ? (
          <div className="space-y-2">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-10 bg-gray-100 rounded animate-pulse" />
            ))}
          </div>
        ) : !data?.recentIncidents.length ? (
          <div className="text-gray-400 text-sm py-8 text-center bg-white rounded-lg border border-gray-200">
            No incidents yet. Enroll an agent to start monitoring.
          </div>
        ) : (
          <div className="bg-white rounded-lg shadow overflow-hidden">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  {["Severity", "Rule", "Host", "Status", "First seen"].map((h) => (
                    <th
                      key={h}
                      className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {data.recentIncidents.map((inc) => (
                  <tr
                    key={inc.id}
                    className="hover:bg-gray-50 cursor-pointer"
                    onClick={() => (window.location.href = `/incidents/${inc.id}`)}
                  >
                    <td className="px-4 py-2 whitespace-nowrap">
                      <SeverityBadge severity={inc.severity} />
                    </td>
                    <td className="px-4 py-2 text-sm text-gray-900 max-w-xs truncate">
                      {inc.rule_name}
                    </td>
                    <td className="px-4 py-2 text-sm font-mono text-gray-600">
                      {inc.hostname}
                    </td>
                    <td className="px-4 py-2 whitespace-nowrap">
                      <StatusBadge status={inc.status} />
                    </td>
                    <td className="px-4 py-2 text-xs text-gray-500 whitespace-nowrap">
                      {formatDistanceToNow(new Date(inc.first_seen_at), { addSuffix: true })}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
