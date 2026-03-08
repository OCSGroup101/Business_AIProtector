"use client";

import { useQuery } from "@tanstack/react-query";
import { CheckCircle, AlertCircle, XCircle, Clock } from "lucide-react";
import { apiClient } from "@/lib/api";
import type { ThreatFeed } from "@/types";

type FeedStatus = ThreatFeed["status"];

const STATUS_CONFIG: Record<
  FeedStatus,
  { icon: React.ElementType; color: string; label: string }
> = {
  healthy: {
    icon: CheckCircle,
    color: "text-green-400",
    label: "Healthy",
  },
  degraded: {
    icon: AlertCircle,
    color: "text-yellow-400",
    label: "Degraded",
  },
  error: {
    icon: XCircle,
    color: "text-red-400",
    label: "Error",
  },
  pending: {
    icon: Clock,
    color: "text-gray-400",
    label: "Pending",
  },
};

function fmt(iso: string | null): string {
  if (!iso) return "Never";
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function fmtCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

export default function IntelligencePage() {
  const { data: feeds = [], isLoading } = useQuery<ThreatFeed[]>({
    queryKey: ["intel", "feeds"],
    queryFn: () => apiClient.get("/api/v1/intel/feeds").then((r) => r.data),
    refetchInterval: 60_000,
  });

  const totalIocs = feeds.reduce((sum, f) => sum + f.ioc_count, 0);
  const healthyCount = feeds.filter((f) => f.status === "healthy").length;
  const errorCount = feeds.filter(
    (f) => f.status === "error" || f.status === "degraded"
  ).length;

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold text-white">Threat Intelligence</h1>

      {/* Summary row */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-gray-900 rounded-xl px-4 py-4">
          <div className="text-3xl font-bold text-orange-400">{fmtCount(totalIocs)}</div>
          <div className="text-xs text-gray-500 mt-1">Total IOCs</div>
        </div>
        <div className="bg-gray-900 rounded-xl px-4 py-4">
          <div className="text-3xl font-bold text-green-400">{healthyCount}</div>
          <div className="text-xs text-gray-500 mt-1">Healthy Feeds</div>
        </div>
        <div className="bg-gray-900 rounded-xl px-4 py-4">
          <div className={`text-3xl font-bold ${errorCount > 0 ? "text-red-400" : "text-gray-600"}`}>
            {errorCount}
          </div>
          <div className="text-xs text-gray-500 mt-1">Degraded / Error</div>
        </div>
      </div>

      {/* Feed cards */}
      {isLoading ? (
        <div className="p-8 text-center text-gray-500 text-sm">Loading feeds…</div>
      ) : feeds.length === 0 ? (
        <div className="p-8 text-center text-gray-500 text-sm">No feeds configured</div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {feeds.map((feed) => (
            <FeedCard key={feed.id} feed={feed} />
          ))}
        </div>
      )}
    </div>
  );
}

function FeedCard({ feed }: { feed: ThreatFeed }) {
  const cfg = STATUS_CONFIG[feed.status];
  const Icon = cfg.icon;

  return (
    <div className="bg-gray-900 rounded-xl p-4 space-y-3">
      {/* Feed header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="text-sm font-semibold text-white">{feed.name}</div>
          <div className="text-xs text-gray-500 font-mono mt-0.5">{feed.source}</div>
        </div>
        <div className={`flex items-center gap-1.5 text-xs font-medium ${cfg.color}`}>
          <Icon className="w-3.5 h-3.5" />
          {cfg.label}
        </div>
      </div>

      {/* Error message */}
      {feed.error_message && (
        <div className="text-xs text-red-400 bg-red-900/20 rounded px-3 py-2 border border-red-900/40">
          {feed.error_message}
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-3 gap-3 text-xs">
        <div>
          <div className="text-gray-500 uppercase tracking-wider text-xs mb-1">IOCs</div>
          <div className="text-gray-200 font-bold">{fmtCount(feed.ioc_count)}</div>
        </div>
        <div>
          <div className="text-gray-500 uppercase tracking-wider text-xs mb-1">Last Ingest</div>
          <div className="text-gray-400">{fmt(feed.last_ingested_at)}</div>
        </div>
        <div>
          <div className="text-gray-500 uppercase tracking-wider text-xs mb-1">Next Run</div>
          <div className="text-gray-400">{fmt(feed.next_scheduled_at)}</div>
        </div>
      </div>
    </div>
  );
}
