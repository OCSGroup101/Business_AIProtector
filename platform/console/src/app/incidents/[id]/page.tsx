"use client";

import { useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  useQuery,
  useMutation,
  useQueryClient,
  useInfiniteQuery,
} from "@tanstack/react-query";
import {
  ArrowLeft,
  CheckCircle,
  User,
  Clock,
  ChevronDown,
  ChevronRight,
} from "lucide-react";
import { apiClient } from "@/lib/api";
import type { Incident, IncidentStatus, Severity } from "@/types";

// ─── Types ────────────────────────────────────────────────────────────────────

interface IncidentDetail extends Incident {
  summary?: string;
  containment_status?: string;
  containment_actions?: string[] | null;
  events: TimelineEvent[];
  resolved_at?: string | null;
  assigned_to?: string | null;
}

interface TimelineEvent {
  event_id: string;
  event_type: string;
  occurred_at: string;
  details: Record<string, unknown>;
}

interface TimelinePage {
  events: TimelineEvent[];
  next_cursor?: string | null;
  total: number;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

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

function fmt(iso?: string | null) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

// ─── Page ────────────────────────────────────────────────────────────────────

export default function IncidentDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const queryClient = useQueryClient();
  const incidentId = params.id;

  const [activeTab, setActiveTab] = useState<"details" | "timeline">("details");
  const [resolveNotes, setResolveNotes] = useState("");
  const [assignTo, setAssignTo] = useState("");
  const [showAssignInput, setShowAssignInput] = useState(false);

  const { data: incident, isLoading } = useQuery<IncidentDetail>({
    queryKey: ["incident", incidentId],
    queryFn: () =>
      apiClient.get(`/api/v1/incidents/${incidentId}`).then((r) => r.data),
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["incident", incidentId] });
    queryClient.invalidateQueries({ queryKey: ["incidents"] });
  };

  const resolve = useMutation({
    mutationFn: () =>
      apiClient.post(`/api/v1/incidents/${incidentId}/resolve`, {
        resolution_notes: resolveNotes || undefined,
      }),
    onSuccess: invalidate,
  });

  const assign = useMutation({
    mutationFn: () =>
      apiClient.post(`/api/v1/incidents/${incidentId}/assign`, {
        assigned_to: assignTo,
      }),
    onSuccess: () => {
      invalidate();
      setShowAssignInput(false);
      setAssignTo("");
    },
  });

  const updateStatus = useMutation({
    mutationFn: (newStatus: IncidentStatus) =>
      apiClient.patch(`/api/v1/incidents/${incidentId}`, { status: newStatus }),
    onSuccess: invalidate,
  });

  // Infinite query for timeline
  const {
    data: timelineData,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery<TimelinePage>({
    queryKey: ["incident-timeline", incidentId],
    queryFn: ({ pageParam }) =>
      apiClient
        .get(`/api/v1/incidents/${incidentId}/timeline`, {
          params: { cursor: pageParam || undefined, limit: 50 },
        })
        .then((r) => r.data),
    initialPageParam: undefined,
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    enabled: activeTab === "timeline",
  });

  const allEvents =
    timelineData?.pages.flatMap((p) => p.events) ?? [];

  if (isLoading || !incident) {
    return (
      <div className="p-6 text-gray-500 text-sm">
        {isLoading ? "Loading incident…" : "Incident not found"}
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Back */}
      <button
        onClick={() => router.push("/incidents")}
        className="flex items-center gap-2 text-sm text-gray-400 hover:text-white transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        Back to incidents
      </button>

      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <span
              className={`px-2 py-0.5 rounded text-xs font-bold ${SEVERITY_COLOR[incident.severity]}`}
            >
              {incident.severity}
            </span>
            <h1 className="text-xl font-bold text-white">{incident.rule_name}</h1>
          </div>
          <p className="text-sm text-gray-500">
            {incident.hostname} &middot; {incident.agent_id}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className={`text-sm font-medium ${STATUS_COLOR[incident.status]}`}>
            {incident.status.replace("_", " ")}
          </span>
        </div>
      </div>

      {/* Action Bar */}
      {incident.status !== "RESOLVED" && incident.status !== "FALSE_POSITIVE" && (
        <div className="flex flex-wrap items-center gap-3 p-4 bg-gray-900 rounded-xl">
          {/* Resolve */}
          {(incident.status === "INVESTIGATING" || incident.status === "CONTAINED") && (
            <div className="flex items-center gap-2 flex-1 min-w-0">
              <input
                type="text"
                placeholder="Resolution notes (optional)"
                value={resolveNotes}
                onChange={(e) => setResolveNotes(e.target.value)}
                className="flex-1 min-w-0 bg-gray-800 text-gray-200 text-sm px-3 py-1.5 rounded-lg border border-gray-700 focus:outline-none focus:border-orange-500"
              />
              <button
                onClick={() => resolve.mutate()}
                disabled={resolve.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-green-700 hover:bg-green-600 text-white text-xs rounded-lg transition-colors disabled:opacity-50"
              >
                <CheckCircle className="w-3.5 h-3.5" />
                Resolve
              </button>
            </div>
          )}

          {/* Status transitions */}
          {incident.status === "OPEN" && (
            <button
              onClick={() => updateStatus.mutate("INVESTIGATING")}
              className="px-3 py-1.5 text-xs rounded border border-yellow-800 text-yellow-400 hover:bg-yellow-900/30 transition-colors"
            >
              Investigate
            </button>
          )}
          {(incident.status === "OPEN" || incident.status === "INVESTIGATING") && (
            <button
              onClick={() => updateStatus.mutate("FALSE_POSITIVE")}
              className="px-3 py-1.5 text-xs rounded border border-gray-700 text-gray-400 hover:bg-gray-800 transition-colors"
            >
              False Positive
            </button>
          )}

          {/* Assign */}
          {showAssignInput ? (
            <div className="flex items-center gap-2">
              <input
                type="text"
                placeholder="Analyst username"
                value={assignTo}
                onChange={(e) => setAssignTo(e.target.value)}
                className="bg-gray-800 text-gray-200 text-sm px-3 py-1.5 rounded-lg border border-gray-700 focus:outline-none focus:border-orange-500"
              />
              <button
                onClick={() => assign.mutate()}
                disabled={!assignTo || assign.isPending}
                className="px-3 py-1.5 text-xs bg-orange-600 hover:bg-orange-500 text-white rounded-lg disabled:opacity-50 transition-colors"
              >
                Assign
              </button>
              <button
                onClick={() => setShowAssignInput(false)}
                className="px-3 py-1.5 text-xs text-gray-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
            </div>
          ) : (
            <button
              onClick={() => setShowAssignInput(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded border border-gray-700 text-gray-400 hover:bg-gray-800 transition-colors"
            >
              <User className="w-3.5 h-3.5" />
              {incident.assigned_to ? `Assigned: ${incident.assigned_to}` : "Assign"}
            </button>
          )}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-800">
        {(["details", "timeline"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab
                ? "border-orange-500 text-orange-400"
                : "border-transparent text-gray-500 hover:text-gray-300"
            }`}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>

      {/* Tab: Details */}
      {activeTab === "details" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <MetaCard title="Detection">
            <MetaRow label="Rule" value={incident.rule_name} />
            <MetaRow label="Severity" value={incident.severity} />
            <MetaRow
              label="MITRE"
              value={incident.mitre_techniques?.join(", ") ?? "—"}
            />
          </MetaCard>

          <MetaCard title="Status">
            <MetaRow label="Status" value={incident.status} />
            <MetaRow label="Assigned to" value={incident.assigned_to ?? "Unassigned"} />
            <MetaRow label="Resolved at" value={fmt(incident.resolved_at)} />
          </MetaCard>

          <MetaCard title="Timing">
            <MetaRow label="First seen" value={fmt(incident.first_seen_at)} />
            <MetaRow label="Last seen" value={fmt(incident.last_seen_at)} />
            <MetaRow label="Agent" value={incident.agent_id} />
          </MetaCard>

          {incident.summary && (
            <MetaCard title="Resolution notes">
              <p className="text-sm text-gray-300">{incident.summary}</p>
            </MetaCard>
          )}
        </div>
      )}

      {/* Tab: Timeline */}
      {activeTab === "timeline" && (
        <div className="space-y-2">
          {allEvents.length === 0 ? (
            <div className="p-8 text-center text-gray-500 text-sm bg-gray-900 rounded-xl">
              No timeline events
            </div>
          ) : (
            <>
              {allEvents.map((ev) => (
                <TimelineRow key={ev.event_id} event={ev} />
              ))}
              {hasNextPage && (
                <button
                  onClick={() => fetchNextPage()}
                  disabled={isFetchingNextPage}
                  className="w-full py-2 text-sm text-gray-500 hover:text-gray-300 border border-gray-800 rounded-xl transition-colors disabled:opacity-50"
                >
                  {isFetchingNextPage ? "Loading…" : "Load more"}
                </button>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function MetaCard({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="bg-gray-900 rounded-xl p-4 space-y-2">
      <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
        {title}
      </h3>
      {children}
    </div>
  );
}

function MetaRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start justify-between gap-2">
      <span className="text-xs text-gray-500 flex-shrink-0">{label}</span>
      <span className="text-xs text-gray-200 text-right font-mono break-all">{value}</span>
    </div>
  );
}

function TimelineRow({ event }: { event: TimelineEvent }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="bg-gray-900 rounded-xl overflow-hidden">
      <button
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-gray-800/40 transition-colors text-left"
      >
        {expanded ? (
          <ChevronDown className="w-3.5 h-3.5 text-gray-500 flex-shrink-0" />
        ) : (
          <ChevronRight className="w-3.5 h-3.5 text-gray-500 flex-shrink-0" />
        )}
        <div className="flex-1 min-w-0 flex items-center gap-4">
          <span className="text-xs font-mono text-gray-500 whitespace-nowrap">
            <Clock className="w-3 h-3 inline mr-1" />
            {fmt(event.occurred_at)}
          </span>
          <span className="px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 text-xs font-mono">
            {event.event_type}
          </span>
          <span className="text-xs text-gray-600 font-mono truncate">
            {event.event_id}
          </span>
        </div>
      </button>
      {expanded && (
        <div className="px-4 pb-3">
          <pre className="text-xs text-gray-400 bg-gray-800 rounded p-3 overflow-x-auto whitespace-pre-wrap">
            {JSON.stringify(event.details, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
