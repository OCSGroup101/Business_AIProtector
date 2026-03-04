"use client";
// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useParams, useRouter } from "next/navigation";
import { format } from "date-fns";
import { getIncident, updateIncident, type IncidentStatus } from "@/lib/api";
import { SeverityBadge } from "@/components/SeverityBadge";
import { StatusBadge } from "@/components/StatusBadge";

const NEXT_STATUS: Partial<Record<IncidentStatus, IncidentStatus>> = {
  OPEN: "INVESTIGATING",
  INVESTIGATING: "CONTAINED",
  CONTAINED: "RESOLVED",
};

export default function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const qc = useQueryClient();

  const { data, isLoading, isError } = useQuery({
    queryKey: ["incident", id],
    queryFn: () => getIncident(id),
  });

  const mutation = useMutation({
    mutationFn: (status: IncidentStatus) => updateIncident(id, { status }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["incident", id] });
      qc.invalidateQueries({ queryKey: ["incidents"] });
    },
  });

  if (isLoading) {
    return <div className="p-6 text-gray-500 text-sm">Loading...</div>;
  }
  if (isError || !data) {
    return (
      <div className="p-6 text-red-600 text-sm">Failed to load incident.</div>
    );
  }

  const nextStatus = NEXT_STATUS[data.status];

  return (
    <div className="p-6 max-w-4xl">
      <button
        onClick={() => router.back()}
        className="text-sm text-blue-600 hover:underline mb-4 block"
      >
        Back to incidents
      </button>

      <div className="bg-white rounded-lg shadow p-6 mb-6">
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-xl font-bold text-gray-900 mb-1">
              {data.rule_name}
            </h1>
            <p className="text-sm text-gray-500 font-mono">{data.id}</p>
          </div>
          <div className="flex gap-2 items-center">
            <SeverityBadge severity={data.severity} />
            <StatusBadge status={data.status} />
          </div>
        </div>

        <dl className="mt-4 grid grid-cols-2 gap-4 text-sm">
          <div>
            <dt className="text-gray-500 font-medium">Host</dt>
            <dd className="font-mono text-gray-900">{data.hostname}</dd>
          </div>
          <div>
            <dt className="text-gray-500 font-medium">Agent ID</dt>
            <dd className="font-mono text-gray-900 text-xs">{data.agent_id}</dd>
          </div>
          <div>
            <dt className="text-gray-500 font-medium">First seen</dt>
            <dd>{format(new Date(data.first_seen_at), "PPpp")}</dd>
          </div>
          <div>
            <dt className="text-gray-500 font-medium">Last seen</dt>
            <dd>{format(new Date(data.last_seen_at), "PPpp")}</dd>
          </div>
          {data.mitre_techniques && data.mitre_techniques.length > 0 && (
            <div className="col-span-2">
              <dt className="text-gray-500 font-medium">MITRE techniques</dt>
              <dd className="flex gap-1 flex-wrap mt-1">
                {data.mitre_techniques.map((t) => (
                  <span
                    key={t}
                    className="bg-gray-100 text-gray-700 px-2 py-0.5 rounded text-xs font-mono"
                  >
                    {t}
                  </span>
                ))}
              </dd>
            </div>
          )}
          {data.summary && (
            <div className="col-span-2">
              <dt className="text-gray-500 font-medium">Summary</dt>
              <dd className="text-gray-800 mt-1">{data.summary}</dd>
            </div>
          )}
        </dl>

        {nextStatus && (
          <div className="mt-6 flex gap-3">
            <button
              onClick={() => mutation.mutate(nextStatus)}
              disabled={mutation.isPending}
              className="px-4 py-2 bg-brand text-white text-sm font-medium rounded-md hover:bg-brand-light disabled:opacity-50 transition-colors"
            >
              {mutation.isPending ? "Updating..." : `Move to ${nextStatus}`}
            </button>
            <button
              onClick={() => mutation.mutate("FALSE_POSITIVE")}
              disabled={mutation.isPending}
              className="px-4 py-2 bg-gray-100 text-gray-700 text-sm font-medium rounded-md hover:bg-gray-200 disabled:opacity-50 transition-colors"
            >
              Mark false positive
            </button>
          </div>
        )}
      </div>

      {data.events.length > 0 && (
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-base font-semibold mb-4">Event timeline</h2>
          <ol className="space-y-3">
            {data.events.map((evt, i) => (
              <li key={i} className="flex gap-4 text-sm">
                <span className="text-gray-400 whitespace-nowrap font-mono text-xs pt-0.5">
                  {evt.occurred_at
                    ? format(new Date(evt.occurred_at as string), "HH:mm:ss")
                    : "—"}
                </span>
                <div>
                  <span className="font-medium text-gray-800">
                    {String(evt.event_type ?? evt.event_id)}
                  </span>
                  <pre className="text-xs text-gray-500 mt-1 whitespace-pre-wrap break-all bg-gray-50 rounded p-2">
                    {JSON.stringify(evt, null, 2)}
                  </pre>
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}
