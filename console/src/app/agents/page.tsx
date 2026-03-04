"use client";
// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.

import { useQuery } from "@tanstack/react-query";
import { formatDistanceToNow } from "date-fns";
import { listAgents } from "@/lib/api";
import clsx from "clsx";

const STATE_CLASSES: Record<string, string> = {
  ACTIVE:    "bg-green-100 text-green-700",
  ENROLLING: "bg-yellow-100 text-yellow-700",
  ISOLATED:  "bg-red-100 text-red-700",
  UPDATING:  "bg-blue-100 text-blue-700",
};

export default function AgentsPage() {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["agents"],
    queryFn: listAgents,
  });

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-6">
        Agents
        {data && (
          <span className="ml-2 text-base font-normal text-gray-400">
            ({data.length})
          </span>
        )}
      </h1>

      {isLoading && (
        <div className="text-gray-500 text-sm py-12 text-center">
          Loading agents...
        </div>
      )}

      {isError && (
        <div className="text-red-600 text-sm py-4 px-4 bg-red-50 rounded-md border border-red-200">
          {error instanceof Error ? error.message : "Failed to load agents"}
        </div>
      )}

      {data && data.length === 0 && (
        <div className="text-gray-500 text-sm py-12 text-center">
          No agents enrolled. Run{" "}
          <code className="bg-gray-100 px-1 rounded text-xs">
            openclaw-agent --enroll &lt;token&gt;
          </code>{" "}
          on an endpoint.
        </div>
      )}

      {data && data.length > 0 && (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                {[
                  "State",
                  "Hostname",
                  "OS",
                  "Agent version",
                  "Policy",
                  "Last heartbeat",
                ].map((h) => (
                  <th
                    key={h}
                    className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {data.map((agent) => (
                <tr key={agent.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span
                      className={clsx(
                        "inline-flex px-2 py-0.5 rounded text-xs font-medium",
                        STATE_CLASSES[agent.state] ?? "bg-gray-100 text-gray-500"
                      )}
                    >
                      {agent.state}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm font-mono font-medium text-gray-900">
                    {agent.hostname}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600">
                    {agent.os_platform}
                    <div className="text-xs text-gray-400 truncate max-w-xs">
                      {agent.os_version}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500 font-mono">
                    {agent.agent_version}
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500">
                    v{agent.policy_version}
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500 whitespace-nowrap">
                    {agent.last_heartbeat_at
                      ? formatDistanceToNow(new Date(agent.last_heartbeat_at), {
                          addSuffix: true,
                        })
                      : "Never"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
