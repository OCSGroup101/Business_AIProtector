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

import { useRouter } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, CheckCircle, XCircle } from "lucide-react";
import { listRules } from "@/lib/api";
import type { RuleFile, RuleMatchType, Severity } from "@/types";

const SEVERITY_DOT: Record<Severity, string> = {
  CRITICAL: "bg-red-500",
  HIGH: "bg-orange-500",
  MEDIUM: "bg-yellow-500",
  LOW: "bg-green-500",
  INFO: "bg-gray-500",
};

const MATCH_TYPE_LABEL: Record<RuleMatchType, string> = {
  ioc: "IOC",
  behavioral: "Behavioral",
  heuristic: "Heuristic",
  sequence: "Sequence",
  threshold: "Threshold",
};

function fmt(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function RulesPage() {
  const router = useRouter();
  const queryClient = useQueryClient();

  const { data: rules = [], isLoading, isError } = useQuery<RuleFile[]>({
    queryKey: ["rules"],
    queryFn: listRules,
    refetchInterval: 60_000,
  });

  const patchEnabled = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      import("@/lib/api").then(({ apiClient }) =>
        apiClient.patch(`/api/v1/rules/${id}`, { enabled })
      ),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["rules"] }),
  });

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Detection Rules</h1>
        <button
          onClick={() => router.push("/rules/new")}
          className="flex items-center gap-2 px-4 py-2 bg-orange-500 hover:bg-orange-600 text-white text-sm font-medium rounded-lg transition-colors"
        >
          <Plus className="w-4 h-4" />
          New Rule
        </button>
      </div>

      {/* Summary counts */}
      {!isLoading && !isError && rules.length > 0 && (
        <div className="flex gap-4 text-xs text-gray-500">
          <span>{rules.length} rules</span>
          <span>{rules.filter((r) => r.enabled).length} enabled</span>
          <span>{rules.filter((r) => r.valid).length} valid</span>
        </div>
      )}

      {/* Table */}
      <div className="bg-gray-900 rounded-xl overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-gray-500 text-sm">Loading...</div>
        ) : isError ? (
          <div className="p-8 text-center text-gray-500 text-sm">
            Error loading data
          </div>
        ) : rules.length === 0 ? (
          <div className="p-12 text-center text-gray-500 text-sm rounded-xl">
            No rules found.{" "}
            <button
              onClick={() => router.push("/rules/new")}
              className="text-orange-400 hover:text-orange-300 underline"
            >
              Create your first rule.
            </button>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-xs text-gray-500 uppercase tracking-wider">
                <th className="px-4 py-3">ID</th>
                <th className="px-4 py-3">Name</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Pack</th>
                <th className="px-4 py-3">Last Modified</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3 text-right">Enabled</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr
                  key={rule.id}
                  onClick={() => router.push(`/rules/${rule.id}`)}
                  className="border-b border-gray-800 last:border-0 hover:bg-gray-800/40 transition-colors cursor-pointer"
                >
                  <td className="px-4 py-3 font-mono text-xs text-gray-500">
                    {rule.rule_id}
                  </td>
                  <td className="px-4 py-3 text-gray-200">{rule.name}</td>
                  <td className="px-4 py-3">
                    <span className="px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 text-xs">
                      {MATCH_TYPE_LABEL[rule.match_type]}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`w-2 h-2 rounded-full flex-shrink-0 ${SEVERITY_DOT[rule.severity]}`}
                      />
                      <span className="text-gray-400 text-xs">
                        {rule.severity}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-gray-500 text-xs">
                    {rule.pack}
                  </td>
                  <td className="px-4 py-3 text-gray-500 text-xs whitespace-nowrap">
                    {fmt(rule.last_modified)}
                  </td>
                  <td className="px-4 py-3">
                    {rule.valid ? (
                      <span className="flex items-center gap-1 text-green-400 text-xs">
                        <CheckCircle className="w-3.5 h-3.5" />
                        Valid
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-red-400 text-xs">
                        <XCircle className="w-3.5 h-3.5" />
                        Invalid
                      </span>
                    )}
                  </td>
                  <td
                    className="px-4 py-3 text-right"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <Toggle
                      enabled={rule.enabled}
                      onChange={(enabled) =>
                        patchEnabled.mutate({ id: rule.id, enabled })
                      }
                    />
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

function Toggle({
  enabled,
  onChange,
}: {
  enabled: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <button
      onClick={() => onChange(!enabled)}
      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
        enabled ? "bg-orange-500" : "bg-gray-700"
      }`}
    >
      <span
        className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
          enabled ? "translate-x-4" : "translate-x-0.5"
        }`}
      />
    </button>
  );
}
