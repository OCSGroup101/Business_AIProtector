"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, ChevronRight } from "lucide-react";
import { apiClient } from "@/lib/api";
import type { Policy, DetectionRule, Severity } from "@/types";

const SEVERITY_DOT: Record<Severity, string> = {
  CRITICAL: "bg-red-500",
  HIGH: "bg-orange-500",
  MEDIUM: "bg-yellow-500",
  LOW: "bg-green-500",
  INFO: "bg-gray-500",
};

const MATCH_TYPE_LABEL: Record<DetectionRule["match_type"], string> = {
  ioc: "IOC",
  behavioral: "Behavioral",
  heuristic: "Heuristic",
  sequence: "Sequence",
  threshold: "Threshold",
};

export default function PoliciesPage() {
  const [expanded, setExpanded] = useState<string | null>(null);

  const { data: policies = [], isLoading } = useQuery<Policy[]>({
    queryKey: ["policies"],
    queryFn: () => apiClient.get("/api/v1/policies").then((r) => r.data),
  });

  return (
    <div className="p-6 space-y-4">
      <h1 className="text-2xl font-bold text-white">Policies</h1>

      {isLoading ? (
        <div className="p-8 text-center text-gray-500 text-sm">Loading…</div>
      ) : policies.length === 0 ? (
        <div className="p-8 text-center text-gray-500 text-sm">No policies found</div>
      ) : (
        <div className="space-y-3">
          {policies.map((policy) => (
            <PolicyCard
              key={policy.id}
              policy={policy}
              isExpanded={expanded === policy.id}
              onToggle={() =>
                setExpanded((prev) => (prev === policy.id ? null : policy.id))
              }
            />
          ))}
        </div>
      )}
    </div>
  );
}

function PolicyCard({
  policy,
  isExpanded,
  onToggle,
}: {
  policy: Policy;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const queryClient = useQueryClient();

  const { data: rules = [], isLoading: rulesLoading } = useQuery<DetectionRule[]>({
    queryKey: ["policies", policy.id, "rules"],
    queryFn: () =>
      apiClient.get(`/api/v1/policies/${policy.id}/rules`).then((r) => r.data),
    enabled: isExpanded,
  });

  const toggleRule = useMutation({
    mutationFn: ({ ruleId, enabled }: { ruleId: string; enabled: boolean }) =>
      apiClient.patch(`/api/v1/policies/${policy.id}/rules/${ruleId}`, { enabled }),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["policies", policy.id, "rules"] }),
  });

  const enabledCount = rules.filter((r) => r.enabled).length;

  return (
    <div className="bg-gray-900 rounded-xl overflow-hidden">
      {/* Policy header */}
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 px-4 py-4 hover:bg-gray-800/50 transition-colors text-left"
      >
        {isExpanded ? (
          <ChevronDown className="w-4 h-4 text-gray-500 flex-shrink-0" />
        ) : (
          <ChevronRight className="w-4 h-4 text-gray-500 flex-shrink-0" />
        )}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-white">{policy.name}</span>
            {policy.is_default && (
              <span className="px-1.5 py-0.5 rounded text-xs bg-orange-500/20 text-orange-400 border border-orange-800">
                Default
              </span>
            )}
          </div>
          <div className="text-xs text-gray-500 mt-0.5">
            v{policy.version} · {policy.agent_count} agent
            {policy.agent_count !== 1 ? "s" : ""}
            {isExpanded && rules.length > 0
              ? ` · ${enabledCount}/${rules.length} rules enabled`
              : ""}
          </div>
        </div>
      </button>

      {/* Expanded rules list */}
      {isExpanded && (
        <div className="border-t border-gray-800">
          {rulesLoading ? (
            <div className="px-4 py-6 text-center text-gray-500 text-sm">
              Loading rules…
            </div>
          ) : rules.length === 0 ? (
            <div className="px-4 py-6 text-center text-gray-500 text-sm">
              No detection rules in this policy
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-800">
                  <th className="px-4 py-2">Rule</th>
                  <th className="px-4 py-2">Type</th>
                  <th className="px-4 py-2">Severity</th>
                  <th className="px-4 py-2">MITRE</th>
                  <th className="px-4 py-2 text-right">Enabled</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr
                    key={rule.id}
                    className="border-b border-gray-800/50 last:border-0"
                  >
                    <td className="px-4 py-2.5">
                      <div className="text-gray-200 text-xs">{rule.name}</div>
                      <div className="text-gray-600 text-xs font-mono">{rule.rule_id}</div>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className="px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 text-xs">
                        {MATCH_TYPE_LABEL[rule.match_type]}
                      </span>
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`w-2 h-2 rounded-full ${SEVERITY_DOT[rule.severity]}`}
                        />
                        <span className="text-gray-400 text-xs">{rule.severity}</span>
                      </div>
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex gap-1 flex-wrap">
                        {(rule.mitre_techniques ?? []).slice(0, 2).map((t) => (
                          <span
                            key={t}
                            className="px-1 py-0.5 rounded bg-gray-800 text-gray-400 text-xs font-mono"
                          >
                            {t}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <Toggle
                        enabled={rule.enabled}
                        onChange={(enabled) =>
                          toggleRule.mutate({ ruleId: rule.id, enabled })
                        }
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
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
