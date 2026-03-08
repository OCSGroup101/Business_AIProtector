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
import { useMutation } from "@tanstack/react-query";
import { Loader2, GitMerge } from "lucide-react";

type ThreatLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

interface CorrelationInsight {
  pattern_type: string;
  confidence: number;
  affected_agents: string[];
  narrative: string;
  recommended_actions: string[];
}

interface CorrelationResponse {
  overall_threat_level: ThreatLevel;
  incidents_analyzed: number;
  summary: string;
  insights: CorrelationInsight[];
}

const THREAT_LEVEL_STYLE: Record<ThreatLevel, string> = {
  CRITICAL: "bg-red-500 text-white",
  HIGH: "bg-orange-500 text-white",
  MEDIUM: "bg-yellow-500 text-black",
  LOW: "bg-green-600 text-white",
};

const CONFIDENCE_COLOR = (pct: number): string => {
  if (pct >= 80) return "bg-red-500";
  if (pct >= 50) return "bg-yellow-500";
  return "bg-green-600";
};

export default function CorrelationPage() {
  const [result, setResult] = useState<CorrelationResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const analyze = useMutation({
    mutationFn: async (): Promise<CorrelationResponse> => {
      const res = await fetch("/api/v1/correlation/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`${res.status}: ${text}`);
      }
      return res.json();
    },
    onSuccess: (data) => {
      setResult(data);
      setError(null);
    },
    onError: (err: Error) => {
      setError(err.message);
      setResult(null);
    },
  });

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Correlation Analysis</h1>
          <p className="text-sm text-gray-500 mt-1">
            AI-powered cross-incident pattern detection across all enrolled agents
          </p>
        </div>

        <button
          onClick={() => analyze.mutate()}
          disabled={analyze.isPending}
          className="flex items-center gap-2 px-5 py-2.5 bg-orange-600 hover:bg-orange-500 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm font-medium rounded-lg transition-colors"
        >
          {analyze.isPending ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <GitMerge className="w-4 h-4" />
          )}
          {analyze.isPending ? "Analyzing…" : "Run Analysis"}
        </button>
      </div>

      {/* Loading hint */}
      {analyze.isPending && (
        <div className="flex items-center gap-3 px-5 py-4 bg-gray-900 border border-gray-700 rounded-xl">
          <Loader2 className="w-5 h-5 animate-spin text-orange-400 shrink-0" />
          <div>
            <p className="text-sm text-gray-200">Running correlation analysis…</p>
            <p className="text-xs text-gray-500 mt-0.5">
              This may take 30–120 seconds depending on incident volume
            </p>
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="px-4 py-3 bg-red-900/30 border border-red-800 rounded-lg text-red-400 text-sm">
          {error}
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-5">
          {/* Summary banner */}
          <div className="bg-gray-900 rounded-xl p-5 flex flex-col sm:flex-row sm:items-start gap-5">
            <div className="shrink-0">
              <span className="block text-xs text-gray-600 mb-1.5">
                Overall Threat Level
              </span>
              <span
                className={`inline-block px-4 py-1.5 rounded-lg text-sm font-bold tracking-wide ${
                  THREAT_LEVEL_STYLE[result.overall_threat_level]
                }`}
              >
                {result.overall_threat_level}
              </span>
            </div>

            <div className="shrink-0">
              <span className="block text-xs text-gray-600 mb-1.5">
                Incidents Analyzed
              </span>
              <span className="text-2xl font-bold text-gray-100 tabular-nums">
                {result.incidents_analyzed}
              </span>
            </div>

            <div className="flex-1">
              <span className="block text-xs text-gray-600 mb-1.5">Summary</span>
              <p className="text-sm text-gray-300 leading-relaxed">
                {result.summary}
              </p>
            </div>
          </div>

          {/* Insights list */}
          <div>
            <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">
              Insights ({result.insights.length})
            </h2>

            {result.insights.length === 0 ? (
              <div className="bg-gray-900 rounded-xl p-8 text-center text-gray-500 text-sm">
                No significant patterns detected
              </div>
            ) : (
              <div className="space-y-3">
                {result.insights.map((insight, i) => (
                  <div
                    key={i}
                    className="bg-gray-900 rounded-xl p-5 space-y-4"
                  >
                    {/* Insight header */}
                    <div className="flex items-start justify-between gap-4">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-semibold text-gray-100">
                            {insight.pattern_type}
                          </span>
                          {insight.affected_agents.length > 0 && (
                            <span className="px-2 py-0.5 rounded-full bg-gray-700 text-gray-400 text-xs">
                              {insight.affected_agents.length} agent
                              {insight.affected_agents.length !== 1 ? "s" : ""}
                            </span>
                          )}
                        </div>

                        {/* Confidence bar */}
                        <div className="flex items-center gap-2">
                          <div className="w-32 h-1.5 bg-gray-700 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${CONFIDENCE_COLOR(insight.confidence)}`}
                              style={{ width: `${Math.min(100, insight.confidence)}%` }}
                            />
                          </div>
                          <span className="text-xs text-gray-500">
                            {insight.confidence}% confidence
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Narrative */}
                    <p className="text-sm text-gray-300 leading-relaxed">
                      {insight.narrative}
                    </p>

                    {/* Affected agents */}
                    {insight.affected_agents.length > 0 && (
                      <div>
                        <span className="block text-xs text-gray-600 mb-1.5">
                          Affected Agents
                        </span>
                        <div className="flex flex-wrap gap-1.5">
                          {insight.affected_agents.map((agent) => (
                            <span
                              key={agent}
                              className="px-2 py-0.5 rounded bg-gray-800 text-gray-400 font-mono text-xs"
                            >
                              {agent}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Recommended actions */}
                    {insight.recommended_actions.length > 0 && (
                      <div>
                        <span className="block text-xs text-gray-600 mb-1.5">
                          Recommended Actions
                        </span>
                        <ul className="space-y-1">
                          {insight.recommended_actions.map((action, j) => (
                            <li
                              key={j}
                              className="flex items-start gap-2 text-sm text-gray-400"
                            >
                              <span className="mt-1.5 w-1.5 h-1.5 rounded-full bg-orange-500 shrink-0" />
                              {action}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Empty state (no run yet) */}
      {!result && !analyze.isPending && !error && (
        <div className="py-16 text-center text-gray-600 text-sm">
          Click <span className="text-gray-400">Run Analysis</span> to detect
          cross-incident patterns
        </div>
      )}
    </div>
  );
}
