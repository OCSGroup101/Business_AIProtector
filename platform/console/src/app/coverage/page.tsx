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
import { RefreshCw } from "lucide-react";

interface TechniqueEntry {
  technique_id: string;
  tactic: string;
  count: number;
}

interface HeatmapResponse {
  period_days: number;
  tactic_totals: Record<string, number>;
  techniques: TechniqueEntry[];
}

const PERIOD_OPTIONS = [
  { label: "7 days", value: 7 },
  { label: "30 days", value: 30 },
  { label: "90 days", value: 90 },
  { label: "365 days", value: 365 },
];

function countColor(count: number, max: number): string {
  if (max === 0) return "bg-gray-800 text-gray-500";
  const ratio = count / max;
  if (ratio >= 0.66) return "bg-red-600 text-white";
  if (ratio >= 0.33) return "bg-yellow-500 text-black";
  return "bg-green-700 text-white";
}

function tacticCardColor(count: number, max: number): string {
  if (max === 0) return "bg-gray-800 border-gray-700";
  const ratio = count / max;
  if (ratio >= 0.66) return "bg-red-900/40 border-red-800";
  if (ratio >= 0.33) return "bg-yellow-900/40 border-yellow-800";
  return "bg-green-900/30 border-green-800";
}

function tacticTextColor(count: number, max: number): string {
  if (max === 0) return "text-gray-400";
  const ratio = count / max;
  if (ratio >= 0.66) return "text-red-400";
  if (ratio >= 0.33) return "text-yellow-400";
  return "text-green-400";
}

export default function CoveragePage() {
  const [periodDays, setPeriodDays] = useState(30);

  const { data, isLoading, error, dataUpdatedAt, refetch } =
    useQuery<HeatmapResponse>({
      queryKey: ["coverage-heatmap", periodDays],
      queryFn: async () => {
        const res = await fetch(
          `/api/v1/coverage/mitre-heatmap?period_days=${periodDays}`
        );
        if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
        return res.json();
      },
      refetchInterval: 60_000,
    });

  const lastRefreshed = dataUpdatedAt
    ? new Date(dataUpdatedAt).toLocaleTimeString()
    : "—";

  const maxTacticCount = data
    ? Math.max(0, ...Object.values(data.tactic_totals))
    : 0;

  const maxTechCount = data
    ? Math.max(0, ...data.techniques.map((t) => t.count))
    : 0;

  const sortedTechniques = data
    ? [...data.techniques].sort((a, b) => b.count - a.count)
    : [];

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">MITRE ATT&CK Coverage</h1>
          <p className="text-sm text-gray-500 mt-1">
            Detection hits by tactic and technique
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-gray-500">Updated {lastRefreshed}</span>
          <button
            onClick={() => refetch()}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-300 bg-gray-800 rounded-lg hover:bg-gray-700 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      {/* Period selector */}
      <div className="flex gap-1">
        {PERIOD_OPTIONS.map((opt) => (
          <button
            key={opt.value}
            onClick={() => setPeriodDays(opt.value)}
            className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
              periodDays === opt.value
                ? "bg-orange-600 text-white"
                : "bg-gray-800 text-gray-400 hover:bg-gray-700 hover:text-gray-200"
            }`}
          >
            {opt.label}
          </button>
        ))}
      </div>

      {isLoading && (
        <div className="py-16 text-center text-gray-500 text-sm">Loading…</div>
      )}

      {error instanceof Error && (
        <div className="px-4 py-3 bg-red-900/30 border border-red-800 rounded-lg text-red-400 text-sm">
          {error.message}
        </div>
      )}

      {data && (
        <div className="space-y-6">
          {/* Tactic summary cards */}
          <div>
            <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">
              Tactic Totals
            </h2>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6">
              {Object.entries(data.tactic_totals)
                .sort(([, a], [, b]) => b - a)
                .map(([tactic, count]) => (
                  <div
                    key={tactic}
                    className={`rounded-xl border p-4 ${tacticCardColor(count, maxTacticCount)}`}
                  >
                    <div
                      className={`text-2xl font-bold tabular-nums ${tacticTextColor(count, maxTacticCount)}`}
                    >
                      {count}
                    </div>
                    <div className="text-xs text-gray-400 mt-1 leading-snug">
                      {tactic}
                    </div>
                  </div>
                ))}
            </div>
          </div>

          {/* Technique table */}
          <div className="bg-gray-900 rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-gray-800 flex items-center justify-between">
              <span className="text-sm font-medium text-gray-300">
                Techniques
              </span>
              <span className="text-xs text-gray-600">
                {sortedTechniques.length} technique
                {sortedTechniques.length !== 1 ? "s" : ""}
              </span>
            </div>

            {sortedTechniques.length === 0 ? (
              <div className="p-8 text-center text-gray-500 text-sm">
                No technique hits in this period
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-800 text-left text-xs text-gray-500 uppercase tracking-wider">
                    <th className="px-4 py-3">Technique</th>
                    <th className="px-4 py-3">Tactic</th>
                    <th className="px-4 py-3">Count</th>
                  </tr>
                </thead>
                <tbody>
                  {sortedTechniques.map((row) => (
                    <tr
                      key={row.technique_id}
                      className="border-b border-gray-800 last:border-0 hover:bg-gray-800/40 transition-colors"
                    >
                      <td className="px-4 py-3 font-mono text-xs text-gray-200">
                        {row.technique_id}
                      </td>
                      <td className="px-4 py-3 text-gray-400 text-xs">
                        {row.tactic}
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`inline-block px-2 py-0.5 rounded text-xs font-bold tabular-nums ${countColor(row.count, maxTechCount)}`}
                        >
                          {row.count}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
