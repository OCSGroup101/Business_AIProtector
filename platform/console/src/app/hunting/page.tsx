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
import { Search, Loader2 } from "lucide-react";

interface StructuredQuery {
  event_type: string;
  filters: Record<string, unknown>;
  time_range_hours: number;
  explanation: string;
}

interface HuntingResult {
  hostname: string;
  rule_name: string;
  severity: string;
  mitre_techniques: string[];
  first_seen_at: string;
}

interface HuntingResponse {
  structured_query: StructuredQuery;
  results: HuntingResult[];
  execution_time_ms: number;
}

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: "bg-red-500 text-white",
  HIGH: "bg-orange-500 text-white",
  MEDIUM: "bg-yellow-500 text-black",
  LOW: "bg-green-600 text-white",
  INFO: "bg-gray-600 text-white",
};

function fmt(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function HuntingPage() {
  const [query, setQuery] = useState("");
  const [response, setResponse] = useState<HuntingResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const hunt = useMutation({
    mutationFn: async (q: string): Promise<HuntingResponse> => {
      const res = await fetch("/api/v1/hunting/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: q }),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`${res.status}: ${text}`);
      }
      return res.json();
    },
    onSuccess: (data) => {
      setResponse(data);
      setError(null);
    },
    onError: (err: Error) => {
      setError(err.message);
      setResponse(null);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (query.trim()) hunt.mutate(query.trim());
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Threat Hunting</h1>
          <p className="text-sm text-gray-500 mt-1">
            Ask a natural language question to query endpoint telemetry
          </p>
        </div>
      </div>

      {/* Query input */}
      <form onSubmit={handleSubmit} className="space-y-3">
        <div className="flex gap-3">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder='e.g. "Show CRITICAL incidents in the last 24 hours"'
            className="flex-1 bg-gray-900 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-orange-500 transition-colors"
          />
          <button
            type="submit"
            disabled={hunt.isPending || !query.trim()}
            className="flex items-center gap-2 px-5 py-2.5 bg-orange-600 hover:bg-orange-500 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm font-medium rounded-lg transition-colors"
          >
            {hunt.isPending ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Search className="w-4 h-4" />
            )}
            {hunt.isPending ? "Hunting…" : "Hunt"}
          </button>
        </div>

        {error && (
          <div className="px-4 py-3 bg-red-900/30 border border-red-800 rounded-lg text-red-400 text-sm">
            {error}
          </div>
        )}
      </form>

      {/* Results */}
      {response && (
        <div className="space-y-5">
          {/* Structured query translation */}
          <div className="bg-gray-900 rounded-xl p-5 space-y-3">
            <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
              Query Translation
            </h2>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
              <div>
                <span className="block text-xs text-gray-600">Event Type</span>
                <span className="text-sm text-gray-200 font-mono">
                  {response.structured_query.event_type || "—"}
                </span>
              </div>
              <div>
                <span className="block text-xs text-gray-600">Time Range</span>
                <span className="text-sm text-gray-200">
                  {response.structured_query.time_range_hours}h
                </span>
              </div>
              <div>
                <span className="block text-xs text-gray-600">Exec Time</span>
                <span className="text-sm text-gray-200">
                  {response.execution_time_ms} ms
                </span>
              </div>
            </div>
            {Object.keys(response.structured_query.filters).length > 0 && (
              <div>
                <span className="block text-xs text-gray-600 mb-1">Filters</span>
                <pre className="text-xs text-gray-400 bg-gray-800 rounded px-3 py-2 overflow-x-auto">
                  {JSON.stringify(response.structured_query.filters, null, 2)}
                </pre>
              </div>
            )}
            <div>
              <span className="block text-xs text-gray-600 mb-1">Explanation</span>
              <p className="text-sm text-gray-300">
                {response.structured_query.explanation}
              </p>
            </div>
          </div>

          {/* Results table */}
          <div className="bg-gray-900 rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-gray-800 flex items-center justify-between">
              <span className="text-sm font-medium text-gray-300">Results</span>
              <span className="text-xs text-gray-600">
                {response.results.length} row{response.results.length !== 1 ? "s" : ""}
              </span>
            </div>

            {response.results.length === 0 ? (
              <div className="p-8 text-center text-gray-500 text-sm">
                No results matched this query
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-800 text-left text-xs text-gray-500 uppercase tracking-wider">
                    <th className="px-4 py-3">Severity</th>
                    <th className="px-4 py-3">Rule</th>
                    <th className="px-4 py-3">Host</th>
                    <th className="px-4 py-3">MITRE</th>
                    <th className="px-4 py-3">First Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {response.results.map((row, i) => (
                    <tr
                      key={i}
                      className="border-b border-gray-800 last:border-0 hover:bg-gray-800/40 transition-colors"
                    >
                      <td className="px-4 py-3">
                        <span
                          className={`inline-block px-2 py-0.5 rounded text-xs font-bold ${
                            SEVERITY_COLOR[row.severity] ?? "bg-gray-700 text-gray-300"
                          }`}
                        >
                          {row.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-gray-200">{row.rule_name}</td>
                      <td className="px-4 py-3 text-gray-400 font-mono text-xs">
                        {row.hostname}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {(row.mitre_techniques ?? []).slice(0, 3).map((t) => (
                            <span
                              key={t}
                              className="px-1.5 py-0.5 rounded bg-gray-700 text-gray-300 text-xs font-mono"
                            >
                              {t}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-gray-500 text-xs whitespace-nowrap">
                        {fmt(row.first_seen_at)}
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
