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
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Download, FileText, Loader2, X } from "lucide-react";
import { listReports, generateReport, getReportDownloadUrl } from "@/lib/api";
import type { Report, ReportType, ReportStatus } from "@/types";

const REPORT_TYPE_LABELS: Record<ReportType, string> = {
  incident_summary: "Incident Summary",
  executive_summary: "Executive Summary",
};

const PERIOD_OPTIONS = [
  { label: "Last 7 days", value: 7 },
  { label: "Last 30 days", value: 30 },
  { label: "Last 90 days", value: 90 },
];

const STATUS_STYLE: Record<ReportStatus, string> = {
  pending: "text-gray-400",
  generating: "text-yellow-400",
  complete: "text-green-400",
  failed: "text-red-400",
};

function fmt(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function ReportsPage() {
  const queryClient = useQueryClient();
  const [showModal, setShowModal] = useState(false);
  const [reportType, setReportType] = useState<ReportType>("incident_summary");
  const [periodDays, setPeriodDays] = useState(30);

  const { data: reports = [], isLoading, isError } = useQuery<Report[]>({
    queryKey: ["reports"],
    queryFn: listReports,
    // Auto-refresh every 10s while any report is generating
    refetchInterval: (query) => {
      const data = query.state.data as Report[] | undefined;
      if (!data) return 10_000;
      const hasGenerating = data.some(
        (r) => r.status === "pending" || r.status === "generating"
      );
      return hasGenerating ? 10_000 : false;
    },
  });

  const generate = useMutation({
    mutationFn: () => generateReport(reportType, periodDays),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["reports"] });
      setShowModal(false);
    },
  });

  const hasGenerating = reports.some(
    (r) => r.status === "pending" || r.status === "generating"
  );

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Reports</h1>
          {hasGenerating && (
            <div className="flex items-center gap-1.5 text-xs text-yellow-400 mt-1">
              <Loader2 className="w-3 h-3 animate-spin" />
              Report generating — auto-refreshing every 10s
            </div>
          )}
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-orange-500 hover:bg-orange-600 text-white text-sm font-medium rounded-lg transition-colors"
        >
          <FileText className="w-4 h-4" />
          Generate Report
        </button>
      </div>

      {/* Reports table */}
      <div className="bg-gray-900 rounded-xl overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-gray-500 text-sm">Loading...</div>
        ) : isError ? (
          <div className="p-8 text-center text-gray-500 text-sm">
            Error loading data
          </div>
        ) : reports.length === 0 ? (
          <div className="p-12 text-center text-gray-500 text-sm rounded-xl">
            No reports yet. Generate your first report.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-xs text-gray-500 uppercase tracking-wider">
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Period</th>
                <th className="px-4 py-3">Created</th>
                <th className="px-4 py-3">Completed</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3 text-right">Download</th>
              </tr>
            </thead>
            <tbody>
              {reports.map((report) => (
                <ReportRow key={report.id} report={report} />
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Generate modal */}
      {showModal && (
        <GenerateModal
          reportType={reportType}
          onTypeChange={setReportType}
          periodDays={periodDays}
          onPeriodChange={setPeriodDays}
          onClose={() => setShowModal(false)}
          onGenerate={() => generate.mutate()}
          isPending={generate.isPending}
          error={generate.error as Error | null}
        />
      )}
    </div>
  );
}

function ReportRow({ report }: { report: Report }) {
  return (
    <tr className="border-b border-gray-800 last:border-0 hover:bg-gray-800/30 transition-colors">
      <td className="px-4 py-3 text-gray-200">
        {REPORT_TYPE_LABELS[report.type] ?? report.type}
      </td>
      <td className="px-4 py-3 text-gray-400 text-xs">
        {report.period_days} days
      </td>
      <td className="px-4 py-3 text-gray-500 text-xs whitespace-nowrap">
        {fmt(report.created_at)}
      </td>
      <td className="px-4 py-3 text-gray-500 text-xs whitespace-nowrap">
        {report.completed_at ? fmt(report.completed_at) : "—"}
      </td>
      <td className="px-4 py-3">
        <div className="flex items-center gap-1.5">
          {(report.status === "pending" || report.status === "generating") && (
            <Loader2 className="w-3 h-3 animate-spin text-yellow-400" />
          )}
          <span
            className={`text-xs font-medium capitalize ${STATUS_STYLE[report.status]}`}
          >
            {report.status}
          </span>
        </div>
        {report.error_message && (
          <div className="text-xs text-red-400 mt-0.5 truncate max-w-xs">
            {report.error_message}
          </div>
        )}
      </td>
      <td className="px-4 py-3 text-right">
        {report.status === "complete" ? (
          <a
            href={getReportDownloadUrl(report.id)}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center justify-end gap-1.5 text-xs text-orange-400 hover:text-orange-300 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            Download
          </a>
        ) : (
          <span className="text-xs text-gray-700">—</span>
        )}
      </td>
    </tr>
  );
}

function GenerateModal({
  reportType,
  onTypeChange,
  periodDays,
  onPeriodChange,
  onClose,
  onGenerate,
  isPending,
  error,
}: {
  reportType: ReportType;
  onTypeChange: (t: ReportType) => void;
  periodDays: number;
  onPeriodChange: (d: number) => void;
  onClose: () => void;
  onGenerate: () => void;
  isPending: boolean;
  error: Error | null;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-md p-6 shadow-2xl">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-lg font-semibold text-white">Generate Report</h2>
          <button
            onClick={onClose}
            className="text-gray-500 hover:text-gray-300 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="space-y-4">
          {/* Report type */}
          <div>
            <label className="block text-xs text-gray-400 mb-1.5 font-medium">
              Report Type
            </label>
            <select
              value={reportType}
              onChange={(e) => onTypeChange(e.target.value as ReportType)}
              className="w-full px-3 py-2 bg-gray-800 border border-gray-700 text-gray-200 text-sm rounded-lg focus:outline-none focus:border-orange-500"
            >
              <option value="incident_summary">Incident Summary</option>
              <option value="executive_summary">Executive Summary</option>
            </select>
          </div>

          {/* Period */}
          <div>
            <label className="block text-xs text-gray-400 mb-1.5 font-medium">
              Period
            </label>
            <div className="flex gap-2">
              {PERIOD_OPTIONS.map(({ label, value }) => (
                <button
                  key={value}
                  onClick={() => onPeriodChange(value)}
                  className={`flex-1 py-2 text-sm rounded-lg border transition-colors ${
                    periodDays === value
                      ? "border-orange-500 bg-orange-500/10 text-orange-400"
                      : "border-gray-700 text-gray-400 hover:border-gray-600 hover:text-gray-300"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          {error && (
            <div className="text-xs text-red-400 bg-red-900/20 border border-red-900 rounded px-3 py-2">
              {error.message}
            </div>
          )}
        </div>

        <div className="flex justify-end gap-2 mt-6">
          <button
            onClick={onClose}
            disabled={isPending}
            className="px-4 py-2 text-sm text-gray-400 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onGenerate}
            disabled={isPending}
            className="flex items-center gap-2 px-4 py-2 bg-orange-500 hover:bg-orange-600 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm font-medium rounded-lg transition-colors"
          >
            {isPending && <Loader2 className="w-4 h-4 animate-spin" />}
            {isPending ? "Generating..." : "Generate"}
          </button>
        </div>
      </div>
    </div>
  );
}
