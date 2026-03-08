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

import { useState, useCallback, useEffect, useRef } from "react";
import { useRouter, useParams } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  CheckCircle,
  XCircle,
  Play,
  Save,
  Trash2,
} from "lucide-react";
import { getRule, updateRule, deleteRule, validateRule, testRule } from "@/lib/api";
import type { RuleFile, RuleValidationResult, RuleTestResult } from "@/types";

function fmt(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function RuleDetailPage() {
  const router = useRouter();
  const params = useParams();
  const id = params.id as string;
  const queryClient = useQueryClient();

  const [content, setContent] = useState("");
  const [validation, setValidation] = useState<RuleValidationResult | null>(null);
  const [validating, setValidating] = useState(false);
  const [fixtureText, setFixtureText] = useState(
    JSON.stringify(
      [{ event_type: "process_create", image: "cmd.exe", parent_image: "winword.exe" }],
      null,
      2
    )
  );
  const [testResult, setTestResult] = useState<RuleTestResult | null>(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [contentLoaded, setContentLoaded] = useState(false);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const { data: rule, isLoading, isError } = useQuery<RuleFile>({
    queryKey: ["rules", id],
    queryFn: () => getRule(id),
  });

  // Populate editor once rule loads
  useEffect(() => {
    if (rule && !contentLoaded) {
      setContent(rule.content_toml ?? "");
      setContentLoaded(true);
    }
  }, [rule, contentLoaded]);

  const runValidate = useCallback(async (toml: string) => {
    setValidating(true);
    try {
      const res = await validateRule(toml);
      setValidation(res.data as RuleValidationResult);
    } catch {
      setValidation({ valid: false, errors: ["Validation request failed"] });
    } finally {
      setValidating(false);
    }
  }, []);

  useEffect(() => {
    if (!contentLoaded) return;
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      runValidate(content);
    }, 500);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [content, contentLoaded, runValidate]);

  const save = useMutation({
    mutationFn: () => updateRule(id, { content_toml: content }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["rules"] });
      queryClient.invalidateQueries({ queryKey: ["rules", id] });
    },
  });

  const toggleEnabled = useMutation({
    mutationFn: (enabled: boolean) =>
      import("@/lib/api").then(({ apiClient }) =>
        apiClient.patch(`/api/v1/rules/${id}`, { enabled })
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["rules"] });
      queryClient.invalidateQueries({ queryKey: ["rules", id] });
    },
  });

  const remove = useMutation({
    mutationFn: () => deleteRule(id),
    onSuccess: () => router.push("/rules"),
  });

  const runTest = useMutation({
    mutationFn: async () => {
      let events: unknown[];
      try {
        events = JSON.parse(fixtureText) as unknown[];
      } catch {
        throw new Error("Fixture JSON is invalid");
      }
      const res = await testRule(content, events);
      return res.data as RuleTestResult;
    },
    onSuccess: (data) => setTestResult(data),
    onError: (err: Error) =>
      setTestResult({
        matched: false,
        match_count: 0,
        matched_events: [],
        errors: [err.message],
      }),
  });

  if (isLoading) {
    return (
      <div className="p-8 text-center text-gray-500 text-sm">Loading...</div>
    );
  }

  if (isError || !rule) {
    return (
      <div className="p-8 text-center text-gray-500 text-sm">
        Error loading data
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Top bar */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800 bg-gray-950">
        <div className="flex items-center gap-3 min-w-0">
          <button
            onClick={() => router.push("/rules")}
            className="text-gray-500 hover:text-gray-300 transition-colors flex-shrink-0"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div className="min-w-0">
            <h1 className="text-lg font-semibold text-white truncate">
              {rule.name}
            </h1>
            <div className="flex items-center gap-3 text-xs text-gray-500 mt-0.5">
              <span className="font-mono">{rule.rule_id}</span>
              <span>Pack: {rule.pack}</span>
              <span>Modified: {fmt(rule.last_modified)}</span>
              {rule.valid ? (
                <span className="flex items-center gap-1 text-green-400">
                  <CheckCircle className="w-3 h-3" />
                  Valid
                </span>
              ) : (
                <span className="flex items-center gap-1 text-red-400">
                  <XCircle className="w-3 h-3" />
                  Invalid
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          {/* Enable / Disable toggle */}
          <button
            onClick={() => toggleEnabled.mutate(!rule.enabled)}
            disabled={toggleEnabled.isPending}
            className={`px-3 py-1.5 text-xs rounded-lg border transition-colors ${
              rule.enabled
                ? "border-orange-800 text-orange-400 hover:bg-orange-900/20"
                : "border-green-800 text-green-400 hover:bg-green-900/20"
            }`}
          >
            {toggleEnabled.isPending
              ? "..."
              : rule.enabled
              ? "Disable"
              : "Enable"}
          </button>

          {/* Delete */}
          {showDeleteConfirm ? (
            <div className="flex items-center gap-1">
              <span className="text-xs text-gray-400">Confirm?</span>
              <button
                onClick={() => remove.mutate()}
                disabled={remove.isPending}
                className="px-2 py-1 text-xs bg-red-600 hover:bg-red-700 text-white rounded transition-colors"
              >
                {remove.isPending ? "Deleting..." : "Yes, delete"}
              </button>
              <button
                onClick={() => setShowDeleteConfirm(false)}
                className="px-2 py-1 text-xs bg-gray-800 hover:bg-gray-700 text-gray-400 rounded transition-colors"
              >
                Cancel
              </button>
            </div>
          ) : (
            <button
              onClick={() => setShowDeleteConfirm(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-red-400 border border-red-900 rounded-lg hover:bg-red-900/20 transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Delete
            </button>
          )}

          {/* Save */}
          <button
            onClick={() => save.mutate()}
            disabled={save.isPending || (validation !== null && !validation.valid)}
            className="flex items-center gap-2 px-4 py-2 bg-orange-500 hover:bg-orange-600 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm font-medium rounded-lg transition-colors"
          >
            <Save className="w-4 h-4" />
            {save.isPending ? "Saving..." : "Save"}
          </button>
        </div>
      </div>

      {/* Split pane */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left: TOML editor */}
        <div className="flex-1 flex flex-col border-r border-gray-800 min-w-0">
          <div className="px-4 py-2 bg-gray-900 border-b border-gray-800 flex items-center justify-between">
            <span className="text-xs text-gray-500 font-medium uppercase tracking-wider">
              Rule TOML
            </span>
            <ValidationBadge validation={validation} validating={validating} />
          </div>
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            spellCheck={false}
            className="flex-1 w-full bg-gray-950 text-gray-200 font-mono text-sm p-4 resize-none focus:outline-none leading-relaxed"
            placeholder="Rule TOML content..."
          />
        </div>

        {/* Right: validation + test */}
        <div className="w-96 flex flex-col bg-gray-900 overflow-auto">
          {/* Validation panel */}
          <div className="p-4 border-b border-gray-800">
            <div className="text-xs text-gray-500 font-medium uppercase tracking-wider mb-3">
              Validation
            </div>
            {validating ? (
              <div className="text-xs text-gray-500">Validating...</div>
            ) : validation === null ? (
              <div className="text-xs text-gray-500">Type to validate</div>
            ) : validation.valid ? (
              <div className="flex items-center gap-2 text-green-400 text-sm">
                <CheckCircle className="w-4 h-4" />
                Valid rule
              </div>
            ) : (
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-red-400 text-sm">
                  <XCircle className="w-4 h-4" />
                  Validation errors
                </div>
                {validation.errors.map((err, i) => (
                  <div
                    key={i}
                    className="text-xs text-red-300 bg-red-900/20 border border-red-900 rounded px-2 py-1.5 font-mono"
                  >
                    {err}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Test with fixture */}
          <div className="p-4 flex flex-col gap-3">
            <div className="text-xs text-gray-500 font-medium uppercase tracking-wider">
              Test with Fixture
            </div>
            <div className="text-xs text-gray-600">
              Paste a JSON array of events to test the rule against:
            </div>
            <textarea
              value={fixtureText}
              onChange={(e) => setFixtureText(e.target.value)}
              spellCheck={false}
              rows={8}
              className="w-full bg-gray-950 text-gray-300 font-mono text-xs p-3 rounded-lg border border-gray-800 focus:outline-none focus:border-orange-500 resize-none leading-relaxed"
              placeholder='[{"event_type": "process_create", ...}]'
            />
            <button
              onClick={() => runTest.mutate()}
              disabled={runTest.isPending}
              className="flex items-center justify-center gap-2 px-3 py-2 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-gray-300 text-sm rounded-lg transition-colors"
            >
              <Play className="w-3.5 h-3.5" />
              {runTest.isPending ? "Running..." : "Run Test"}
            </button>

            {testResult && (
              <div className="space-y-2">
                {testResult.errors.length > 0 ? (
                  <div className="text-xs text-red-400 bg-red-900/20 border border-red-900 rounded px-2 py-1.5">
                    {testResult.errors.join("; ")}
                  </div>
                ) : testResult.matched ? (
                  <div className="text-xs text-green-400 bg-green-900/20 border border-green-900 rounded px-2 py-1.5">
                    Matched {testResult.match_count} event
                    {testResult.match_count !== 1 ? "s" : ""}
                  </div>
                ) : (
                  <div className="text-xs text-yellow-400 bg-yellow-900/20 border border-yellow-900 rounded px-2 py-1.5">
                    No match — rule did not fire on the provided events
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function ValidationBadge({
  validation,
  validating,
}: {
  validation: RuleValidationResult | null;
  validating: boolean;
}) {
  if (validating) {
    return <span className="text-xs text-gray-500 italic">validating...</span>;
  }
  if (!validation) return null;
  return validation.valid ? (
    <span className="flex items-center gap-1 text-xs text-green-400">
      <CheckCircle className="w-3 h-3" />
      Valid
    </span>
  ) : (
    <span className="flex items-center gap-1 text-xs text-red-400">
      <XCircle className="w-3 h-3" />
      {validation.errors.length} error{validation.errors.length !== 1 ? "s" : ""}
    </span>
  );
}
