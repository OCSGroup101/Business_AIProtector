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
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { ArrowLeft, CheckCircle, XCircle, Play, Save } from "lucide-react";
import { validateRule, testRule, createRule } from "@/lib/api";
import type { RuleValidationResult, RuleTestResult } from "@/types";

const TEMPLATES: Record<string, { label: string; toml: string }> = {
  behavioral: {
    label: "Behavioral (process)",
    toml: `[rule]
id = "PROC-0001"
name = "Suspicious Process Spawn"
pack = "custom"
severity = "HIGH"
match_type = "behavioral"
mitre_techniques = ["T1059"]
description = "Detects suspicious child process creation"

[behavioral]
parent_image = "winword.exe"
child_image_pattern = "cmd.exe|powershell.exe"
`,
  },
  heuristic: {
    label: "Heuristic (Lua)",
    toml: `[rule]
id = "LUA-0001"
name = "High Entropy PE Injection"
pack = "custom"
severity = "HIGH"
match_type = "heuristic"
mitre_techniques = ["T1055"]
description = "Lua-based heuristic for PE injection patterns"

[heuristic]
script = """
function evaluate(event)
  if event.entropy ~= nil and event.entropy > 7.2 then
    return true, "high entropy write: " .. tostring(event.entropy)
  end
  return false, nil
end
"""
`,
  },
  ioc: {
    label: "IOC (hash)",
    toml: `[rule]
id = "IOC-0001"
name = "Known Malware Hash"
pack = "custom"
severity = "CRITICAL"
match_type = "ioc"
mitre_techniques = ["T1204"]
description = "Matches known malware SHA-256 hashes"

[ioc]
field = "sha256"
values = [
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
]
`,
  },
  sequence: {
    label: "Sequence",
    toml: `[rule]
id = "SEQ-0001"
name = "Recon Then Lateral Movement"
pack = "custom"
severity = "HIGH"
match_type = "sequence"
mitre_techniques = ["T1018", "T1021"]
description = "Detect recon followed by lateral movement within 5 minutes"

[[sequence.steps]]
match_type = "behavioral"
image_pattern = "net.exe|nltest.exe"

[[sequence.steps]]
match_type = "behavioral"
image_pattern = "psexec.exe|wmic.exe"

[sequence]
within_seconds = 300
`,
  },
};

export default function NewRulePage() {
  const router = useRouter();
  const [content, setContent] = useState(TEMPLATES.behavioral.toml);
  const [selectedTemplate, setSelectedTemplate] = useState("behavioral");
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
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

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
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      runValidate(content);
    }, 500);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [content, runValidate]);

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

  const save = useMutation({
    mutationFn: () => createRule({ content_toml: content }),
    onSuccess: () => router.push("/rules"),
  });

  return (
    <div className="flex flex-col h-full">
      {/* Top bar */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800 bg-gray-950">
        <div className="flex items-center gap-3">
          <button
            onClick={() => router.push("/rules")}
            className="text-gray-500 hover:text-gray-300 transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <h1 className="text-lg font-semibold text-white">New Rule</h1>
          {/* Template selector */}
          <select
            value={selectedTemplate}
            onChange={(e) => {
              setSelectedTemplate(e.target.value);
              setContent(TEMPLATES[e.target.value].toml);
            }}
            className="ml-4 px-3 py-1.5 bg-gray-800 border border-gray-700 text-gray-300 text-sm rounded-lg focus:outline-none focus:border-orange-500"
          >
            {Object.entries(TEMPLATES).map(([key, { label }]) => (
              <option key={key} value={key}>
                {label}
              </option>
            ))}
          </select>
        </div>
        <button
          onClick={() => save.mutate()}
          disabled={save.isPending || (validation !== null && !validation.valid)}
          className="flex items-center gap-2 px-4 py-2 bg-orange-500 hover:bg-orange-600 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm font-medium rounded-lg transition-colors"
        >
          <Save className="w-4 h-4" />
          {save.isPending ? "Saving..." : "Save Rule"}
        </button>
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
            placeholder="Enter rule TOML here..."
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
    return (
      <span className="text-xs text-gray-500 italic">validating...</span>
    );
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
