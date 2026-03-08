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
import { useQuery, useMutation } from "@tanstack/react-query";
import { Copy, Check, KeyRound, Terminal } from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { getMspTenants, generateEnrollmentToken } from "@/lib/api";
import type { TenantSummary } from "@/types";

export default function MspEnrollmentPage() {
  const [selectedTenantId, setSelectedTenantId] = useState<string>("");
  const [generatedToken, setGeneratedToken] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const { data: tenants = [], isLoading } = useQuery<TenantSummary[]>({
    queryKey: ["msp-tenants"],
    queryFn: getMspTenants,
  });

  const generate = useMutation({
    mutationFn: () => generateEnrollmentToken(selectedTenantId),
    onSuccess: (data) => {
      setGeneratedToken(data.token);
    },
  });

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const selectedTenant = tenants.find((t) => t.id === selectedTenantId);

  const installCmd = generatedToken
    ? `curl -fsSL https://get.omniprotect.io/agent | ENROLLMENT_TOKEN="${generatedToken}" bash`
    : "";

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Enrollment</h1>
        <p className="text-sm text-slate-500 mt-1">
          Generate enrollment tokens to onboard agents for a client.
        </p>
      </div>

      {/* Token generator */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-5 space-y-4">
        <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
          <KeyRound className="w-4 h-4 text-blue-400" />
          Generate Enrollment Token
        </h2>

        <div>
          <label className="block text-xs font-medium text-slate-400 mb-1.5">
            Select Client
          </label>
          <select
            value={selectedTenantId}
            onChange={(e) => {
              setSelectedTenantId(e.target.value);
              setGeneratedToken(null);
            }}
            disabled={isLoading}
            className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-sm text-slate-200 focus:outline-none focus:ring-1 focus:ring-blue-500 disabled:opacity-50"
          >
            <option value="">Select a client...</option>
            {tenants.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </select>
        </div>

        <Button
          onClick={() => generate.mutate()}
          loading={generate.isPending}
          disabled={!selectedTenantId}
          size="sm"
        >
          Generate Token
        </Button>

        {generatedToken && (
          <div className="space-y-3 pt-2 border-t border-slate-700">
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-medium text-slate-400">
                  Enrollment Token
                </label>
                <button
                  onClick={() => handleCopy(generatedToken)}
                  className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                >
                  {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                  {copied ? "Copied!" : "Copy"}
                </button>
              </div>
              <div className="px-3 py-2 bg-slate-900 rounded-lg font-mono text-xs text-green-400 break-all border border-slate-700">
                {generatedToken}
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
                  <Terminal className="w-3 h-3" />
                  Install Command
                </label>
                <button
                  onClick={() => handleCopy(installCmd)}
                  className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                >
                  <Copy className="w-3 h-3" />
                  Copy
                </button>
              </div>
              <div className="px-3 py-2 bg-slate-900 rounded-lg font-mono text-xs text-slate-300 break-all border border-slate-700">
                {installCmd}
              </div>
            </div>

            {selectedTenant && (
              <Badge variant="info">
                Client: {selectedTenant.name}
              </Badge>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
