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
import { useRouter } from "next/navigation";
import { Plus, Search } from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Modal, useModal } from "@/components/ui/Modal";
import { Skeleton } from "@/components/ui/Skeleton";
import { getMspTenants, provisionTenant } from "@/lib/api";
import { useTenant } from "@/contexts/TenantContext";
import type { TenantSummary } from "@/types";

function healthVariant(t: TenantSummary): "success" | "danger" | "warning" {
  if (t.critical_incidents > 0) return "danger";
  if (t.open_incidents > 0) return "warning";
  return "success";
}

function healthLabel(t: TenantSummary): string {
  if (t.critical_incidents > 0) return "Critical";
  if (t.open_incidents > 0) return "Warning";
  return "Healthy";
}

export default function MspClientsPage() {
  const router = useRouter();
  const { setActiveTenant } = useTenant();
  const qc = useQueryClient();
  const { isOpen, open, close } = useModal();
  const [search, setSearch] = useState("");
  const [newName, setNewName] = useState("");
  const [newId, setNewId] = useState("");

  const { data: tenants = [], isLoading } = useQuery<TenantSummary[]>({
    queryKey: ["msp-tenants"],
    queryFn: getMspTenants,
  });

  const provision = useMutation({
    mutationFn: () => provisionTenant({ name: newName, tenant_id: newId || undefined }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["msp-tenants"] });
      qc.invalidateQueries({ queryKey: ["msp-summary"] });
      close();
      setNewName("");
      setNewId("");
    },
  });

  const filtered = tenants.filter((t) =>
    t.name.toLowerCase().includes(search.toLowerCase())
  );

  const handleView = (t: TenantSummary) => {
    setActiveTenant(t.id, t.name);
    router.push(`/msp/clients/${t.id}`);
  };

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-slate-100">Clients</h1>
        <Button onClick={open} size="sm">
          <Plus className="w-4 h-4" />
          Add Client
        </Button>
      </div>

      {/* Search */}
      <div className="flex items-center gap-2 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 w-64">
        <Search className="w-4 h-4 text-slate-500" />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search clients..."
          className="bg-transparent text-sm text-slate-200 placeholder:text-slate-600 outline-none flex-1"
        />
      </div>

      {/* Table */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-700">
              {["Client Name", "Tenant ID", "Agents", "Open Incidents", "Health", ""].map(
                (h) => (
                  <th
                    key={h}
                    className="px-4 py-3 text-left text-xs text-slate-500 font-medium uppercase tracking-wider"
                  >
                    {h}
                  </th>
                )
              )}
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              Array.from({ length: 5 }).map((_, i) => (
                <tr key={i} className="border-b border-slate-700/50">
                  {Array.from({ length: 6 }).map((__, j) => (
                    <td key={j} className="px-4 py-3">
                      <Skeleton className="h-4" />
                    </td>
                  ))}
                </tr>
              ))
            ) : filtered.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-10 text-center text-slate-500 text-sm">
                  {search ? "No clients matching search" : "No clients provisioned yet"}
                </td>
              </tr>
            ) : (
              filtered.map((t) => (
                <tr
                  key={t.id}
                  className="border-b border-slate-700/50 last:border-0 hover:bg-slate-700/20 transition-colors"
                >
                  <td className="px-4 py-3 font-medium text-slate-200">{t.name}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-500">{t.id}</td>
                  <td className="px-4 py-3 text-slate-400">{t.agent_count}</td>
                  <td className="px-4 py-3 text-slate-400">{t.open_incidents}</td>
                  <td className="px-4 py-3">
                    <Badge variant={healthVariant(t)}>{healthLabel(t)}</Badge>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => handleView(t)}
                      className="px-3 py-1 text-xs bg-blue-600/20 text-blue-400 border border-blue-700/50 rounded-lg hover:bg-blue-600/30 transition-colors"
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Add Client Modal */}
      <Modal isOpen={isOpen} onClose={close} title="Provision New Client">
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">
              Organization Name *
            </label>
            <input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Acme Corp"
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">
              Tenant ID (optional — auto-generated if blank)
            </label>
            <input
              value={newId}
              onChange={(e) => setNewId(e.target.value)}
              placeholder="acme-corp"
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-sm text-slate-200 placeholder:text-slate-500 font-mono focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <Button variant="ghost" onClick={close} size="sm">
              Cancel
            </Button>
            <Button
              onClick={() => provision.mutate()}
              loading={provision.isPending}
              disabled={!newName.trim()}
              size="sm"
            >
              Provision
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
