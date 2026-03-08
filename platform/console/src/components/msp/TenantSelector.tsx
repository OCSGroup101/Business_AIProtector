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
import { ChevronDown, Building2, X } from "lucide-react";
import { useTenant } from "@/contexts/TenantContext";
import type { TenantSummary } from "@/types";

interface TenantSelectorProps {
  tenants: TenantSummary[];
}

export function TenantSelector({ tenants }: TenantSelectorProps) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const { activeTenantId, activeTenantName, setActiveTenant, clearActiveTenant } = useTenant();

  const filtered = tenants.filter((t) =>
    t.name.toLowerCase().includes(search.toLowerCase())
  );

  const handleSelect = (t: TenantSummary) => {
    setActiveTenant(t.id, t.name);
    setOpen(false);
    setSearch("");
  };

  const handleClear = (e: React.MouseEvent) => {
    e.stopPropagation();
    clearActiveTenant();
    setOpen(false);
  };

  return (
    <div className="relative">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2 px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-300 hover:bg-slate-700 transition-colors min-w-[180px]"
      >
        <Building2 className="w-4 h-4 text-slate-500 flex-shrink-0" />
        <span className="flex-1 text-left truncate">
          {activeTenantName ?? "All Clients"}
        </span>
        {activeTenantId ? (
          <X
            className="w-3.5 h-3.5 text-slate-500 hover:text-slate-300 flex-shrink-0"
            onClick={handleClear}
          />
        ) : (
          <ChevronDown className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
        )}
      </button>

      {open && (
        <div className="absolute top-full left-0 mt-1 w-64 bg-slate-800 border border-slate-700 rounded-lg shadow-xl z-40">
          <div className="p-2 border-b border-slate-700">
            <input
              autoFocus
              type="text"
              placeholder="Search clients..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full px-2.5 py-1.5 text-xs bg-slate-700 border border-slate-600 rounded text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>
          <div className="max-h-52 overflow-y-auto py-1">
            <button
              onClick={() => { clearActiveTenant(); setOpen(false); }}
              className={`w-full flex items-center gap-2 px-3 py-2 text-sm transition-colors hover:bg-slate-700 ${
                !activeTenantId ? "text-blue-400 font-medium" : "text-slate-400"
              }`}
            >
              <Building2 className="w-3.5 h-3.5" />
              All Clients
            </button>
            {filtered.map((t) => (
              <button
                key={t.id}
                onClick={() => handleSelect(t)}
                className={`w-full flex items-center gap-2 px-3 py-2 text-sm transition-colors hover:bg-slate-700 ${
                  activeTenantId === t.id ? "text-blue-400 font-medium" : "text-slate-300"
                }`}
              >
                <Building2 className="w-3.5 h-3.5 flex-shrink-0 text-slate-500" />
                <span className="truncate">{t.name}</span>
              </button>
            ))}
            {filtered.length === 0 && (
              <p className="px-3 py-2 text-xs text-slate-500">No clients found</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
