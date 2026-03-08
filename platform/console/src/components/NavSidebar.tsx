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

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  BarChart3,
  AlertTriangle,
  Monitor,
  Shield,
  Radar,
  ClipboardList,
  BookOpen,
  FileText,
  Settings,
  Plug,
  Search,
  ArrowLeft,
  Brain,
  Target,
} from "lucide-react";
import { useTenant } from "@/contexts/TenantContext";

const NAV_MAIN = [
  { href: "/dashboard", label: "Dashboard", icon: BarChart3 },
  { href: "/incidents", label: "Incidents", icon: AlertTriangle },
  { href: "/agents", label: "Agents", icon: Monitor },
  { href: "/policies", label: "Policies", icon: Shield },
  { href: "/intelligence", label: "Intelligence", icon: Radar },
  { href: "/rules", label: "Rules", icon: BookOpen },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/audit", label: "Audit Log", icon: ClipboardList },
];

const NAV_AI = [
  { href: "/hunting", label: "Threat Hunting", icon: Search },
  { href: "/correlation", label: "Correlation", icon: Brain },
  { href: "/coverage", label: "MITRE Coverage", icon: Target },
];

const NAV_SETTINGS = [
  { href: "/settings/siem", label: "SIEM Connectors", icon: Plug },
];

export function NavSidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const { activeTenantId, activeTenantName, clearActiveTenant } = useTenant();

  const isActive = (href: string) =>
    pathname === href || pathname.startsWith(href + "/");

  const handleBackToMsp = () => {
    clearActiveTenant();
    router.push("/msp/dashboard");
  };

  return (
    <aside className="w-56 flex-shrink-0 bg-slate-900 border-r border-slate-700/60 flex flex-col">
      {/* Brand */}
      <div className="px-4 py-5 border-b border-slate-700/60">
        <span className="text-sm font-bold tracking-widest text-orange-400 uppercase">
          OmniProtect
        </span>
        {activeTenantName ? (
          <p className="text-xs text-blue-400 mt-0.5 truncate" title={activeTenantName}>
            {activeTenantName}
          </p>
        ) : (
          <p className="text-xs text-slate-500 mt-0.5">Endpoint Security</p>
        )}
      </div>

      {/* MSP back button when drilled in */}
      {activeTenantId && (
        <div className="px-2 pt-2">
          <button
            onClick={handleBackToMsp}
            className="flex items-center gap-2 px-3 py-1.5 w-full rounded-lg text-xs text-blue-400 hover:bg-slate-800 transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Back to MSP
          </button>
        </div>
      )}

      {/* Nav links */}
      <nav className="flex-1 px-2 py-4 space-y-0.5 overflow-auto">
        {NAV_MAIN.map(({ href, label, icon: Icon }) => {
          const active = isActive(href);
          return (
            <Link
              key={href}
              href={href}
              className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                active
                  ? "bg-orange-500/10 text-orange-400 font-medium"
                  : "text-slate-400 hover:text-slate-100 hover:bg-slate-800"
              }`}
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              {label}
            </Link>
          );
        })}

        {/* AI section */}
        <div className="pt-4 pb-1 px-3">
          <div className="text-xs text-slate-600 font-medium uppercase tracking-wider">
            AI
          </div>
        </div>
        {NAV_AI.map(({ href, label, icon: Icon }) => {
          const active = isActive(href);
          return (
            <Link
              key={href}
              href={href}
              className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                active
                  ? "bg-orange-500/10 text-orange-400 font-medium"
                  : "text-slate-400 hover:text-slate-100 hover:bg-slate-800"
              }`}
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              {label}
            </Link>
          );
        })}

        {/* Settings section */}
        <div className="pt-4 pb-1 px-3">
          <div className="flex items-center gap-2 text-xs text-slate-600 font-medium uppercase tracking-wider">
            <Settings className="w-3 h-3" />
            Settings
          </div>
        </div>
        {NAV_SETTINGS.map(({ href, label, icon: Icon }) => {
          const active = isActive(href);
          return (
            <Link
              key={href}
              href={href}
              className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                active
                  ? "bg-orange-500/10 text-orange-400 font-medium"
                  : "text-slate-400 hover:text-slate-100 hover:bg-slate-800"
              }`}
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              {label}
            </Link>
          );
        })}
      </nav>

      {/* Version footer */}
      <div className="px-4 py-3 border-t border-slate-700/60">
        <p className="text-xs text-slate-600">v2.0.0</p>
      </div>
    </aside>
  );
}
