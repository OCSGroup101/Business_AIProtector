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
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Building2,
  KeyRound,
  AlertTriangle,
  ClipboardList,
  LogOut,
  Shield,
} from "lucide-react";

const NAV_ITEMS = [
  { href: "/msp/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/msp/clients", label: "Clients", icon: Building2 },
  { href: "/msp/enrollment", label: "Enrollment", icon: KeyRound },
  { href: "/msp/alerts", label: "Alerts", icon: AlertTriangle },
  { href: "/msp/audit", label: "Audit Log", icon: ClipboardList },
];

interface MspSidebarProps {
  onLogout?: () => void;
}

export function MspSidebar({ onLogout }: MspSidebarProps) {
  const pathname = usePathname();

  const isActive = (href: string) =>
    pathname === href || pathname.startsWith(href + "/");

  return (
    <aside className="w-56 flex-shrink-0 bg-slate-900 border-r border-slate-700/60 flex flex-col">
      {/* Brand */}
      <div className="px-4 py-5 border-b border-slate-700/60">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-blue-400" />
          <div>
            <span className="text-sm font-bold tracking-wide text-slate-100">
              OmniProtect
            </span>
            <p className="text-xs text-blue-400 font-medium">MSP Portal</p>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-2 py-4 space-y-0.5 overflow-auto">
        {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
          const active = isActive(href);
          return (
            <Link
              key={href}
              href={href}
              className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                active
                  ? "bg-blue-600/15 text-blue-400 font-medium"
                  : "text-slate-400 hover:text-slate-100 hover:bg-slate-800"
              }`}
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              {label}
            </Link>
          );
        })}
      </nav>

      {/* User footer */}
      <div className="px-2 py-3 border-t border-slate-700/60">
        {onLogout && (
          <button
            onClick={onLogout}
            className="flex items-center gap-3 px-3 py-2 w-full rounded-lg text-sm text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors"
          >
            <LogOut className="w-4 h-4 flex-shrink-0" />
            Sign out
          </button>
        )}
        <p className="text-xs text-slate-600 px-3 mt-2">v2.0.0</p>
      </div>
    </aside>
  );
}
