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
} from "lucide-react";

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

const NAV_SETTINGS = [
  { href: "/settings/siem", label: "SIEM Connectors", icon: Plug },
];

export function NavSidebar() {
  const pathname = usePathname();

  const isActive = (href: string) =>
    pathname === href || pathname.startsWith(href + "/");

  return (
    <aside className="w-56 flex-shrink-0 bg-gray-900 border-r border-gray-800 flex flex-col">
      {/* Brand */}
      <div className="px-4 py-5 border-b border-gray-800">
        <span className="text-sm font-bold tracking-widest text-orange-400 uppercase">
          OpenClaw
        </span>
        <p className="text-xs text-gray-500 mt-0.5">Endpoint Security</p>
      </div>

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
                  : "text-gray-400 hover:text-gray-100 hover:bg-gray-800"
              }`}
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              {label}
            </Link>
          );
        })}

        {/* Settings section */}
        <div className="pt-4 pb-1 px-3">
          <div className="flex items-center gap-2 text-xs text-gray-600 font-medium uppercase tracking-wider">
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
                  : "text-gray-400 hover:text-gray-100 hover:bg-gray-800"
              }`}
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              {label}
            </Link>
          );
        })}
      </nav>

      {/* Version footer */}
      <div className="px-4 py-3 border-t border-gray-800">
        <p className="text-xs text-gray-600">v0.1.0-alpha</p>
      </div>
    </aside>
  );
}
