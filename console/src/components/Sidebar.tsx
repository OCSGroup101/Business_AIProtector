"use client";
// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.

import Link from "next/link";
import { usePathname } from "next/navigation";
import clsx from "clsx";

const NAV = [
  { href: "/",          label: "Dashboard",    exact: true },
  { href: "/incidents", label: "Incidents" },
  { href: "/agents",    label: "Agents" },
  { href: "/policies",  label: "Policies" },
  { href: "/intel",     label: "Intelligence" },
  { href: "/audit",     label: "Audit Log" },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-56 min-h-screen bg-gray-900 text-gray-100 flex flex-col">
      <div className="px-5 py-4 border-b border-gray-700">
        <span className="text-lg font-bold tracking-tight text-white">OpenClaw</span>
        <span className="ml-2 text-xs text-gray-400">console</span>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-1">
        {NAV.map(({ href, label, exact }) => {
          const active = exact ? pathname === href : pathname.startsWith(href);
          return (
            <Link
              key={href}
              href={href}
              className={clsx(
                "block px-3 py-2 rounded-md text-sm font-medium transition-colors",
                active
                  ? "bg-brand text-white"
                  : "text-gray-300 hover:bg-gray-700 hover:text-white"
              )}
            >
              {label}
            </Link>
          );
        })}
      </nav>

      <div className="px-5 py-3 border-t border-gray-700 text-xs text-gray-500">
        v0.1.0-alpha
      </div>
    </aside>
  );
}
