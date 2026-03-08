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

import type { LucideIcon } from "lucide-react";

interface StatCardProps {
  icon: LucideIcon;
  label: string;
  value: number | string;
  delta?: string;
  deltaPositive?: boolean;
  iconColor?: string;
}

export function StatCard({
  icon: Icon,
  label,
  value,
  delta,
  deltaPositive,
  iconColor = "text-blue-400",
}: StatCardProps) {
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl p-5 flex items-start gap-4">
      <div className={`p-2.5 rounded-lg bg-slate-700/60 ${iconColor}`}>
        <Icon className="w-5 h-5" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-xs text-slate-500 font-medium uppercase tracking-wider">
          {label}
        </p>
        <p className="text-2xl font-bold text-slate-100 mt-0.5">{value}</p>
        {delta && (
          <p
            className={`text-xs mt-1 ${
              deltaPositive ? "text-green-400" : "text-red-400"
            }`}
          >
            {delta}
          </p>
        )}
      </div>
    </div>
  );
}
