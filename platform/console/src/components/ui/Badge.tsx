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

type BadgeVariant = "default" | "success" | "warning" | "danger" | "info";

const VARIANT_CLASSES: Record<BadgeVariant, string> = {
  default: "bg-slate-700 text-slate-300",
  success: "bg-green-900/50 text-green-400 ring-1 ring-green-800",
  warning: "bg-yellow-900/50 text-yellow-400 ring-1 ring-yellow-800",
  danger: "bg-red-900/50 text-red-400 ring-1 ring-red-800",
  info: "bg-blue-900/50 text-blue-400 ring-1 ring-blue-800",
};

interface BadgeProps {
  variant?: BadgeVariant;
  children: React.ReactNode;
  className?: string;
}

export function Badge({ variant = "default", children, className = "" }: BadgeProps) {
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${VARIANT_CLASSES[variant]} ${className}`}
    >
      {children}
    </span>
  );
}
