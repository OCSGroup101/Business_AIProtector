// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
import clsx from "clsx";
import type { Severity } from "@/lib/api";

const CLASSES: Record<Severity, string> = {
  CRITICAL: "bg-red-100 text-red-700 border-red-300",
  HIGH:     "bg-orange-100 text-orange-700 border-orange-300",
  MEDIUM:   "bg-yellow-100 text-yellow-700 border-yellow-300",
  LOW:      "bg-blue-100 text-blue-700 border-blue-300",
  INFO:     "bg-gray-100 text-gray-600 border-gray-300",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border",
        CLASSES[severity] ?? CLASSES.INFO
      )}
    >
      {severity}
    </span>
  );
}
