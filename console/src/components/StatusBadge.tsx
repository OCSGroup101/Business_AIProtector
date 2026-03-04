// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
import clsx from "clsx";
import type { IncidentStatus } from "@/lib/api";

const CLASSES: Record<IncidentStatus, string> = {
  OPEN:           "bg-red-50 text-red-600 border-red-200",
  INVESTIGATING:  "bg-orange-50 text-orange-600 border-orange-200",
  CONTAINED:      "bg-purple-50 text-purple-600 border-purple-200",
  RESOLVED:       "bg-green-50 text-green-600 border-green-200",
  FALSE_POSITIVE: "bg-gray-50 text-gray-500 border-gray-200",
};

export function StatusBadge({ status }: { status: IncidentStatus }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border",
        CLASSES[status] ?? "bg-gray-50 text-gray-500 border-gray-200"
      )}
    >
      {status.replace("_", " ")}
    </span>
  );
}
