"use client";
// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.

import { useQuery } from "@tanstack/react-query";
import { listFeeds, type FeedStatus } from "@/lib/api";
import clsx from "clsx";

const STATUS_DOT: Record<FeedStatus["status"], string> = {
  active:  "bg-green-400",
  pending: "bg-yellow-400",
  error:   "bg-red-500",
};

export default function IntelPage() {
  const { data, isLoading } = useQuery({
    queryKey: ["feeds"],
    queryFn: listFeeds,
  });

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-6">Intelligence Feeds</h1>

      {isLoading && (
        <div className="text-gray-500 text-sm py-12 text-center">
          Loading feed status...
        </div>
      )}

      {data && (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                {["Feed", "Interval", "Status"].map((h) => (
                  <th
                    key={h}
                    className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {data.feeds.map((feed) => (
                <tr key={feed.name} className="hover:bg-gray-50">
                  <td className="px-4 py-3 text-sm font-medium text-gray-900">
                    {feed.name}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-500">
                    {feed.interval}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <span
                        className={clsx(
                          "h-2 w-2 rounded-full",
                          STATUS_DOT[feed.status] ?? STATUS_DOT.pending
                        )}
                      />
                      <span className="text-sm text-gray-700 capitalize">
                        {feed.status}
                      </span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
