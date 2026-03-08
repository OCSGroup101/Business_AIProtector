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
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Plus,
  Trash2,
  CheckCircle,
  XCircle,
  Loader2,
  ChevronDown,
} from "lucide-react";
import {
  listSiemConnectors,
  createSiemConnector,
  deleteSiemConnector,
  testSiemConnector,
} from "@/lib/api";
import type { SiemConnector, SiemConnectorType, CreateSiemConnectorRequest } from "@/types";

// Field definitions per connector type
const CONNECTOR_FIELDS: Record<
  SiemConnectorType,
  { key: string; label: string; placeholder: string; secret?: boolean }[]
> = {
  splunk: [
    { key: "url", label: "HEC URL", placeholder: "https://splunk.example.com:8088" },
    { key: "hec_token", label: "HEC Token", placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", secret: true },
    { key: "index", label: "Index", placeholder: "main" },
    { key: "source_type", label: "Source Type", placeholder: "openclaw:event" },
  ],
  elasticsearch: [
    { key: "url", label: "URL", placeholder: "https://es.example.com:9200" },
    { key: "api_key", label: "API Key", placeholder: "base64-encoded-api-key", secret: true },
    { key: "index_prefix", label: "Index Prefix", placeholder: "openclaw-" },
  ],
  sentinel: [
    { key: "workspace_id", label: "Workspace ID", placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" },
    { key: "shared_key", label: "Shared Key", placeholder: "base64-encoded-shared-key", secret: true },
    { key: "log_type", label: "Log Type", placeholder: "OpenClawEvents" },
  ],
};

const TYPE_LABELS: Record<SiemConnectorType, string> = {
  splunk: "Splunk HEC",
  elasticsearch: "Elasticsearch",
  sentinel: "Microsoft Sentinel",
};

const TYPE_ICON: Record<SiemConnectorType, string> = {
  splunk: "SP",
  elasticsearch: "ES",
  sentinel: "MS",
};

const TYPE_ICON_COLOR: Record<SiemConnectorType, string> = {
  splunk: "bg-orange-500/20 text-orange-400",
  elasticsearch: "bg-yellow-500/20 text-yellow-400",
  sentinel: "bg-blue-500/20 text-blue-400",
};

function fmt(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function SiemSettingsPage() {
  const queryClient = useQueryClient();
  const [showAddForm, setShowAddForm] = useState(false);

  const { data: connectors = [], isLoading, isError } = useQuery<SiemConnector[]>({
    queryKey: ["siem-connectors"],
    queryFn: listSiemConnectors,
  });

  const remove = useMutation({
    mutationFn: (id: string) => deleteSiemConnector(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["siem-connectors"] }),
  });

  const testConn = useMutation({
    mutationFn: (id: string) => testSiemConnector(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["siem-connectors"] }),
  });

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div>
        <div className="text-xs text-gray-500 uppercase tracking-wider mb-1">
          Settings
        </div>
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-white">SIEM Connectors</h1>
          <button
            onClick={() => setShowAddForm((v) => !v)}
            className="flex items-center gap-2 px-4 py-2 bg-orange-500 hover:bg-orange-600 text-white text-sm font-medium rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" />
            Add Connector
            <ChevronDown
              className={`w-3.5 h-3.5 transition-transform ${showAddForm ? "rotate-180" : ""}`}
            />
          </button>
        </div>
      </div>

      {/* Add connector inline form */}
      {showAddForm && (
        <AddConnectorForm
          onSuccess={() => {
            setShowAddForm(false);
            queryClient.invalidateQueries({ queryKey: ["siem-connectors"] });
          }}
          onCancel={() => setShowAddForm(false)}
        />
      )}

      {/* Connectors list */}
      <div className="bg-gray-900 rounded-xl overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-gray-500 text-sm">Loading...</div>
        ) : isError ? (
          <div className="p-8 text-center text-gray-500 text-sm">
            Error loading data
          </div>
        ) : connectors.length === 0 ? (
          <div className="p-12 text-center text-gray-500 text-sm rounded-xl">
            No SIEM connectors configured. Add one to start forwarding events.
          </div>
        ) : (
          <div className="divide-y divide-gray-800">
            {connectors.map((connector) => (
              <ConnectorRow
                key={connector.id}
                connector={connector}
                onDelete={() => remove.mutate(connector.id)}
                onTest={() => testConn.mutate(connector.id)}
                isTesting={testConn.isPending && testConn.variables === connector.id}
                isDeleting={remove.isPending && remove.variables === connector.id}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function ConnectorRow({
  connector,
  onDelete,
  onTest,
  isTesting,
  isDeleting,
}: {
  connector: SiemConnector;
  onDelete: () => void;
  onTest: () => void;
  isTesting: boolean;
  isDeleting: boolean;
}) {
  const [confirmDelete, setConfirmDelete] = useState(false);

  return (
    <div className="flex items-center gap-4 px-4 py-4 hover:bg-gray-800/30 transition-colors">
      {/* Type icon */}
      <div
        className={`w-10 h-10 rounded-lg flex items-center justify-center text-xs font-bold flex-shrink-0 ${TYPE_ICON_COLOR[connector.type]}`}
      >
        {TYPE_ICON[connector.type]}
      </div>

      {/* Name + type */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-white truncate">
            {connector.name}
          </span>
          <span className="px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 text-xs flex-shrink-0">
            {TYPE_LABELS[connector.type]}
          </span>
          <span
            className={`w-2 h-2 rounded-full flex-shrink-0 ${
              connector.enabled ? "bg-green-500" : "bg-gray-600"
            }`}
          />
        </div>
        {/* Last test result */}
        {connector.last_test_at && (
          <div className="flex items-center gap-1.5 mt-0.5">
            {connector.last_test_ok ? (
              <>
                <CheckCircle className="w-3 h-3 text-green-400" />
                <span className="text-xs text-green-400">
                  Connected · {fmt(connector.last_test_at)}
                </span>
              </>
            ) : (
              <>
                <XCircle className="w-3 h-3 text-red-400" />
                <span className="text-xs text-red-400">
                  Failed · {fmt(connector.last_test_at)}
                </span>
                {connector.last_test_error && (
                  <span className="text-xs text-gray-600 truncate max-w-xs">
                    — {connector.last_test_error}
                  </span>
                )}
              </>
            )}
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2 flex-shrink-0">
        <button
          onClick={onTest}
          disabled={isTesting}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-300 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 rounded-lg transition-colors"
        >
          {isTesting ? (
            <Loader2 className="w-3 h-3 animate-spin" />
          ) : (
            <CheckCircle className="w-3 h-3" />
          )}
          {isTesting ? "Testing..." : "Test"}
        </button>

        {confirmDelete ? (
          <div className="flex items-center gap-1">
            <button
              onClick={onDelete}
              disabled={isDeleting}
              className="px-2 py-1 text-xs bg-red-600 hover:bg-red-700 text-white rounded transition-colors"
            >
              {isDeleting ? "Deleting..." : "Confirm"}
            </button>
            <button
              onClick={() => setConfirmDelete(false)}
              className="px-2 py-1 text-xs bg-gray-800 hover:bg-gray-700 text-gray-400 rounded transition-colors"
            >
              Cancel
            </button>
          </div>
        ) : (
          <button
            onClick={() => setConfirmDelete(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-red-400 border border-red-900 rounded-lg hover:bg-red-900/20 transition-colors"
          >
            <Trash2 className="w-3 h-3" />
            Delete
          </button>
        )}
      </div>
    </div>
  );
}

function AddConnectorForm({
  onSuccess,
  onCancel,
}: {
  onSuccess: () => void;
  onCancel: () => void;
}) {
  const [name, setName] = useState("");
  const [type, setType] = useState<SiemConnectorType>("splunk");
  const [sslVerify, setSslVerify] = useState(true);
  const [config, setConfig] = useState<Record<string, string>>({});

  const fields = CONNECTOR_FIELDS[type];

  const save = useMutation({
    mutationFn: () => {
      const data: CreateSiemConnectorRequest = {
        name,
        type,
        ssl_verify: sslVerify,
        config,
      };
      return createSiemConnector(data);
    },
    onSuccess,
  });

  const handleTypeChange = (newType: SiemConnectorType) => {
    setType(newType);
    setConfig({}); // reset config when type changes
  };

  const setField = (key: string, value: string) => {
    setConfig((prev) => ({ ...prev, [key]: value }));
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-5">
      <h2 className="text-sm font-semibold text-white">Add SIEM Connector</h2>

      <div className="grid grid-cols-2 gap-4">
        {/* Name */}
        <div>
          <label className="block text-xs text-gray-400 mb-1.5 font-medium">
            Name
          </label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="My Splunk Connector"
            className="w-full px-3 py-2 bg-gray-800 border border-gray-700 text-gray-200 text-sm rounded-lg focus:outline-none focus:border-orange-500 placeholder-gray-600"
          />
        </div>

        {/* Type */}
        <div>
          <label className="block text-xs text-gray-400 mb-1.5 font-medium">
            Type
          </label>
          <select
            value={type}
            onChange={(e) => handleTypeChange(e.target.value as SiemConnectorType)}
            className="w-full px-3 py-2 bg-gray-800 border border-gray-700 text-gray-200 text-sm rounded-lg focus:outline-none focus:border-orange-500"
          >
            <option value="splunk">Splunk HEC</option>
            <option value="elasticsearch">Elasticsearch</option>
            <option value="sentinel">Microsoft Sentinel</option>
          </select>
        </div>
      </div>

      {/* Dynamic config fields */}
      <div className="grid grid-cols-2 gap-4">
        {fields.map(({ key, label, placeholder, secret }) => (
          <div key={key}>
            <label className="block text-xs text-gray-400 mb-1.5 font-medium">
              {label}
            </label>
            <input
              type={secret ? "password" : "text"}
              value={config[key] ?? ""}
              onChange={(e) => setField(key, e.target.value)}
              placeholder={placeholder}
              className="w-full px-3 py-2 bg-gray-800 border border-gray-700 text-gray-200 text-sm rounded-lg focus:outline-none focus:border-orange-500 placeholder-gray-600"
            />
          </div>
        ))}
      </div>

      {/* SSL verify toggle */}
      <div className="flex items-center gap-3">
        <button
          onClick={() => setSslVerify((v) => !v)}
          className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
            sslVerify ? "bg-orange-500" : "bg-gray-700"
          }`}
        >
          <span
            className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
              sslVerify ? "translate-x-4" : "translate-x-0.5"
            }`}
          />
        </button>
        <span className="text-sm text-gray-400">Verify SSL certificate</span>
      </div>

      {save.isError && (
        <div className="text-xs text-red-400 bg-red-900/20 border border-red-900 rounded px-3 py-2">
          {(save.error as Error).message}
        </div>
      )}

      <div className="flex justify-end gap-2">
        <button
          onClick={onCancel}
          disabled={save.isPending}
          className="px-4 py-2 text-sm text-gray-400 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
        >
          Cancel
        </button>
        <button
          onClick={() => save.mutate()}
          disabled={save.isPending || !name.trim()}
          className="flex items-center gap-2 px-4 py-2 bg-orange-500 hover:bg-orange-600 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm font-medium rounded-lg transition-colors"
        >
          {save.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
          {save.isPending ? "Saving..." : "Save Connector"}
        </button>
      </div>
    </div>
  );
}
