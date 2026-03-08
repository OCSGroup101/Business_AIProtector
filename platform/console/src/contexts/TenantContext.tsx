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

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import { apiClient } from "@/lib/api";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TenantContextState {
  activeTenantId: string | null;
  activeTenantName: string | null;
  setActiveTenant: (id: string, name: string) => void;
  clearActiveTenant: () => void;
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

const TenantContext = createContext<TenantContextState>({
  activeTenantId: null,
  activeTenantName: null,
  setActiveTenant: () => undefined,
  clearActiveTenant: () => undefined,
});

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

interface TenantProviderProps {
  children: React.ReactNode;
}

export function TenantProvider({ children }: TenantProviderProps) {
  const [activeTenantId, setActiveTenantId] = useState<string | null>(null);
  const [activeTenantName, setActiveTenantName] = useState<string | null>(null);

  // Keep the apiClient default header in sync with the active tenant
  useEffect(() => {
    if (activeTenantId) {
      apiClient.defaults.headers.common["X-Tenant-ID"] = activeTenantId;
    } else {
      delete apiClient.defaults.headers.common["X-Tenant-ID"];
    }
  }, [activeTenantId]);

  const setActiveTenant = useCallback((id: string, name: string) => {
    setActiveTenantId(id);
    setActiveTenantName(name);
  }, []);

  const clearActiveTenant = useCallback(() => {
    setActiveTenantId(null);
    setActiveTenantName(null);
  }, []);

  return (
    <TenantContext.Provider
      value={{
        activeTenantId,
        activeTenantName,
        setActiveTenant,
        clearActiveTenant,
      }}
    >
      {children}
    </TenantContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Returns the current `TenantContextState`.
 * Must be called inside a `TenantProvider`.
 */
export function useTenant(): TenantContextState {
  return useContext(TenantContext);
}
