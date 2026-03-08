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

import { createContext, useContext } from "react";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface AuthUser {
  id: string;
  name: string;
  email: string;
  roles: string[];
}

export interface AuthState {
  token: string | null;
  user: AuthUser | null;
  isAuthenticated: boolean;
  isMsp: boolean;
  login: (msp?: boolean) => void;
  logout: () => void;
}

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

interface JwtPayload {
  sub?: string;
  name?: string;
  preferred_username?: string;
  email?: string;
  realm_access?: { roles?: string[] };
  [key: string]: unknown;
}

/**
 * Decode the base64url-encoded payload segment of a JWT.
 * Does NOT verify the signature — use only for UI display / role extraction.
 */
export function getTokenPayload(token: string): JwtPayload | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    // base64url → base64
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(
      base64.length + ((4 - (base64.length % 4)) % 4),
      "="
    );
    const json =
      typeof window !== "undefined"
        ? atob(padded)
        : Buffer.from(padded, "base64").toString("utf8");
    return JSON.parse(json) as JwtPayload;
  } catch {
    return null;
  }
}

/**
 * Extract a typed `AuthUser` from a JWT token string.
 * Returns `null` when the token cannot be decoded.
 */
export function extractUserFromToken(token: string): AuthUser | null {
  const payload = getTokenPayload(token);
  if (!payload) return null;

  return {
    id: payload.sub ?? "",
    name: payload.name ?? payload.preferred_username ?? "",
    email: payload.email ?? "",
    roles: payload.realm_access?.roles ?? [],
  };
}

/**
 * Returns `true` when the role list includes the `msp_operator` role.
 */
export function isMspOperator(roles: string[]): boolean {
  return roles.includes("msp_operator");
}

// ---------------------------------------------------------------------------
// React context
// ---------------------------------------------------------------------------

const defaultState: AuthState = {
  token: null,
  user: null,
  isAuthenticated: false,
  isMsp: false,
  login: () => undefined,
  logout: () => undefined,
};

export const AuthContext = createContext<AuthState>(defaultState);

/**
 * Hook that returns the current `AuthState`.
 * Must be called inside an `AuthProvider`.
 */
export function useAuth(): AuthState {
  return useContext(AuthContext);
}
