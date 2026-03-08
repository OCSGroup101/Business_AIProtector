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

import React, { useCallback, useEffect, useState } from "react";
import {
  AuthContext,
  AuthState,
  AuthUser,
  extractUserFromToken,
  isMspOperator,
} from "@/lib/auth";
import { keycloak, initKeycloak } from "@/lib/keycloak";

// ---------------------------------------------------------------------------
// Dev-mode token → role mapping
// ---------------------------------------------------------------------------

const DEV_TOKEN_ROLES: Record<string, string[]> = {
  "dev-msp-token": ["msp_operator", "tenant_admin"],
  "dev-admin-token": ["tenant_admin"],
  "dev-security-token": ["security_admin"],
  "dev-helpdesk-token": ["helpdesk"],
  "dev-auditor-token": ["auditor"],
};

const IS_DEV = process.env.NEXT_PUBLIC_DEV_MODE === "true";

function buildDevUser(token: string): AuthUser {
  const roles = DEV_TOKEN_ROLES[token] ?? ["tenant_admin"];
  return {
    id: `dev-user-${token}`,
    name: token
      .replace("dev-", "")
      .replace("-token", "")
      .replace("-", " ")
      .replace(/\b\w/g, (c) => c.toUpperCase()),
    email: `${token.replace("dev-", "").replace("-token", "")}@dev.omniprotect.local`,
    roles,
  };
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

interface AuthProviderProps {
  children: React.ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<AuthUser | null>(null);

  // ------------------------------------------------------------------
  // Login / logout helpers
  // ------------------------------------------------------------------

  const login = useCallback((msp = false) => {
    if (IS_DEV) {
      // In dev mode point the user to the /login page where they can pick a
      // token, or default to dev-admin-token for convenience.
      if (typeof window !== "undefined") {
        window.location.href = msp ? "/login?role=msp" : "/login";
      }
      return;
    }
    if (keycloak) {
      keycloak.login({
        redirectUri: typeof window !== "undefined" ? window.location.href : undefined,
      });
    }
  }, []);

  const logout = useCallback(() => {
    if (IS_DEV) {
      if (typeof window !== "undefined") {
        localStorage.removeItem("dev_token");
      }
      setToken(null);
      setUser(null);
      window.location.href = "/login";
      return;
    }
    sessionStorage.removeItem("kc_token");
    setToken(null);
    setUser(null);
    if (keycloak) {
      keycloak.logout({ redirectUri: window.location.origin });
    }
  }, []);

  // ------------------------------------------------------------------
  // Initialisation
  // ------------------------------------------------------------------

  useEffect(() => {
    if (IS_DEV) {
      // Dev mode: read token from localStorage
      const stored =
        typeof window !== "undefined"
          ? localStorage.getItem("dev_token")
          : null;
      if (stored) {
        setToken(stored);
        setUser(buildDevUser(stored));
      }
      return;
    }

    // Production: initialise Keycloak (lazy-loaded inside initKeycloak)
    initKeycloak((authenticated) => {
      // After initKeycloak resolves, the module-level `keycloak` singleton is
      // populated — access it via the imported reference.
      if (authenticated && keycloak?.token) {
        const kToken = keycloak.token;
        sessionStorage.setItem("kc_token", kToken);
        setToken(kToken);
        const extracted = extractUserFromToken(kToken);
        setUser(extracted);
      }

      // Wire up lifecycle callbacks now that the instance exists
      if (keycloak) {
        keycloak.onTokenExpired = () => {
          keycloak
            ?.updateToken(60)
            .then((refreshed) => {
              if (refreshed && keycloak?.token) {
                const newToken = keycloak.token;
                sessionStorage.setItem("kc_token", newToken);
                setToken(newToken);
                setUser(extractUserFromToken(newToken));
              }
            })
            .catch(() => {
              sessionStorage.removeItem("kc_token");
              setToken(null);
              setUser(null);
            });
        };

        keycloak.onAuthLogout = () => {
          sessionStorage.removeItem("kc_token");
          setToken(null);
          setUser(null);
        };
      }
    });
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ------------------------------------------------------------------
  // Context value
  // ------------------------------------------------------------------

  const value: AuthState = {
    token,
    user,
    isAuthenticated: token !== null,
    isMsp: user ? isMspOperator(user.roles) : false,
    login,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
