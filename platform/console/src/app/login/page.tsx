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

import { useState, useEffect, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Shield, Building2, Lock, AlertTriangle } from "lucide-react";

// Show dev shortcuts when explicitly enabled OR when running on localhost
const IS_DEV =
  process.env.NEXT_PUBLIC_DEV_MODE === "true" ||
  (typeof window !== "undefined" && window.location.hostname === "localhost");

const DEV_TOKENS = [
  { label: "MSP Operator", value: "dev-msp-token" },
  { label: "Tenant Admin", value: "dev-admin-token" },
  { label: "Security Admin", value: "dev-security-token" },
  { label: "Helpdesk", value: "dev-helpdesk-token" },
  { label: "Auditor", value: "dev-auditor-token" },
];

/** Set both a cookie (for the Edge middleware) and sessionStorage (for the API client). */
function setAuthToken(token: string) {
  // Cookie — readable by Next.js middleware
  document.cookie = `kc_token=${token}; path=/; SameSite=Lax; max-age=86400`;
  // sessionStorage — readable by axios interceptor
  sessionStorage.setItem("kc_token", token);
  // localStorage — persists across tab closes (dev only)
  localStorage.setItem("dev_token", token);
}

const ERROR_MESSAGES: Record<string, string> = {
  login_required: "You must sign in to access this page.",
  insufficient_role: "Your account does not have permission to access that area.",
  access_denied: "Access was denied. Please contact your administrator.",
  invalid_token: "Your session has expired. Please sign in again.",
};

function LoginContent() {
  const searchParams = useSearchParams();
  const router = useRouter();

  const [tab, setTab] = useState<"tenant" | "msp">(
    searchParams.get("tab") === "msp" ? "msp" : "tenant"
  );
  const [devToken, setDevToken] = useState(
    tab === "msp" ? "dev-msp-token" : "dev-admin-token"
  );
  const [ssoLoading, setSsoLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Pick up error from query param (?error=login_required) OR URL hash (#error=...)
  useEffect(() => {
    const qErr = searchParams.get("error");
    if (qErr) {
      setErrorMsg(ERROR_MESSAGES[qErr] ?? `Authentication error: ${qErr}`);
      return;
    }
    // Keycloak sometimes puts errors in the hash fragment
    const hash = window.location.hash;
    if (hash.includes("error=")) {
      const params = new URLSearchParams(hash.replace("#", ""));
      const hashErr = params.get("error");
      if (hashErr) {
        setErrorMsg(ERROR_MESSAGES[hashErr] ?? `Authentication error: ${hashErr}`);
        // Clean up the hash so it doesn't persist on refresh
        window.history.replaceState(null, "", window.location.pathname + window.location.search);
      }
    }
  }, [searchParams]);

  useEffect(() => {
    setDevToken(tab === "msp" ? "dev-msp-token" : "dev-admin-token");
  }, [tab]);

  const handleDevLogin = () => {
    setAuthToken(devToken);
    router.push(devToken === "dev-msp-token" ? "/msp/dashboard" : "/incidents");
  };

  const handleSsoLogin = (isMsp: boolean) => {
    const kcUrl = process.env.NEXT_PUBLIC_KEYCLOAK_URL ?? "http://localhost:8080";

    // On localhost without Keycloak running, show a helpful message instead of erroring
    if (window.location.hostname === "localhost" && !process.env.NEXT_PUBLIC_KEYCLOAK_URL) {
      setErrorMsg(
        "Keycloak SSO is not running locally. Use the Dev Quick Login below to sign in during development."
      );
      return;
    }

    setSsoLoading(true);
    setErrorMsg(null);

    const realm = process.env.NEXT_PUBLIC_KEYCLOAK_REALM ?? "omniprotect-platform";
    const clientId = process.env.NEXT_PUBLIC_KEYCLOAK_CLIENT_ID ?? "omniprotect-console";
    const redirectUri = encodeURIComponent(`${window.location.origin}/login/callback`);
    const scope = isMsp ? "openid msp_operator" : "openid";

    window.location.href = `${kcUrl}/realms/${realm}/protocol/openid-connect/auth?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code&scope=${scope}`;
  };

  const nextPath = searchParams.get("next");

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6">
      <div className="w-full max-w-md">
        {/* Brand */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-2.5 mb-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-blue-500 to-cyan-400 flex items-center justify-center">
              <svg width="18" height="18" viewBox="0 0 14 14" fill="none">
                <path d="M7 1L12 4V10L7 13L2 10V4L7 1Z" stroke="white" strokeWidth="1.5" strokeLinejoin="round"/>
                <circle cx="7" cy="7" r="2" fill="white"/>
              </svg>
            </div>
            <span className="text-2xl font-bold text-slate-100">OmniProtect</span>
          </div>
          <p className="text-slate-500 text-sm">Endpoint Security Platform</p>
        </div>

        {/* Error banner */}
        {errorMsg && (
          <div className="mb-4 flex items-start gap-3 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-sm">
            <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Redirect notice */}
        {nextPath && !errorMsg && (
          <div className="mb-4 px-4 py-3 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-300 text-sm text-center">
            Sign in to continue to <span className="font-mono">{nextPath}</span>
          </div>
        )}

        {/* Card */}
        <div className="bg-slate-800 border border-slate-700 rounded-2xl overflow-hidden">
          {/* Tabs */}
          <div className="flex border-b border-slate-700">
            <button
              onClick={() => { setTab("tenant"); setErrorMsg(null); }}
              className={`flex-1 flex items-center justify-center gap-2 py-3.5 text-sm font-medium transition-colors ${
                tab === "tenant"
                  ? "text-blue-400 border-b-2 border-blue-500 bg-blue-600/5"
                  : "text-slate-500 hover:text-slate-300"
              }`}
            >
              <Lock className="w-4 h-4" />
              Tenant Login
            </button>
            <button
              onClick={() => { setTab("msp"); setErrorMsg(null); }}
              className={`flex-1 flex items-center justify-center gap-2 py-3.5 text-sm font-medium transition-colors ${
                tab === "msp"
                  ? "text-blue-400 border-b-2 border-blue-500 bg-blue-600/5"
                  : "text-slate-500 hover:text-slate-300"
              }`}
            >
              <Building2 className="w-4 h-4" />
              MSP Login
            </button>
          </div>

          <div className="p-6 space-y-4">
            {tab === "tenant" ? (
              <>
                <p className="text-sm text-slate-400">
                  Sign in to your organisation&apos;s security console to manage
                  agents, review incidents, and configure detection policies.
                </p>
                <button
                  onClick={() => handleSsoLogin(false)}
                  disabled={ssoLoading}
                  className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-60 text-white rounded-xl font-semibold text-sm transition-colors flex items-center justify-center gap-2"
                >
                  {ssoLoading ? (
                    <span className="inline-block w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  ) : (
                    <Shield className="w-4 h-4" />
                  )}
                  Sign in with SSO
                </button>
              </>
            ) : (
              <>
                <p className="text-sm text-slate-400">
                  MSP operators can manage multiple client tenants, provision
                  new clients, and view aggregate security posture across all
                  managed organisations.
                </p>
                <button
                  onClick={() => handleSsoLogin(true)}
                  disabled={ssoLoading}
                  className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-60 text-white rounded-xl font-semibold text-sm transition-colors flex items-center justify-center gap-2"
                >
                  {ssoLoading ? (
                    <span className="inline-block w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  ) : (
                    <Building2 className="w-4 h-4" />
                  )}
                  MSP SSO Sign In
                </button>
              </>
            )}

            {/* Dev quick login — always visible on localhost */}
            {IS_DEV && (
              <div className="pt-3 border-t border-slate-700/60 space-y-2">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-yellow-400/80 uppercase tracking-wider">
                    Dev Quick Login
                  </span>
                  <span className="px-1.5 py-0.5 rounded bg-yellow-500/10 border border-yellow-500/20 text-yellow-500 text-xs">
                    localhost only
                  </span>
                </div>
                <div className="flex gap-2">
                  <select
                    value={devToken}
                    onChange={(e) => setDevToken(e.target.value)}
                    className="flex-1 px-2.5 py-2 text-xs bg-slate-700 border border-slate-600 rounded-lg text-slate-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
                  >
                    {DEV_TOKENS.map((t) => (
                      <option key={t.value} value={t.value}>
                        {t.label}
                      </option>
                    ))}
                  </select>
                  <button
                    onClick={handleDevLogin}
                    className="px-4 py-2 text-xs bg-yellow-500/15 border border-yellow-600/40 text-yellow-400 rounded-lg hover:bg-yellow-500/25 transition-colors font-semibold"
                  >
                    Login
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        <p className="text-center text-xs text-slate-600 mt-6">
          OmniProtect v2.0.0 &mdash; &copy; {new Date().getFullYear()} Omni Cyber Solutions LLC
        </p>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginContent />
    </Suspense>
  );
}
