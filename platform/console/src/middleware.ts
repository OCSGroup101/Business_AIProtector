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

// NOTE: Next.js middleware runs in the Edge runtime.
// No Node.js built-ins, no DOM APIs other than fetch/URL/Headers/cookies.

import { NextRequest, NextResponse } from "next/server";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const IS_DEV = process.env.NEXT_PUBLIC_DEV_MODE === "true";

/** Paths that do not require authentication. */
const PUBLIC_PATHS = new Set(["/", "/login"]);

/** Path prefix reserved for MSP operators. */
const MSP_PREFIX = "/msp";

// ---------------------------------------------------------------------------
// JWT payload decode (Edge-safe — no Buffer, no atob polyfill needed in Edge)
// ---------------------------------------------------------------------------

interface JwtPayload {
  realm_access?: { roles?: string[] };
  exp?: number;
}

function decodePayload(token: string): JwtPayload | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    // base64url → base64
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded =
      base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    // Edge runtime has atob
    const json = atob(padded);
    return JSON.parse(json) as JwtPayload;
  } catch {
    return null;
  }
}

function hasRole(token: string, role: string): boolean {
  const payload = decodePayload(token);
  return payload?.realm_access?.roles?.includes(role) ?? false;
}

// Dev-mode token → roles map (mirrors AuthProvider)
const DEV_TOKEN_ROLES: Record<string, string[]> = {
  "dev-msp-token": ["msp_operator", "tenant_admin"],
  "dev-admin-token": ["tenant_admin"],
  "dev-security-token": ["security_admin"],
  "dev-helpdesk-token": ["helpdesk"],
  "dev-auditor-token": ["auditor"],
};

function devTokenHasRole(token: string, role: string): boolean {
  return DEV_TOKEN_ROLES[token]?.includes(role) ?? false;
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

export function middleware(request: NextRequest): NextResponse {
  const { pathname } = request.nextUrl;

  // Pass through public paths and Next.js internals / API routes
  if (
    PUBLIC_PATHS.has(pathname) ||
    pathname.startsWith("/api/") ||
    pathname.startsWith("/_next/") ||
    pathname.startsWith("/favicon") ||
    pathname === "/silent-check-sso.html"
  ) {
    return NextResponse.next();
  }

  // Resolve token: cookie first, then Authorization header
  let token =
    request.cookies.get("kc_token")?.value ??
    request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") ??
    null;

  // Also check dev_token cookie (set by login page localStorage mirror)
  if (!token) {
    const devCookie = request.cookies.get("dev_token")?.value ?? null;
    if (devCookie && devCookie in DEV_TOKEN_ROLES) {
      token = devCookie;
    }
  }

  // No token → redirect to /login
  if (!token) {
    const loginUrl = request.nextUrl.clone();
    loginUrl.pathname = "/login";
    loginUrl.searchParams.set("next", pathname);
    return NextResponse.redirect(loginUrl);
  }

  // MSP routes require msp_operator role
  if (pathname.startsWith(MSP_PREFIX)) {
    // Use dev-token map if the token is a known dev token OR env flag is set
    const isDevToken = token in DEV_TOKEN_ROLES;
    const isMsp = (IS_DEV || isDevToken)
      ? devTokenHasRole(token, "msp_operator")
      : hasRole(token, "msp_operator");

    if (!isMsp) {
      const loginUrl = request.nextUrl.clone();
      loginUrl.pathname = "/login";
      loginUrl.searchParams.set("error", "insufficient_role");
      return NextResponse.redirect(loginUrl);
    }
  }

  return NextResponse.next();
}

export const config = {
  // Run on all routes except static files
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
