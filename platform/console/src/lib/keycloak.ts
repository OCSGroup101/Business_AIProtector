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

// keycloak-js is a browser-only library.  We keep a module-level singleton
// that is null during SSR and populated lazily on the client.

import type KeycloakType from "keycloak-js";

/**
 * The Keycloak singleton instance, or `null` when running in SSR / Edge
 * contexts where `window` is not available.
 *
 * Do not access this before `initKeycloak` has been called.
 */
export let keycloak: KeycloakType | null = null;

/**
 * Initialise the Keycloak singleton (if not yet initialised) and trigger the
 * standard silent SSO `check-sso` flow.
 *
 * Safe to call in a React `useEffect` — returns immediately if called outside
 * a browser context.
 *
 * @param onReady Callback invoked with `true` when the user is authenticated,
 *                `false` otherwise.
 */
export async function initKeycloak(
  onReady: (authenticated: boolean) => void
): Promise<void> {
  // Guard against SSR / Edge runtime
  if (typeof window === "undefined") {
    return;
  }

  // Lazy-load keycloak-js so Next.js never bundles it into the server chunk
  if (keycloak === null) {
    const KeycloakCtor = (await import("keycloak-js")).default;

    keycloak = new KeycloakCtor({
      url: process.env.NEXT_PUBLIC_KEYCLOAK_URL ?? "http://localhost:8080",
      realm:
        process.env.NEXT_PUBLIC_KEYCLOAK_REALM ?? "omniprotect-platform",
      clientId:
        process.env.NEXT_PUBLIC_KEYCLOAK_CLIENT_ID ?? "omniprotect-console",
    });
  }

  try {
    const authenticated = await keycloak.init({
      onLoad: "check-sso",
      silentCheckSsoRedirectUri: `${window.location.origin}/silent-check-sso.html`,
      pkceMethod: "S256",
    });
    onReady(authenticated);
  } catch (err) {
    console.error("[keycloak] init error", err);
    onReady(false);
  }
}
