// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// macOS Endpoint Security Framework — direct C FFI bindings.
//
// This module is only compiled when the `macos-esf` feature flag is enabled
// (gate is in esf/mod.rs: `#[cfg(feature = "macos-esf")] pub mod esf_ffi;`).
//
// Requires: com.apple.developer.endpoint-security.client entitlement.
// Every unsafe block must carry a `// SAFETY:` comment and Security Architect
// sign-off per CLAUDE.md invariant #2.
//
// Current status: stub — full FFI implementation pending entitlement provisioning.
// All production telemetry uses eslogger (Approach A in mod.rs) until then.

use anyhow::Result;

/// Opaque handle to an EndpointSecurity client.
/// Full implementation requires linking EndpointSecurity.framework.
pub struct EsClient;

impl EsClient {
    /// Create a new ESF client.
    /// Returns an error until the FFI layer is implemented.
    pub fn new() -> Result<Self> {
        anyhow::bail!("macos-esf FFI not yet implemented; use eslogger (default) instead")
    }
}

impl Default for EsClient {
    fn default() -> Self {
        // Intentionally unreachable in practice — `new()` always returns Err.
        // Required by clippy::new_without_default.
        EsClient
    }
}
