// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// macOS Endpoint Security Framework — direct C FFI bindings.
//
// This module is only compiled when the `macos-esf` feature is enabled.
// It requires the com.apple.developer.endpoint-security.client entitlement
// and Security Architect sign-off before any unsafe block is added or modified.
//
// Current status: stub — full FFI implementation pending entitlement provisioning.
// All production telemetry is collected via eslogger (Approach A in mod.rs) until
// the entitlement is approved and this module is fully implemented.

#[cfg(feature = "macos-esf")]
pub mod bindings {
    // SAFETY: FFI declarations below follow Apple's EndpointSecurity.h exactly.
    // Each unsafe block requires Security Architect review per CLAUDE.md invariant #2.
    // No unsafe code is present in this stub; it will be added under separate PR
    // with architect sign-off once the entitlement is provisioned.

    /// Placeholder type — will be replaced with the real ESClient handle from
    /// EndpointSecurity.framework once the FFI layer is implemented.
    pub struct EsClient;

    impl EsClient {
        /// Stub constructor — returns an error until the FFI is implemented.
        pub fn new() -> Result<Self, anyhow::Error> {
            anyhow::bail!(
                "macos-esf FFI not yet implemented; use eslogger (default) instead"
            )
        }
    }
}
