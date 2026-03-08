// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// Build script for the OpenClaw agent.
// Links EndpointSecurity.framework on macOS when the "macos-esf" feature is enabled.

fn main() {
    // Link EndpointSecurity.framework for full ESF access (requires entitlement + root)
    #[cfg(target_os = "macos")]
    {
        if std::env::var("CARGO_FEATURE_MACOS_ESF").is_ok() {
            println!("cargo:rustc-link-lib=framework=EndpointSecurity");
        }
    }

    // Rerun if build env changes
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_MACOS_ESF");
}
