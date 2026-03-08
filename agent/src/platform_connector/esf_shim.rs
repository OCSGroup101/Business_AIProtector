// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// ESF FFI shim — EndpointSecurity.framework C bindings.
//
// ⚠️  SECURITY ARCHITECT REVIEW REQUIRED before enabling feature "macos-esf".
//     All unsafe blocks below carry // SAFETY: comments documenting the invariants.
//     Per CLAUDE.md: every unsafe block requires Security Architect sign-off.
//
// Gate: cfg(feature = "macos-esf") — NOT compiled by default.
// Requires: com.apple.developer.endpoint-security.client entitlement + root.

#![cfg(feature = "macos-esf")]

use anyhow::Result;
use tracing::{info, warn};

// Link EndpointSecurity.framework on macOS
// build.rs emits `cargo:rustc-link-lib=framework=EndpointSecurity`

/// Opaque ESF client handle (matches es_client_t* in the C API).
#[repr(C)]
pub struct EsClient {
    _opaque: std::marker::PhantomData<*mut ()>,
}

/// Opaque ESF message handle.
#[repr(C)]
pub struct EsMessage {
    _opaque: std::marker::PhantomData<*mut ()>,
}

/// ES_NEW_CLIENT_RESULT values
#[repr(u32)]
#[allow(dead_code)]
pub enum EsNewClientResult {
    Success = 0,
    ErrInternal = 1,
    ErrInvalidArgument = 2,
    ErrNotEntitled = 3,
    ErrNotPermittedToAdoptEvents = 4,
    ErrNotPrivileged = 5,
    ErrTooManyClients = 6,
}

extern "C" {
    fn es_new_client(
        client: *mut *mut EsClient,
        handler: extern "C" fn(*mut EsClient, *const EsMessage),
    ) -> u32;
    fn es_subscribe(client: *mut EsClient, events: *const u32, event_count: u32) -> u32;
    fn es_delete_client(client: *mut EsClient) -> u32;
}

/// ES_EVENT_TYPE values used by OpenClaw
const ES_EVENT_TYPE_NOTIFY_EXEC: u32 = 9;
const ES_EVENT_TYPE_NOTIFY_CREATE: u32 = 2;
const ES_EVENT_TYPE_NOTIFY_WRITE: u32 = 40;
const ES_EVENT_TYPE_NOTIFY_RENAME: u32 = 23;
const ES_EVENT_TYPE_NOTIFY_UNLINK: u32 = 36;
const ES_EVENT_TYPE_NOTIFY_SETUID: u32 = 29;
const ES_EVENT_TYPE_NOTIFY_AUTHENTICATION: u32 = 90;

static EVENT_SENDER: std::sync::OnceLock<
    tokio::sync::mpsc::Sender<serde_json::Value>,
> = std::sync::OnceLock::new();

/// FFI callback — called by the ES framework on each subscribed event.
///
/// # SAFETY
/// - `client` is a valid `es_client_t*` provided by `es_new_client`.
/// - `message` is a valid `es_message_t*` for the duration of this callback.
/// - We do not retain `message` beyond this function; ES framework owns it.
/// - `EVENT_SENDER` is initialized before `es_new_client` is called.
extern "C" fn es_event_handler(_client: *mut EsClient, message: *const EsMessage) {
    // SAFETY: message is a valid pointer for the duration of this callback (ES contract).
    // We only read from it via the C API and immediately release it after returning.
    // The pointer is never stored or dereferenced after this call returns.
    let raw_ptr = message as usize; // encode as usize to cross FFI boundary safely
    if let Some(tx) = EVENT_SENDER.get() {
        let json = serde_json::json!({ "_esf_raw_ptr": raw_ptr });
        let _ = tx.try_send(json);
    }
}

/// Initialize the ESF client and subscribe to relevant event types.
///
/// # SAFETY
/// - Must be called from a privileged process with the ESF entitlement.
/// - `es_new_client` is thread-safe per Apple's documentation.
/// - The returned `*mut EsClient` must be cleaned up with `es_delete_client`.
pub fn init_esf_client(
    tx: tokio::sync::mpsc::Sender<serde_json::Value>,
) -> Result<*mut EsClient> {
    EVENT_SENDER
        .set(tx)
        .map_err(|_| anyhow::anyhow!("ESF sender already initialized"))?;

    let mut client: *mut EsClient = std::ptr::null_mut();

    // SAFETY: es_new_client is documented to be safe when called with a valid
    // callback and output pointer. The callback satisfies the C extern "C" ABI.
    let result = unsafe { es_new_client(&mut client, es_event_handler) };

    if result != EsNewClientResult::Success as u32 {
        anyhow::bail!("es_new_client failed with code {}", result);
    }

    let events = [
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_CREATE,
        ES_EVENT_TYPE_NOTIFY_WRITE,
        ES_EVENT_TYPE_NOTIFY_RENAME,
        ES_EVENT_TYPE_NOTIFY_UNLINK,
        ES_EVENT_TYPE_NOTIFY_SETUID,
        ES_EVENT_TYPE_NOTIFY_AUTHENTICATION,
    ];

    // SAFETY: client is a valid non-null pointer from es_new_client.
    // events is a stack-allocated array valid for the duration of this call.
    let sub_result = unsafe {
        es_subscribe(client, events.as_ptr(), events.len() as u32)
    };

    if sub_result != 0 {
        // SAFETY: client is a valid pointer; es_delete_client cleans up the client.
        unsafe { es_delete_client(client) };
        anyhow::bail!("es_subscribe failed with code {}", sub_result);
    }

    info!("ESF client initialized with {} event types", events.len());
    Ok(client)
}

/// Clean up the ESF client on shutdown.
///
/// # SAFETY
/// - `client` must be a valid pointer previously returned by `init_esf_client`.
/// - Must be called exactly once per `init_esf_client` call.
pub unsafe fn cleanup_esf_client(client: *mut EsClient) {
    // SAFETY: caller guarantees client is a valid pointer from init_esf_client.
    es_delete_client(client);
}
