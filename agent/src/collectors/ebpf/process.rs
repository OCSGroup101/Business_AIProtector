// Copyright 2026 Omni Cyber Solutions LLC
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

// eBPF process event types and parser.
//
// `ProcessEvent` mirrors the C struct in agent/src/bpf/process_monitor.bpf.c.
// The layout MUST remain identical: both are `#[repr(C)]` with fixed-size arrays
// matching the BPF map value layout (no padding inserted by the kernel).

use serde_json::json;
use std::collections::HashMap;

use crate::core::event_bus::{EventType, OsInfo, TelemetryEvent};

/// Raw event written by the BPF program into the PROCESS_EVENTS perf array.
/// Must match `struct process_event` in process_monitor.bpf.c exactly.
#[repr(C)]
pub struct ProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    /// Task comm name (not NUL-padded by BPF — we trim it ourselves).
    pub comm: [u8; 16],
    /// Absolute executable path.
    pub filename: [u8; 256],
}

impl ProcessEvent {
    /// Byte size of the on-wire representation written by the BPF program.
    pub const SIZE: usize = std::mem::size_of::<Self>();
}

/// Convert a raw byte slice from a perf event buffer into a `TelemetryEvent`.
///
/// Returns `None` if `bytes` is too short to contain a full `ProcessEvent`.
pub fn parse_process_event(
    bytes: &[u8],
    agent_id: &str,
    tenant_id: &str,
    hostname: &str,
    os_info: &OsInfo,
) -> Option<TelemetryEvent> {
    if bytes.len() < ProcessEvent::SIZE {
        return None;
    }

    // SAFETY: We have verified `bytes` contains at least `SIZE` bytes.
    // `ProcessEvent` is `#[repr(C)]` with fixed-size primitive fields — no
    // pointers, no padding that could cause UB. The cast reads the bytes
    // in-place; the resulting reference does not outlive `bytes`.
    let raw: &ProcessEvent = unsafe { &*(bytes.as_ptr() as *const ProcessEvent) };

    let comm = nul_terminated_str(&raw.comm);
    let filename = nul_terminated_str(&raw.filename);

    let mut payload: HashMap<String, serde_json::Value> = HashMap::new();
    payload.insert("pid".to_string(), json!(raw.pid));
    payload.insert("ppid".to_string(), json!(raw.ppid));
    payload.insert("uid".to_string(), json!(raw.uid));
    payload.insert("comm".to_string(), json!(comm));
    payload.insert("image_path".to_string(), json!(filename));
    payload.insert("collector_source".to_string(), json!("ebpf"));

    let mut event = TelemetryEvent::new(
        agent_id,
        tenant_id,
        "ebpf_process",
        EventType::ProcessCreate,
        hostname,
        os_info.clone(),
    );
    event.payload = payload;
    Some(event)
}

/// Read a NUL-terminated (or end-of-slice) UTF-8 string from a fixed byte buffer.
fn nul_terminated_str(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}
