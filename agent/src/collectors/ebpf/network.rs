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

// eBPF network event types and parser.
//
// `NetworkEvent` mirrors `struct network_event` in network_monitor.bpf.c.
// IP address and port fields are in network byte order (big-endian) as written
// by the BPF program directly from the kernel sockaddr — we convert to host
// order before serialising into the TelemetryEvent payload.

use serde_json::json;
use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::core::event_bus::{EventType, OsInfo, TelemetryEvent};

/// Raw event written by the BPF program into the NETWORK_EVENTS perf array.
/// Must match `struct network_event` in network_monitor.bpf.c exactly.
#[repr(C)]
pub struct NetworkEvent {
    pub pid: u32,
    pub uid: u32,
    /// Destination IPv4 address — big-endian (network byte order).
    pub dst_ip: u32,
    /// Destination port — big-endian (network byte order).
    pub dst_port: u16,
    /// IP protocol number (6 = TCP, 17 = UDP).
    pub protocol: u8,
    pub _pad: u8,
}

impl NetworkEvent {
    /// Byte size of the on-wire representation.
    pub const SIZE: usize = std::mem::size_of::<Self>();
}

/// Convert a raw perf-event byte slice into a `TelemetryEvent`.
///
/// Returns `None` if `bytes` is shorter than `NetworkEvent::SIZE`.
pub fn parse_network_event(
    bytes: &[u8],
    agent_id: &str,
    tenant_id: &str,
    hostname: &str,
    os_info: &OsInfo,
) -> Option<TelemetryEvent> {
    if bytes.len() < NetworkEvent::SIZE {
        return None;
    }

    // SAFETY: We have verified `bytes` contains at least `SIZE` bytes.
    // `NetworkEvent` is `#[repr(C)]` with only primitive integer fields.
    // No pointers, no padding ambiguity. The reference does not outlive `bytes`.
    let raw: &NetworkEvent = unsafe { &*(bytes.as_ptr() as *const NetworkEvent) };

    // Convert network byte order to host byte order for display
    let dst_ip = Ipv4Addr::from(u32::from_be(raw.dst_ip));
    let dst_port = u16::from_be(raw.dst_port);
    let protocol_name = match raw.protocol {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMP",
        _ => "UNKNOWN",
    };

    let mut payload: HashMap<String, serde_json::Value> = HashMap::new();
    payload.insert("pid".to_string(), json!(raw.pid));
    payload.insert("uid".to_string(), json!(raw.uid));
    payload.insert("dst_ip".to_string(), json!(dst_ip.to_string()));
    payload.insert("dst_port".to_string(), json!(dst_port));
    payload.insert("protocol".to_string(), json!(protocol_name));
    payload.insert("protocol_num".to_string(), json!(raw.protocol));
    payload.insert("collector_source".to_string(), json!("ebpf"));

    let mut event = TelemetryEvent::new(
        agent_id,
        tenant_id,
        "ebpf_network",
        EventType::NetworkConnect,
        hostname,
        os_info.clone(),
    );
    event.payload = payload;
    Some(event)
}
