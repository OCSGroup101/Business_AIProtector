// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// Network Collector — cross-platform TCP connection monitoring.
//
// Strategy: poll active ESTABLISHED connections every POLL_INTERVAL_SECS seconds,
// diff against the previous snapshot, and emit NetworkConnect for each new
// connection (i.e. connections not present in the previous poll).  This catches
// outbound C2, lateral movement, and reverse shell activity without requiring
// packet capture or elevated kernel drivers.
//
// Platform implementations:
//   Linux   — parses /proc/net/tcp and /proc/net/tcp6 (no extra privileges needed)
//   Windows — calls GetExtendedTcpTable via Win32 IP Helper API
//   macOS   — Phase 3 (no events emitted; collector runs idle)
//
// Emits: EventType::NetworkConnect

use std::collections::HashSet;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::json;
use tracing::{debug, info};

use crate::collectors::Collector;
use crate::config::AgentConfig;
use crate::core::event_bus::{EventPublisher, EventType, OsInfo, TelemetryEvent};

/// Poll interval — connection diff is run every N seconds.
const POLL_INTERVAL_SECS: u64 = 30;

/// Deduplication key for an active TCP connection.
#[derive(PartialEq, Eq, Hash, Clone)]
struct ConnKey {
    src: String,
    src_port: u16,
    dst: String,
    dst_port: u16,
}

pub struct NetworkCollector {
    capture_dns: bool,
    agent_id: String,
    tenant_id: String,
    hostname: String,
    os_info: OsInfo,
}

impl NetworkCollector {
    pub fn new(cfg: &AgentConfig, agent_id: &str, tenant_id: &str) -> Result<Self> {
        Ok(Self {
            capture_dns: cfg.collectors.network_capture_dns,
            agent_id: agent_id.to_string(),
            tenant_id: tenant_id.to_string(),
            hostname: super::process::hostname_stub(),
            os_info: super::process::os_info_stub(),
        })
    }

    fn make_event(&self, event_type: EventType) -> TelemetryEvent {
        TelemetryEvent::new(
            &self.agent_id,
            &self.tenant_id,
            "network",
            event_type,
            &self.hostname,
            self.os_info.clone(),
        )
    }
}

#[async_trait]
impl Collector for NetworkCollector {
    fn name(&self) -> &'static str {
        "network"
    }

    async fn run(self: Box<Self>, publisher: EventPublisher) -> Result<()> {
        info!(capture_dns = self.capture_dns, "NetworkCollector starting");

        let mut prev_conns: HashSet<ConnKey> = HashSet::new();

        loop {
            // sample_tcp_connections does blocking I/O — run off the async executor
            let current = tokio::task::spawn_blocking(sample_tcp_connections)
                .await
                .unwrap_or_default();

            // Emit an event for every new connection not seen in the previous poll
            for conn in current.difference(&prev_conns) {
                let mut event = self.make_event(EventType::NetworkConnect);
                event.payload.insert("src_ip".into(), json!(conn.src));
                event
                    .payload
                    .insert("src_port".into(), json!(conn.src_port));
                event.payload.insert("dst_ip".into(), json!(conn.dst));
                event
                    .payload
                    .insert("dst_port".into(), json!(conn.dst_port));
                event.payload.insert("protocol".into(), json!("TCP"));
                debug!(dst = %conn.dst, port = conn.dst_port, "New TCP connection");
                publisher.publish(event);
            }

            prev_conns = current;
            tokio::time::sleep(tokio::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
        }
    }
}

/// Sample all currently ESTABLISHED TCP connections.
/// Returns a HashSet for O(1) membership testing in the diff step.
fn sample_tcp_connections() -> HashSet<ConnKey> {
    #[cfg(target_os = "linux")]
    return linux::sample();

    #[cfg(target_os = "windows")]
    return windows::sample();

    #[allow(unreachable_code)]
    HashSet::new()
}

// ─── Linux (/proc/net/tcp + /proc/net/tcp6) ───────────────────────────────────

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::ConnKey;

    pub fn sample() -> HashSet<ConnKey> {
        let mut conns = HashSet::new();
        parse_proc_net("/proc/net/tcp", false, &mut conns);
        parse_proc_net("/proc/net/tcp6", true, &mut conns);
        conns
    }

    fn parse_proc_net(path: &str, is_v6: bool, out: &mut HashSet<ConnKey>) {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return,
        };
        // Header line is skipped
        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 4 {
                continue;
            }
            // Column 3 is TCP state; "01" = TCP_ESTABLISHED
            if cols[3] != "01" {
                continue;
            }

            let src = parse_addr(cols[1], is_v6);
            let dst = parse_addr(cols[2], is_v6);

            if let (Some((src_ip, src_port)), Some((dst_ip, dst_port))) = (src, dst) {
                // Skip loopback destinations — reduces noise from IPC traffic
                if dst_ip.starts_with("127.") || dst_ip == "::1" {
                    continue;
                }
                out.insert(ConnKey {
                    src: src_ip,
                    src_port,
                    dst: dst_ip,
                    dst_port,
                });
            }
        }
    }

    /// Parse "XXXXXXXX:PPPP" (IPv4) or "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:PPPP" (IPv6).
    ///
    /// In /proc/net/tcp[6] addresses are stored as hex in host (little-endian) byte order.
    /// Swapping bytes converts from the on-disk representation to network byte order.
    fn parse_addr(s: &str, is_v6: bool) -> Option<(String, u16)> {
        let colon = s.rfind(':')?;
        let addr_hex = &s[..colon];
        let port_hex = &s[colon + 1..];

        // Port is big-endian hex
        let port = u16::from_str_radix(port_hex, 16).ok()?;

        if !is_v6 && addr_hex.len() == 8 {
            // IPv4: single 32-bit little-endian word
            let raw = u32::from_str_radix(addr_hex, 16).ok()?;
            let ip = Ipv4Addr::from(raw.swap_bytes());
            Some((ip.to_string(), port))
        } else if is_v6 && addr_hex.len() == 32 {
            // IPv6: four 32-bit little-endian words; each must be swapped individually
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                let word = u32::from_str_radix(&addr_hex[i * 8..(i + 1) * 8], 16).ok()?;
                let word_be = word.swap_bytes();
                bytes[i * 4..(i + 1) * 4].copy_from_slice(&word_be.to_be_bytes());
            }
            let ip = Ipv6Addr::from(bytes);
            Some((ip.to_string(), port))
        } else {
            None
        }
    }
}

// ─── Windows (IP Helper API — GetExtendedTcpTable) ────────────────────────────

#[cfg(target_os = "windows")]
mod windows {
    use std::collections::HashSet;
    use std::net::Ipv4Addr;

    use super::ConnKey;

    pub fn sample() -> HashSet<ConnKey> {
        use windows::Win32::Foundation::ERROR_SUCCESS;
        use windows::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
        };

        let mut conns = HashSet::new();

        unsafe {
            // First call: obtain the required buffer size
            let mut buf_size: u32 = 0;
            GetExtendedTcpTable(
                None,
                &mut buf_size,
                false,
                2, // AF_INET
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if buf_size == 0 {
                return conns;
            }

            let mut buf: Vec<u8> = vec![0u8; buf_size as usize];
            let ret = GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut buf_size,
                false,
                2, // AF_INET
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if ret != ERROR_SUCCESS.0 {
                return conns;
            }

            // Buffer layout: u32 dwNumEntries, then dwNumEntries × MIB_TCPROW_OWNER_PID
            if buf.len() < 4 {
                return conns;
            }
            let num_entries = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            let row_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
            let base = 4usize; // skip dwNumEntries field

            for i in 0..num_entries {
                let start = base + i * row_size;
                let end = start + row_size;
                if end > buf.len() {
                    break;
                }

                let row: MIB_TCPROW_OWNER_PID =
                    std::ptr::read_unaligned(buf[start..end].as_ptr() as *const _);

                // dwState 5 == MIB_TCP_STATE_ESTAB
                if row.dwState != 5 {
                    continue;
                }

                let src_ip = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
                let dst_ip = Ipv4Addr::from(u32::from_be(row.dwRemoteAddr));
                let src_port = u16::from_be(row.dwLocalPort as u16);
                let dst_port = u16::from_be(row.dwRemotePort as u16);

                if dst_ip.is_loopback() {
                    continue;
                }

                conns.insert(ConnKey {
                    src: src_ip.to_string(),
                    src_port,
                    dst: dst_ip.to_string(),
                    dst_port,
                });
            }
        }

        conns
    }
}
