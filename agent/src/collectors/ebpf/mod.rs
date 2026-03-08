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

// Entry point for eBPF-based collectors on Linux.
// Uses the `aya` crate to load and attach BPF programs.
// Feature gate: linux-ebpf
//
// Two eBPF programs are shipped as embedded bytecode:
//   process_monitor.bpf.o  — tracepoint sched/sched_process_exec → ProcessCreate
//   network_monitor.bpf.o  — tracepoint syscalls/sys_enter_connect → NetworkConnect
//
// The BPF program sources live in agent/src/bpf/. Build them with:
//   clang -target bpf -O2 -g \
//         -I /usr/include/$(uname -m)-linux-gnu \
//         -c src/bpf/process_monitor.bpf.c -o src/bpf/process_monitor.bpf.o
//   clang -target bpf -O2 -g \
//         -I /usr/include/$(uname -m)-linux-gnu \
//         -c src/bpf/network_monitor.bpf.c -o src/bpf/network_monitor.bpf.o
//
// The compiled .bpf.o objects must exist at build time for the embed to succeed.
// In CI, compile them as a build-script step before `cargo build --features linux-ebpf`.

pub mod network;
pub mod process;

use anyhow::{Context, Result};
use aya::maps::PerfEventArray;
use aya::programs::TracePoint;
use aya::util::nr_cpus;
use aya::Ebpf;
use bytes::BytesMut;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::config::AgentConfig;
use crate::core::event_bus::{EventBus, EventPublisher, OsInfo};

// ─── Embedded BPF object files ───────────────────────────────────────────────
//
// The compiled object files must be present on disk before this crate is built
// with `--features linux-ebpf`. If they are absent (e.g. on the build host
// before the BPF toolchain runs), define empty fallback bytes so the module
// still compiles — the loader will return an error at runtime instead of a
// compile-time panic.

#[cfg(linux_ebpf_objects_present)]
const PROCESS_MONITOR_OBJ: &[u8] =
    include_bytes!("../../../bpf/process_monitor.bpf.o");

#[cfg(linux_ebpf_objects_present)]
const NETWORK_MONITOR_OBJ: &[u8] =
    include_bytes!("../../../bpf/network_monitor.bpf.o");

#[cfg(not(linux_ebpf_objects_present))]
const PROCESS_MONITOR_OBJ: &[u8] = &[];

#[cfg(not(linux_ebpf_objects_present))]
const NETWORK_MONITOR_OBJ: &[u8] = &[];

// ─── EbpfCollector ───────────────────────────────────────────────────────────

/// Loads and runs both eBPF tracepoint programs, forwarding events to the
/// EventBus.
pub struct EbpfCollector;

impl EbpfCollector {
    /// Load eBPF programs, attach tracepoints, and pump events into `publisher`
    /// until an unrecoverable error occurs or the process exits.
    ///
    /// Requires `CAP_BPF` (or `CAP_SYS_ADMIN` on older kernels) and
    /// `CAP_PERFMON` (Linux 5.8+).
    pub async fn run(config: Arc<AgentConfig>, publisher: Arc<EventBus>) -> Result<()> {
        if PROCESS_MONITOR_OBJ.is_empty() || NETWORK_MONITOR_OBJ.is_empty() {
            anyhow::bail!(
                "eBPF object files not embedded — compile with `linux_ebpf_objects_present` \
                 cfg flag set (requires prior `clang -target bpf` build step)"
            );
        }

        let agent_id = config
            .platform
            .url
            .trim_start_matches("https://")
            .to_string();
        let tenant_id = "unknown".to_string(); // populated after enrollment
        let hostname = hostname();
        let os_info = current_os_info();

        let proc_publisher = publisher.publisher();
        let net_publisher = publisher.publisher();

        let proc_handle = tokio::task::spawn_blocking({
            let agent_id = agent_id.clone();
            let tenant_id = tenant_id.clone();
            let hostname = hostname.clone();
            let os_info = os_info.clone();
            move || {
                run_process_collector(proc_publisher, &agent_id, &tenant_id, &hostname, &os_info)
            }
        });

        let net_handle = tokio::task::spawn_blocking({
            let agent_id = agent_id.clone();
            let tenant_id = tenant_id.clone();
            let hostname = hostname.clone();
            let os_info = os_info.clone();
            move || {
                run_network_collector(net_publisher, &agent_id, &tenant_id, &hostname, &os_info)
            }
        });

        // Wait for either collector task to exit (they normally run indefinitely)
        let (result, _, _) = futures::future::select_all([proc_handle, net_handle]).await;
        match result {
            Ok(inner) => inner,
            Err(e) => Err(anyhow::anyhow!("eBPF collector task panicked: {}", e)),
        }
    }
}

// ─── Process collector (blocking) ─────────────────────────────────────────────

fn run_process_collector(
    publisher: EventPublisher,
    agent_id: &str,
    tenant_id: &str,
    hostname: &str,
    os_info: &OsInfo,
) -> Result<()> {
    let mut bpf = Ebpf::load(PROCESS_MONITOR_OBJ)
        .context("failed to load process_monitor BPF object")?;

    // Attach to tracepoint sched/sched_process_exec
    let prog: &mut TracePoint = bpf
        .program_mut("handle_exec")
        .context("BPF program 'handle_exec' not found")?
        .try_into()
        .context("program is not a TracePoint")?;

    prog.load().context("failed to load handle_exec into kernel")?;
    prog.attach("sched", "sched_process_exec")
        .context("failed to attach handle_exec tracepoint")?;

    info!("eBPF process_monitor attached to sched/sched_process_exec");

    // Open the perf event array
    let map = bpf
        .take_map("PROCESS_EVENTS")
        .context("PROCESS_EVENTS map not found")?;
    let mut perf_array: PerfEventArray<_> = PerfEventArray::try_from(map)
        .context("failed to create PerfEventArray for PROCESS_EVENTS")?;

    // Open a perf buffer for each online CPU
    let cpu_count = nr_cpus().unwrap_or(1) as u32;
    let mut buffers: Vec<_> = (0..cpu_count)
        .filter_map(|cpu_id| {
            perf_array
                .open(cpu_id, None)
                .map_err(|e| {
                    warn!(cpu_id, err = %e, "failed to open PROCESS_EVENTS perf buffer");
                    e
                })
                .ok()
        })
        .collect();

    if buffers.is_empty() {
        anyhow::bail!("no PROCESS_EVENTS perf buffers could be opened");
    }

    // aya's PerfBuffer::read_events takes a &mut [BytesMut] and fills each
    // buffer with the raw bytes of one event from the kernel perf ring.
    let mut event_bufs: Vec<BytesMut> = (0..16).map(|_| BytesMut::with_capacity(4096)).collect();

    loop {
        for buf in &mut buffers {
            match buf.read_events(&mut event_bufs) {
                Ok(info) => {
                    for i in 0..info.read {
                        if let Some(evt) = process::parse_process_event(
                            &event_bufs[i],
                            agent_id,
                            tenant_id,
                            hostname,
                            os_info,
                        ) {
                            publisher.publish(evt);
                        }
                    }
                }
                Err(e) => {
                    error!(err = %e, "PROCESS_EVENTS perf read error");
                }
            }
        }
        // Yield to avoid spinning at 100% CPU when the event rate is low
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

// ─── Network collector (blocking) ─────────────────────────────────────────────

fn run_network_collector(
    publisher: EventPublisher,
    agent_id: &str,
    tenant_id: &str,
    hostname: &str,
    os_info: &OsInfo,
) -> Result<()> {
    let mut bpf = Ebpf::load(NETWORK_MONITOR_OBJ)
        .context("failed to load network_monitor BPF object")?;

    let prog: &mut TracePoint = bpf
        .program_mut("handle_connect")
        .context("BPF program 'handle_connect' not found")?
        .try_into()
        .context("program is not a TracePoint")?;

    prog.load().context("failed to load handle_connect into kernel")?;
    prog.attach("syscalls", "sys_enter_connect")
        .context("failed to attach handle_connect tracepoint")?;

    info!("eBPF network_monitor attached to syscalls/sys_enter_connect");

    let map = bpf
        .take_map("NETWORK_EVENTS")
        .context("NETWORK_EVENTS map not found")?;
    let mut perf_array: PerfEventArray<_> = PerfEventArray::try_from(map)
        .context("failed to create PerfEventArray for NETWORK_EVENTS")?;

    let cpu_count = nr_cpus().unwrap_or(1) as u32;
    let mut buffers: Vec<_> = (0..cpu_count)
        .filter_map(|cpu_id| {
            perf_array
                .open(cpu_id, None)
                .map_err(|e| {
                    warn!(cpu_id, err = %e, "failed to open NETWORK_EVENTS perf buffer");
                    e
                })
                .ok()
        })
        .collect();

    if buffers.is_empty() {
        anyhow::bail!("no NETWORK_EVENTS perf buffers could be opened");
    }

    let mut event_bufs: Vec<BytesMut> = (0..16).map(|_| BytesMut::with_capacity(256)).collect();

    loop {
        for buf in &mut buffers {
            match buf.read_events(&mut event_bufs) {
                Ok(info) => {
                    for i in 0..info.read {
                        if let Some(evt) = network::parse_network_event(
                            &event_bufs[i],
                            agent_id,
                            tenant_id,
                            hostname,
                            os_info,
                        ) {
                            publisher.publish(evt);
                        }
                    }
                }
                Err(e) => {
                    error!(err = %e, "NETWORK_EVENTS perf read error");
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn current_os_info() -> OsInfo {
    OsInfo {
        platform: "linux".to_string(),
        version: std::fs::read_to_string("/proc/version")
            .unwrap_or_default()
            .lines()
            .next()
            .unwrap_or("unknown")
            .to_string(),
        arch: std::env::consts::ARCH.to_string(),
    }
}
