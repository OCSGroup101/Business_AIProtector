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

// Process Collector
//
// Windows: ETW provider {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716} (Microsoft-Windows-Kernel-Process)
//   — Requires SeSystemProfilePrivilege (elevated agent). Falls back to stub if not elevated.
//   — Emits ProcessCreate on EventID 1, ProcessTerminate on EventID 2.
//   — SHA-256 of the new process binary is computed on-demand from the image path.
//
// macOS:   Endpoint Security Framework (ESF) — Phase 3
// Linux:   eBPF (aya crate) — Phase 3
//
// Emits: EventType::ProcessCreate, EventType::ProcessTerminate

use anyhow::Result;
use async_trait::async_trait;
use serde_json::json;
use tracing::warn;

use crate::collectors::Collector;
use crate::config::AgentConfig;
use crate::core::event_bus::{EventPublisher, EventType, OsInfo, Severity, TelemetryEvent};

pub struct ProcessCollector {
    agent_id: String,
    tenant_id: String,
    hostname: String,
    os_info: OsInfo,
}

impl ProcessCollector {
    pub fn new(cfg: &AgentConfig, agent_id: &str, tenant_id: &str) -> Result<Self> {
        let _ = cfg;
        Ok(Self {
            agent_id: agent_id.to_string(),
            tenant_id: tenant_id.to_string(),
            hostname: hostname(),
            os_info: current_os_info(),
        })
    }

    fn make_event(&self, event_type: EventType) -> TelemetryEvent {
        TelemetryEvent::new(
            &self.agent_id,
            &self.tenant_id,
            "process",
            event_type,
            &self.hostname,
            self.os_info.clone(),
        )
    }
}

#[async_trait]
impl Collector for ProcessCollector {
    fn name(&self) -> &'static str {
        "process"
    }

    async fn run(self: Box<Self>, publisher: EventPublisher) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            run_windows(*self, publisher).await
        }
        #[cfg(target_os = "macos")]
        {
            tracing::info!("macOS ESF process collector (Phase 3 — stub mode)");
            run_stub(*self, publisher).await
        }
        #[cfg(target_os = "linux")]
        {
            tracing::info!("Linux eBPF process collector (Phase 3 — stub mode)");
            run_stub(*self, publisher).await
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            warn!("ProcessCollector: unsupported platform — running in stub mode");
            run_stub(*self, publisher).await
        }
    }
}

// ─── Windows ETW Implementation ───────────────────────────────────────────────

#[cfg(target_os = "windows")]
async fn run_windows(collector: ProcessCollector, publisher: EventPublisher) -> Result<()> {
    match etw::start_session() {
        Ok((session, trace)) => {
            info!("ETW ProcessCollector started (provider: 22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716)");
            etw::run_relay(collector, publisher, session, trace).await
        }
        Err(e) => {
            warn!(
                error = %e,
                "ETW session failed to start (not elevated?). \
                 Falling back to stub mode — process telemetry will be synthetic."
            );
            run_stub(collector, publisher).await
        }
    }
}

/// Windows ETW session management and event parsing.
#[cfg(target_os = "windows")]
mod etw {
    use super::*;
    use std::cell::RefCell;
    use std::mem;
    use std::sync::mpsc;

    use windows::core::{GUID, PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
    use windows::Win32::System::Diagnostics::Etw::{
        CloseTrace, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW, StopTraceW,
        CONTROLTRACE_HANDLE, EVENT_RECORD, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
        PROCESSTRACE_HANDLE,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    // Provider: Microsoft-Windows-Kernel-Process {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
    const KERNEL_PROCESS_GUID: GUID = GUID {
        data1: 0x22FB2CD6,
        data2: 0x0E7B,
        data3: 0x422B,
        data4: [0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16],
    };

    // ETW constants not always re-exported by windows crate in all versions
    const WNODE_FLAG_TRACED_GUID: u32 = 0x0002_0000;
    const EVENT_TRACE_REAL_TIME_MODE: u32 = 0x0000_0100;
    const PROCESS_TRACE_MODE_REAL_TIME: u32 = 0x0000_0100;
    const PROCESS_TRACE_MODE_EVENT_RECORD: u32 = 0x1000_0000;
    const EVENT_CONTROL_CODE_ENABLE_PROVIDER: u32 = 1;
    const TRACE_LEVEL_INFORMATION: u8 = 4;
    const PROCESS_KEYWORD: u64 = 0x10;

    const EVENT_ID_PROCESS_START: u16 = 1;
    const EVENT_ID_PROCESS_STOP: u16 = 2;

    // Session name as a static UTF-16 null-terminated string — pointer lifetime is 'static
    static SESSION_NAME_W: &[u16] = &[
        b'O' as u16,
        b'p' as u16,
        b'e' as u16,
        b'n' as u16,
        b'C' as u16,
        b'l' as u16,
        b'a' as u16,
        b'w' as u16,
        b'E' as u16,
        b'T' as u16,
        b'W' as u16,
        0u16,
    ];

    /// Data extracted from a raw ETW ProcessStart/ProcessStop event.
    #[derive(Debug)]
    pub struct RawProcessEvent {
        pub is_start: bool,
        pub pid: u32,
        pub ppid: u32,
        pub image_path: String,
        pub exit_code: Option<i32>,
    }

    // Thread-local sender for the C callback → Rust bridge.
    // ETW calls the callback on the same thread as ProcessTrace.
    thread_local! {
        static ETW_SENDER: RefCell<Option<mpsc::SyncSender<RawProcessEvent>>>
            = RefCell::new(None);
    }

    /// ETW event record callback — called by ProcessTrace on every event.
    /// Must be `unsafe extern "system"`.
    unsafe extern "system" fn on_event_record(record: *mut EVENT_RECORD) {
        // SAFETY: record is a valid non-null pointer provided by the ETW runtime for
        // the duration of this callback. We take a shared reference and do not store it.
        if record.is_null() {
            return;
        }
        let record = &*record;

        let event_id = record.EventHeader.EventDescriptor.Id;
        let raw = match event_id {
            EVENT_ID_PROCESS_START => parse_process_start(record),
            EVENT_ID_PROCESS_STOP => parse_process_stop(record),
            _ => return,
        };

        if let Some(event) = raw {
            ETW_SENDER.with(|s| {
                if let Some(sender) = s.borrow().as_ref() {
                    // try_send: drop event if channel is full rather than blocking
                    // the ETW thread (which would stall the kernel event session).
                    let _ = sender.try_send(event);
                }
            });
        }
    }

    /// Parse a ProcessStart (EventID 1) UserData buffer.
    ///
    /// Microsoft-Windows-Kernel-Process manifest layout for EventID 1:
    ///   Offset  0: ProcessID      (UINT32)
    ///   Offset  4: ParentProcessID (UINT32)
    ///   Offset  8: ImageFileName  (null-terminated UTF-16 string)
    ///   (more fields follow, not needed for Phase 1)
    unsafe fn parse_process_start(record: &EVENT_RECORD) -> Option<RawProcessEvent> {
        // SAFETY: UserData points to the event payload buffer owned by the ETW runtime
        // for the lifetime of this callback. UserDataLength gives the valid byte count.
        let data = std::slice::from_raw_parts(
            record.UserData as *const u8,
            record.UserDataLength as usize,
        );

        if data.len() < 8 {
            return None;
        }

        let pid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let ppid = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        // Query the OS for the full image path — more reliable than parsing the ETW
        // string field, and gives us the path even if the string offset varies by version.
        let image_path = get_process_image_path(pid).unwrap_or_else(|| "<unknown>".to_string());

        Some(RawProcessEvent {
            is_start: true,
            pid,
            ppid,
            image_path,
            exit_code: None,
        })
    }

    /// Parse a ProcessStop (EventID 2) UserData buffer.
    ///
    /// Layout:
    ///   Offset  0: ProcessID  (UINT32)
    ///   Offset  4: ExitCode   (INT32)
    unsafe fn parse_process_stop(record: &EVENT_RECORD) -> Option<RawProcessEvent> {
        // SAFETY: same as parse_process_start.
        let data = std::slice::from_raw_parts(
            record.UserData as *const u8,
            record.UserDataLength as usize,
        );

        if data.len() < 8 {
            return None;
        }

        let pid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let exit_code = i32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        Some(RawProcessEvent {
            is_start: false,
            pid,
            ppid: 0,
            image_path: String::new(),
            exit_code: Some(exit_code),
        })
    }

    /// Query the OS for the full image path of a running process by PID.
    ///
    /// Uses `QueryFullProcessImageNameW` which works even for protected processes
    /// when `PROCESS_QUERY_LIMITED_INFORMATION` is sufficient.
    unsafe fn get_process_image_path(pid: u32) -> Option<String> {
        // SAFETY: OpenProcess returns NULL on failure, which .ok() converts to None.
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;

        let mut buf = [0u16; 1024];
        let mut size = 1024u32;

        // SAFETY: buf is a valid array of the size reported in `size`. handle is valid
        // (checked by .ok() above). CloseHandle is called unconditionally below.
        let result = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        );

        // Always close the handle — do not return early before this point.
        let _ = CloseHandle(handle);

        result.ok()?;
        Some(String::from_utf16_lossy(&buf[..size as usize]))
    }

    /// Allocate an EVENT_TRACE_PROPERTIES buffer with the session name appended.
    ///
    /// The Windows API requires the struct followed immediately by the session name
    /// string in the same allocation, with `LoggerNameOffset` pointing to the string.
    fn alloc_trace_properties() -> Vec<u8> {
        let name_bytes = SESSION_NAME_W.len() * 2; // UTF-16 bytes
        let total = mem::size_of::<EVENT_TRACE_PROPERTIES>() + name_bytes;
        let mut buf = vec![0u8; total];

        // SAFETY: buf is exactly `total` bytes, properly aligned (Vec<u8> guarantees
        // alignment ≥ 1, and EVENT_TRACE_PROPERTIES requires ≤ 8-byte alignment on x64).
        // We write only within bounds.
        unsafe {
            let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
            (*props).Wnode.BufferSize = total as u32;
            (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            (*props).LoggerNameOffset = mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;

            let name_dst = std::slice::from_raw_parts_mut(
                buf.as_mut_ptr()
                    .add(mem::size_of::<EVENT_TRACE_PROPERTIES>()) as *mut u16,
                SESSION_NAME_W.len(),
            );
            name_dst.copy_from_slice(SESSION_NAME_W);
        }

        buf
    }

    /// Start (or restart) the ETW trace session.
    /// Returns the session handle and the props buffer (must stay alive for StopTraceW).
    pub fn start_session() -> Result<(CONTROLTRACE_HANDLE, Vec<u8>)> {
        let session_name = PCWSTR::from_raw(SESSION_NAME_W.as_ptr());
        let mut buf = alloc_trace_properties();
        let mut session_handle = CONTROLTRACE_HANDLE(0);

        let props_ptr = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        // SAFETY: buf is correctly sized and session_name is a valid static 'static pointer.
        let result = unsafe { StartTraceW(&mut session_handle, session_name, props_ptr) };

        if result == ERROR_ALREADY_EXISTS {
            // A previous (possibly crashed) agent instance left an ETW session open.
            // Stop it cleanly, then start fresh.
            tracing::debug!("ETW session already exists — stopping and restarting");
            let _ = unsafe { StopTraceW(CONTROLTRACE_HANDLE(0), session_name, props_ptr) };

            // Re-zero the buffer after StopTraceW may have modified it
            buf = alloc_trace_properties();
            let props_ptr = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
            unsafe { StartTraceW(&mut session_handle, session_name, props_ptr) }
                .ok()
                .map_err(|e| anyhow::anyhow!("StartTraceW (retry): {}", e))?;
        } else {
            result
                .ok()
                .map_err(|e| anyhow::anyhow!("StartTraceW: {}", e))?;
        }

        // Enable the Microsoft-Windows-Kernel-Process provider on our session
        // SAFETY: session_handle is valid (StartTraceW succeeded). GUID pointer is 'static.
        let rc = unsafe {
            EnableTraceEx2(
                session_handle,
                &KERNEL_PROCESS_GUID,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_INFORMATION,
                PROCESS_KEYWORD,
                0,
                0,
                std::ptr::null(),
            )
        };

        if rc != ERROR_SUCCESS {
            // Clean up the session we just started
            unsafe { StopTraceW(session_handle, session_name, props_ptr) };
            anyhow::bail!("EnableTraceEx2 failed: {}", rc.0);
        }

        Ok((session_handle, buf))
    }

    /// Open the real-time trace for consumption and return a PROCESSTRACE_HANDLE.
    pub fn open_trace() -> Result<PROCESSTRACE_HANDLE> {
        // SAFETY: SESSION_NAME_W is a valid static null-terminated UTF-16 string.
        // EVENT_TRACE_LOGFILEW is zero-initialized (zeroed() is safe for POD types).
        let mut logfile = unsafe { mem::zeroed::<EVENT_TRACE_LOGFILEW>() };

        // LoggerName: non-const PWSTR — ETW won't modify it
        logfile.LoggerName = PWSTR(SESSION_NAME_W.as_ptr() as *mut u16);

        // SAFETY: union field write — ProcessTraceMode and EventRecordCallback are
        // the only fields we set; the rest remain zero from zeroed().
        unsafe {
            logfile.Anonymous1.ProcessTraceMode =
                PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            logfile.Anonymous2.EventRecordCallback = Some(on_event_record);
        }

        let handle = unsafe { OpenTraceW(&mut logfile) };

        // INVALID_PROCESSTRACE_HANDLE is represented as isize::MAX (0x7FFFFFFF...FF)
        // on x64, which equals u64::MAX when reinterpreted. Check for the sentinel.
        if handle.0 == isize::MAX {
            anyhow::bail!(
                "OpenTraceW failed — is the ETW session running? ({})",
                unsafe { windows::Win32::Foundation::GetLastError().0 }
            );
        }

        Ok(handle)
    }

    /// Main async relay loop.
    ///
    /// Architecture:
    ///   ETW callback (C, sync) → std::sync::mpsc → spawn_blocking relay → tokio::mpsc → async loop
    pub async fn run_relay(
        collector: ProcessCollector,
        publisher: EventPublisher,
        session_handle: CONTROLTRACE_HANDLE,
        props_buf: Vec<u8>,
    ) -> Result<()> {
        // Bridge: C callback writes to std_tx (non-async, try_send — drops on overflow)
        let (std_tx, std_rx) = mpsc::sync_channel::<RawProcessEvent>(2048);

        // Async channel: relay thread writes here, async loop reads
        let (tokio_tx, mut tokio_rx) = tokio::sync::mpsc::channel::<RawProcessEvent>(2048);

        // Open the real-time trace for event consumption
        let trace_handle = open_trace()?;

        // ETW processing thread — ProcessTrace blocks until CloseTrace is called
        let std_tx_etw = std_tx;
        std::thread::Builder::new()
            .name("openclaw-etw".to_string())
            .spawn(move || {
                // SAFETY: Installing into thread-local before ProcessTrace so the
                // callback can always find the sender on this thread.
                ETW_SENDER.with(|s| {
                    *s.borrow_mut() = Some(std_tx_etw);
                });

                // SAFETY: trace_handle is valid (open_trace succeeded). ProcessTrace
                // blocks here and invokes on_event_record for each event.
                unsafe {
                    let handles = [trace_handle];
                    ProcessTrace(handles.as_ptr(), 1, std::ptr::null(), std::ptr::null());
                }

                tracing::debug!("ETW ProcessTrace thread exiting");
            })?;

        // Relay thread — bridges std::sync::mpsc (blocking) → tokio::mpsc (async)
        tokio::task::spawn_blocking(move || {
            while let Ok(event) = std_rx.recv() {
                if tokio_tx.blocking_send(event).is_err() {
                    break; // receiver dropped — tokio runtime shutting down
                }
            }
        });

        // Async consumer loop
        while let Some(raw) = tokio_rx.recv().await {
            let event = make_event(&collector, &raw);
            publisher.publish(event);
        }

        // Cleanup: stop the ETW session (CloseTrace is implicit when the ETW thread exits)
        let session_name = PCWSTR::from_raw(SESSION_NAME_W.as_ptr());
        let props_ptr = props_buf.as_ptr() as *mut EVENT_TRACE_PROPERTIES;
        // SAFETY: session_handle is valid. props_ptr points to the buffer we own.
        unsafe {
            let _ = StopTraceW(session_handle, session_name, props_ptr);
        }

        Ok(())
    }

    /// Build a TelemetryEvent from a raw ETW process event.
    fn make_event(collector: &ProcessCollector, raw: &RawProcessEvent) -> TelemetryEvent {
        let event_type = if raw.is_start {
            EventType::ProcessCreate
        } else {
            EventType::ProcessTerminate
        };

        let mut event = collector.make_event(event_type);
        event.payload.insert("pid".into(), json!(raw.pid));

        if raw.is_start {
            event.payload.insert("ppid".into(), json!(raw.ppid));
            event
                .payload
                .insert("image_path".into(), json!(&raw.image_path));

            // Derive short process name from the full path
            let process_name = std::path::Path::new(&raw.image_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("<unknown>");
            event
                .payload
                .insert("process_name".into(), json!(process_name));

            // Compute SHA-256 of the binary for IOC matching
            if let Ok(data) = std::fs::read(&raw.image_path) {
                let digest = sha256_hex(&data);
                event.payload.insert("hash_sha256".into(), json!(digest));
            }
        } else if let Some(exit_code) = raw.exit_code {
            event.payload.insert("exit_code".into(), json!(exit_code));
        }

        event
    }

    fn sha256_hex(data: &[u8]) -> String {
        use ring::digest;
        let d = digest::digest(&digest::SHA256, data);
        hex::encode(d.as_ref())
    }
} // mod etw

// ─── Stub (cross-platform integration testing) ───────────────────────────────

/// Emits synthetic events every 5 seconds — used on non-Windows and as an
/// elevation fallback. Useful for integration testing without real telemetry.
async fn run_stub(collector: ProcessCollector, publisher: EventPublisher) -> Result<()> {
    use tokio::time::{sleep, Duration};

    warn!("ProcessCollector running in stub mode — events are synthetic");

    loop {
        sleep(Duration::from_secs(5)).await;

        let mut event = collector.make_event(EventType::ProcessCreate);
        event.severity = Severity::Info;
        event
            .payload
            .insert("process_name".into(), json!("stub.exe"));
        event.payload.insert("pid".into(), json!(1234u32));
        event.payload.insert("ppid".into(), json!(5678u32));
        event
            .payload
            .insert("cmdline".into(), json!("stub.exe --test"));
        event
            .payload
            .insert("image_path".into(), json!("C:\\stub\\stub.exe"));
        event.payload.insert(
            "hash_sha256".into(),
            json!("0000000000000000000000000000000000000000000000000000000000000000"),
        );
        event.payload.insert("stub".into(), json!(true));

        publisher.publish(event);
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

pub(crate) fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

pub(crate) fn current_os_info() -> OsInfo {
    OsInfo {
        platform: std::env::consts::OS.to_string(),
        version: os_version(),
        arch: std::env::consts::ARCH.to_string(),
    }
}

fn os_version() -> String {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|s| {
                s.lines().find(|l| l.starts_with("PRETTY_NAME=")).map(|l| {
                    l.trim_start_matches("PRETTY_NAME=")
                        .trim_matches('"')
                        .to_string()
                })
            })
            .unwrap_or_else(|| "Linux".to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        "unknown".to_string()
    }
}

// Re-exported for sibling collectors to avoid duplication
pub(crate) fn hostname_stub() -> String {
    hostname()
}
pub(crate) fn os_info_stub() -> OsInfo {
    current_os_info()
}
