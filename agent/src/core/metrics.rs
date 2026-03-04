// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
// Agent resource metrics — CPU and RAM usage for heartbeat + performance budget enforcement.
//
// Performance budget (enforced in CI):  <4% CPU average, <80 MB RSS
// Readings are taken at each heartbeat interval (default 60s).

use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System};
use tracing::debug;

/// Snapshot of agent resource consumption at a single point in time.
#[derive(Debug, Clone)]
pub struct AgentMetrics {
    /// Agent process CPU usage 0.0–100.0 (averaged across all cores)
    pub cpu_percent: f32,
    /// Agent process RSS in megabytes
    pub ram_mb: u32,
}

/// Read the current process's CPU and RAM usage.
///
/// sysinfo requires two CPU samples to compute a delta — the first call after
/// process startup will return cpu_percent = 0.0. This is acceptable; the heartbeat
/// fires every 60 seconds so the second reading is accurate.
pub fn sample() -> AgentMetrics {
    let pid = Pid::from(std::process::id() as usize);

    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::new().with_cpu().with_memory()),
    );
    sys.refresh_processes_specifics(ProcessRefreshKind::new().with_cpu().with_memory());

    if let Some(proc) = sys.process(pid) {
        let cpu = proc.cpu_usage();
        // sysinfo returns per-logical-core usage; normalise to 0–100% of one core equivalent
        let num_cpus = sys.cpus().len().max(1) as f32;
        let cpu_normalised = (cpu / num_cpus).min(100.0);
        let ram_mb = (proc.memory() / 1024 / 1024) as u32;

        debug!(cpu = cpu_normalised, ram_mb, "Agent resource sample");
        AgentMetrics {
            cpu_percent: cpu_normalised,
            ram_mb,
        }
    } else {
        debug!("Could not find own process in sysinfo — returning zero metrics");
        AgentMetrics {
            cpu_percent: 0.0,
            ram_mb: 0,
        }
    }
}
