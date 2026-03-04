// Periodic task scheduler for the agent.
// Wraps tokio::time::interval to run recurring tasks (heartbeat, telemetry upload, etc.)
// Each scheduled task gets its own tokio task.

use anyhow::Result;
use std::future::Future;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{debug, error};

/// A handle to a running scheduled task.
pub struct ScheduledTask {
    handle: JoinHandle<()>,
    name: String,
}

impl ScheduledTask {
    /// Abort the scheduled task.
    pub fn abort(&self) {
        self.handle.abort();
        debug!(task = %self.name, "Scheduled task aborted");
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Schedule a recurring async task at a fixed interval.
///
/// The task runs immediately on first tick, then every `interval`.
/// If the task panics, the error is logged and the task is NOT restarted
/// (the JoinHandle will be done). Callers should check `handle.is_finished()`
/// in their health checks.
pub fn schedule<F, Fut>(name: impl Into<String>, interval: Duration, mut task: F) -> ScheduledTask
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    let name = name.into();
    let task_name = name.clone();

    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            debug!(task = %task_name, "Running scheduled task");
            if let Err(e) = task().await {
                error!(task = %task_name, error = %e, "Scheduled task failed");
                // Continue — don't crash the agent on a transient failure
            }
        }
    });

    ScheduledTask { handle, name }
}

/// Schedule a one-shot task with a delay.
pub fn schedule_once<F, Fut>(name: impl Into<String>, delay: Duration, task: F) -> ScheduledTask
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    let name = name.into();
    let task_name = name.clone();

    let handle = tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        debug!(task = %task_name, "Running one-shot task");
        if let Err(e) = task().await {
            error!(task = %task_name, error = %e, "One-shot task failed");
        }
    });

    ScheduledTask { handle, name }
}
