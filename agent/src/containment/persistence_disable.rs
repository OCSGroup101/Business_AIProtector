// Persistence disable containment — Phase 2

use anyhow::Result;
use tracing::info;

use crate::core::event_bus::TelemetryEvent;

pub async fn disable_persistence(event: &TelemetryEvent) -> Result<()> {
    // Phase 2: Implement based on persistence event payload type
    // - registry: delete registry key
    // - scheduled_task: schtasks /delete
    // - service: sc stop + sc delete
    info!(event_id = %event.event_id, "Persistence disable (Phase 2 — stub)");
    Ok(())
}
