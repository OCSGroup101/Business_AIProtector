// SQLite-backed ring buffer — stores up to N telemetry events locally.
// Events are uploaded in batches; once confirmed uploaded they are deleted.
// On reconnect, any buffered events are uploaded before new ones.

use anyhow::Result;
use rusqlite::{Connection, params};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{debug, warn};

use crate::core::event_bus::TelemetryEvent;

pub struct RingBuffer {
    inner: Arc<Mutex<RingBufferInner>>,
    capacity: usize,
}

struct RingBufferInner {
    conn: Connection,
}

impl RingBuffer {
    pub fn open(data_dir: &PathBuf, capacity: usize) -> Result<Self> {
        let db_path = data_dir.join("ring-buffer.db");
        let conn = Connection::open(&db_path)?;
        init_schema(&conn)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(RingBufferInner { conn })),
            capacity,
        })
    }

    /// Append an event. If at capacity, drops the oldest event (ring behaviour).
    pub fn push(&self, event: &TelemetryEvent) -> Result<()> {
        let json = serde_json::to_string(event)?;
        let inner = self.inner.lock().unwrap();

        // Enforce capacity — drop oldest if needed
        let count: usize = inner.conn.query_row(
            "SELECT COUNT(*) FROM events",
            [],
            |r| r.get(0),
        )?;

        if count >= self.capacity {
            let dropped = self.capacity / 10; // evict 10% at a time
            inner.conn.execute(
                "DELETE FROM events WHERE rowid IN (
                    SELECT rowid FROM events ORDER BY seq ASC LIMIT ?1
                )",
                params![dropped],
            )?;
            warn!(dropped, capacity = self.capacity, "Ring buffer full — oldest events evicted");
        }

        inner.conn.execute(
            "INSERT INTO events (event_id, event_json, uploaded) VALUES (?1, ?2, 0)",
            params![event.event_id, json],
        )?;
        Ok(())
    }

    /// Fetch up to `limit` unuploaded events for batch upload.
    pub fn pending_batch(&self, limit: usize) -> Result<Vec<TelemetryEvent>> {
        let inner = self.inner.lock().unwrap();
        let mut stmt = inner.conn.prepare(
            "SELECT event_json FROM events WHERE uploaded = 0 ORDER BY seq ASC LIMIT ?1",
        )?;
        let events: Vec<TelemetryEvent> = stmt
            .query_map(params![limit], |row| row.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .filter_map(|json| serde_json::from_str(&json).ok())
            .collect();
        debug!(count = events.len(), "Fetched pending batch from ring buffer");
        Ok(events)
    }

    /// Mark events as uploaded (will be purged on next maintenance cycle).
    pub fn mark_uploaded(&self, event_ids: &[String]) -> Result<()> {
        if event_ids.is_empty() {
            return Ok(());
        }
        let inner = self.inner.lock().unwrap();
        let placeholders = event_ids
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", i + 1))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "UPDATE events SET uploaded = 1 WHERE event_id IN ({})",
            placeholders
        );
        let mut stmt = inner.conn.prepare(&sql)?;
        let params: Vec<&dyn rusqlite::ToSql> =
            event_ids.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        stmt.execute(params.as_slice())?;
        Ok(())
    }

    /// Delete uploaded events (housekeeping — call periodically).
    pub fn purge_uploaded(&self) -> Result<usize> {
        let inner = self.inner.lock().unwrap();
        let deleted = inner.conn.execute(
            "DELETE FROM events WHERE uploaded = 1",
            [],
        )?;
        if deleted > 0 {
            debug!(deleted, "Purged uploaded events from ring buffer");
        }
        Ok(deleted)
    }

    /// Percentage of capacity currently used (0–100).
    pub fn fill_pct(&self) -> u8 {
        let inner = self.inner.lock().unwrap();
        let count: usize = inner
            .conn
            .query_row("SELECT COUNT(*) FROM events WHERE uploaded = 0", [], |r| {
                r.get(0)
            })
            .unwrap_or(0);
        ((count * 100) / self.capacity.max(1)).min(100) as u8
    }

    pub fn pending_count(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner
            .conn
            .query_row("SELECT COUNT(*) FROM events WHERE uploaded = 0", [], |r| {
                r.get(0)
            })
            .unwrap_or(0)
    }
}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS events (
            seq        INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id   TEXT NOT NULL UNIQUE,
            event_json TEXT NOT NULL,
            uploaded   INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_events_uploaded ON events(uploaded, seq);
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA page_size = 4096;",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event_bus::{EventType, OsInfo, TelemetryEvent};
    use tempfile::TempDir;

    fn make_event(id: &str) -> TelemetryEvent {
        let mut e = TelemetryEvent::new(
            "agt_test", "ten_test", "test",
            EventType::ProcessCreate, "host",
            OsInfo { platform: "test".into(), version: "0".into(), arch: "x64".into() },
        );
        e.event_id = format!("evt_{}", id);
        e
    }

    #[test]
    fn test_push_and_pending() {
        let dir = TempDir::new().unwrap();
        let buf = RingBuffer::open(&dir.path().to_path_buf(), 100).unwrap();

        buf.push(&make_event("001")).unwrap();
        buf.push(&make_event("002")).unwrap();

        let batch = buf.pending_batch(10).unwrap();
        assert_eq!(batch.len(), 2);
    }

    #[test]
    fn test_mark_uploaded_and_purge() {
        let dir = TempDir::new().unwrap();
        let buf = RingBuffer::open(&dir.path().to_path_buf(), 100).unwrap();

        let e = make_event("abc");
        buf.push(&e).unwrap();
        buf.mark_uploaded(&[e.event_id.clone()]).unwrap();

        let pending = buf.pending_batch(10).unwrap();
        assert_eq!(pending.len(), 0);

        let purged = buf.purge_uploaded().unwrap();
        assert_eq!(purged, 1);
    }

    #[test]
    fn test_ring_capacity_eviction() {
        let dir = TempDir::new().unwrap();
        let buf = RingBuffer::open(&dir.path().to_path_buf(), 10).unwrap();

        for i in 0..15 {
            buf.push(&make_event(&format!("{:03}", i))).unwrap();
        }

        // Fill pct should not exceed 100
        assert!(buf.fill_pct() <= 100);
        // Count should be ≤ capacity
        assert!(buf.pending_count() <= 10);
    }
}
