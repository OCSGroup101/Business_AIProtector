// IOC Store — LMDB-backed hash/IP/domain lookup
//
// Provides O(1) P99 <1ms lookup for known-bad indicators.
// Populated from signed intel bundles received from the platform.
//
// IOC types: file_hash (SHA-256), ip_address, domain, url

use anyhow::Result;
use lmdb_rkv::{Database, DatabaseFlags, Environment, EnvironmentFlags, Transaction, WriteFlags};
use std::path::Path;
use tracing::{debug, info};

pub struct IocStore {
    env: Environment,
    db: Database,
}

impl IocStore {
    pub fn open(data_dir: &Path) -> Result<Self> {
        let lmdb_path = data_dir.join("ioc-store.lmdb");
        std::fs::create_dir_all(&lmdb_path)?;

        let env = Environment::new()
            .set_flags(EnvironmentFlags::NO_SYNC | EnvironmentFlags::MAP_ASYNC)
            .set_max_dbs(4)
            .set_map_size(512 * 1024 * 1024) // 512 MB max map
            .open(&lmdb_path)?;

        let db = {
            let mut txn = env.begin_rw_txn()?;
            let db = txn.open_db(Some("iocs"), DatabaseFlags::empty())?;
            txn.commit()?;
            db
        };

        info!("IOC store opened at {:?}", lmdb_path);
        Ok(Self { env, db })
    }

    /// Look up a value (hash/IP/domain) in the IOC store.
    /// Key format: `{ioc_type}:{value}`, e.g. `file_hash:abc123...`
    pub fn contains(&self, ioc_type: &str, value: &str) -> bool {
        let key = format!("{}:{}", ioc_type, value.to_lowercase());
        let txn = match self.env.begin_ro_txn() {
            Ok(t) => t,
            Err(_) => return false,
        };
        match txn.get(self.db, &key.as_bytes()) {
            Ok(_) => true,
            Err(lmdb_rkv::Error::NotFound) => false,
            Err(e) => {
                debug!(error = %e, key = %key, "IOC lookup error");
                false
            }
        }
    }

    /// Insert an IOC with metadata JSON (confidence score, source, expiry).
    pub fn insert(&self, ioc_type: &str, value: &str, metadata: &str) -> Result<()> {
        let key = format!("{}:{}", ioc_type, value.to_lowercase());
        let mut txn = self.env.begin_rw_txn()?;
        txn.put(self.db, &key.as_bytes(), &metadata.as_bytes(), WriteFlags::empty())?;
        txn.commit()?;
        Ok(())
    }

    /// Bulk insert from an iterator of (ioc_type, value, metadata) triples.
    /// Uses a single write transaction for efficiency.
    pub fn bulk_insert<'a>(
        &self,
        iocs: impl Iterator<Item = (&'a str, &'a str, &'a str)>,
    ) -> Result<usize> {
        let mut txn = self.env.begin_rw_txn()?;
        let mut count = 0;
        for (ioc_type, value, metadata) in iocs {
            let key = format!("{}:{}", ioc_type, value.to_lowercase());
            txn.put(self.db, &key.as_bytes(), &metadata.as_bytes(), WriteFlags::empty())?;
            count += 1;
        }
        txn.commit()?;
        debug!(count, "Bulk IOC insert complete");
        Ok(count)
    }

    /// Remove an expired or revoked IOC.
    pub fn remove(&self, ioc_type: &str, value: &str) -> Result<bool> {
        let key = format!("{}:{}", ioc_type, value.to_lowercase());
        let mut txn = self.env.begin_rw_txn()?;
        match txn.del(self.db, &key.as_bytes(), None) {
            Ok(()) => { txn.commit()?; Ok(true) }
            Err(lmdb_rkv::Error::NotFound) => { Ok(false) }
            Err(e) => Err(e.into()),
        }
    }

    pub fn count(&self) -> usize {
        let txn = match self.env.begin_ro_txn() {
            Ok(t) => t,
            Err(_) => return 0,
        };
        txn.open_db(Some("iocs"))
            .and_then(|db| txn.stat(db))
            .map(|stat| stat.entries())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_insert_and_lookup() {
        let dir = TempDir::new().unwrap();
        let store = IocStore::open(dir.path()).unwrap();

        let hash = "abc123def456abc123def456abc123def456abc123def456abc123def456abcd";
        store.insert("file_hash", hash, r#"{"confidence":0.95,"source":"malwarebazaar"}"#).unwrap();

        assert!(store.contains("file_hash", hash));
        assert!(!store.contains("file_hash", "nonexistent"));
    }

    #[test]
    fn test_case_insensitive() {
        let dir = TempDir::new().unwrap();
        let store = IocStore::open(dir.path()).unwrap();
        store.insert("domain", "EVIL.COM", "{}").unwrap();
        assert!(store.contains("domain", "evil.com"));
        assert!(store.contains("domain", "EVIL.COM"));
    }

    #[test]
    fn test_remove() {
        let dir = TempDir::new().unwrap();
        let store = IocStore::open(dir.path()).unwrap();
        store.insert("ip_address", "1.2.3.4", "{}").unwrap();
        assert!(store.remove("ip_address", "1.2.3.4").unwrap());
        assert!(!store.contains("ip_address", "1.2.3.4"));
    }

    #[test]
    fn test_bulk_insert_performance() {
        let dir = TempDir::new().unwrap();
        let store = IocStore::open(dir.path()).unwrap();

        let hashes: Vec<String> = (0..10_000)
            .map(|i| format!("{:064x}", i))
            .collect();

        let iocs: Vec<(&str, &str, &str)> = hashes
            .iter()
            .map(|h| ("file_hash", h.as_str(), r#"{"confidence":0.9}"#))
            .collect();

        let start = std::time::Instant::now();
        let count = store.bulk_insert(iocs.into_iter()).unwrap();
        let elapsed = start.elapsed();

        assert_eq!(count, 10_000);
        // Bulk insert of 10K IOCs should be fast
        assert!(elapsed.as_millis() < 5_000, "Bulk insert too slow: {:?}", elapsed);
    }
}
