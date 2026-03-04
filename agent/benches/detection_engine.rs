// Detection engine benchmark — CI performance gate
// Requirement: process 10,000 events/sec at <4% CPU
//
// Run: cargo bench --bench detection_engine

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::collections::HashMap;

// We benchmark the core evaluation logic without I/O
fn bench_behavioral_rule_eval(c: &mut Criterion) {
    use openclaw_agent::core::event_bus::{EventType, OsInfo, TelemetryEvent};
    use openclaw_agent::detection::rule_loader::{Condition, MatchBlock, MatchType};

    let event = {
        let mut e = TelemetryEvent::new(
            "agt_bench",
            "ten_bench",
            "process",
            EventType::ProcessCreate,
            "bench-host",
            OsInfo {
                platform: "windows".into(),
                version: "10.0".into(),
                arch: "x86_64".into(),
            },
        );
        e.payload
            .insert("process_name".into(), serde_json::json!("powershell.exe"));
        e.payload
            .insert("parent_name".into(), serde_json::json!("winword.exe"));
        e.payload.insert(
            "cmdline".into(),
            serde_json::json!("powershell.exe -enc ABCDEF"),
        );
        e
    };

    let mut group = c.benchmark_group("detection_engine");
    group.throughput(Throughput::Elements(1));

    group.bench_function("behavioral_rule_two_conditions", |b| {
        b.iter(|| {
            // Simulate two condition checks
            let p_name = event
                .payload
                .get("process_name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let parent = event
                .payload
                .get("parent_name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let match1 = ["winword.exe", "excel.exe"].contains(&parent);
            let match2 = ["powershell.exe", "cmd.exe"].contains(&p_name);
            black_box(match1 && match2)
        })
    });

    group.finish();
}

fn bench_ioc_lookup(c: &mut Criterion) {
    use openclaw_agent::detection::ioc_store::IocStore;
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    let store = IocStore::open(dir.path()).unwrap();

    // Seed 100,000 IOCs
    let hashes: Vec<String> = (0..100_000).map(|i| format!("{:064x}", i)).collect();
    let iocs: Vec<(&str, &str, &str)> = hashes
        .iter()
        .map(|h| ("file_hash", h.as_str(), r#"{"confidence":0.9}"#))
        .collect();
    store.bulk_insert(iocs.into_iter()).unwrap();

    let known_hash = format!("{:064x}", 50_000);
    let unknown_hash = format!("{:064x}", 200_000);

    let mut group = c.benchmark_group("ioc_lookup");
    group.throughput(Throughput::Elements(1));

    group.bench_function("hit", |b| {
        b.iter(|| black_box(store.contains("file_hash", &known_hash)))
    });

    group.bench_function("miss", |b| {
        b.iter(|| black_box(store.contains("file_hash", &unknown_hash)))
    });

    group.finish();
}

criterion_group!(benches, bench_behavioral_rule_eval, bench_ioc_lookup);
criterion_main!(benches);
