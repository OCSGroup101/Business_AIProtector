// Event bus throughput benchmark — 10,000 events/sec requirement
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

fn bench_event_bus_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .build()
        .unwrap();

    let mut group = c.benchmark_group("event_bus");
    group.throughput(Throughput::Elements(1));

    group.bench_function("publish_10k_events", |b| {
        use openclaw_agent::core::event_bus::{EventBus, EventType, OsInfo, TelemetryEvent};

        b.iter(|| {
            rt.block_on(async {
                let bus = EventBus::new(10_000);
                let publisher = bus.publisher();
                let mut receiver = bus.subscribe();

                for _ in 0..10_000 {
                    let event = TelemetryEvent::new(
                        "agt", "ten", "bench",
                        EventType::ProcessCreate, "host",
                        OsInfo { platform: "test".into(), version: "0".into(), arch: "x64".into() },
                    );
                    publisher.publish(event);
                }
                black_box(())
            })
        })
    });

    group.finish();
}

criterion_group!(benches, bench_event_bus_throughput);
criterion_main!(benches);
