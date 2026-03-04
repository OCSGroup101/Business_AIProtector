// IOC lookup benchmark — P99 <1ms requirement
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

fn bench_ioc_p99(c: &mut Criterion) {
    // Placeholder — full benchmark in Phase 1 once IocStore is fully integrated
    let mut group = c.benchmark_group("ioc_p99");
    group.throughput(Throughput::Elements(1));
    group.bench_function("placeholder", |b| b.iter(|| black_box(0u64)));
    group.finish();
}

criterion_group!(benches, bench_ioc_p99);
criterion_main!(benches);
