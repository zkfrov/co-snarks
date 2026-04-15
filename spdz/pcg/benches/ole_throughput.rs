//! Throughput benchmark for OLE expansion over BN254.

use ark_bn254::Fr;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use spdz_pcg::pcg::{PcgParams, PcgSeed};

fn bench_expand(c: &mut Criterion) {
    for log_n in [14, 16, 18, 20].iter() {
        let params = PcgParams { log_n: *log_n };
        let n = params.n();
        let (p0, _p1) = PcgSeed::<Fr>::gen_pair_insecure(params.clone(), 42);

        c.bench_function(&format!("ole_expand_n_2^{}", log_n), |b| {
            b.iter(|| {
                let out = p0.expand();
                black_box(out);
            });
        });
        eprintln!("log_n={log_n}, N={n}: benchmark above");
    }
}

criterion_group!(benches, bench_expand);
criterion_main!(benches);
