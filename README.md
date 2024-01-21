# Succinct zkVM

## Profile

```
cd core && RUST_TRACER=debug cargo run --bin profile --release --features perf -- --program ../programs/sha2
```

## Benchmark

```
cd core && cargo bench --features perf
```