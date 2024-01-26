# Succinct zkVM

## Profile

```
cd core && RUST_TRACER=debug cargo run --bin profile --release --features perf -- --program ../programs/sha2
```

## Benchmark

```
cd core && cargo bench --features perf
```


## Compiling ELFs

Follow the instructions here: https://www.notion.so/Compiling-ELFs-for-Succinct-VM-c0e96bc99e664a02816518e7827509e0