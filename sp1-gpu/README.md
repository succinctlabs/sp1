# SP1 GPU

An implementation of the GPU prover.

## Compilation

### CUDA Architecture Selection

You can speed up compilation times by specifying the target CUDA architecture using the `CUDA_ARCHS` environment variable. This avoids compiling for all supported architectures.

Examples:
- **Ada Lovelace** (RTX 4090, 4080, etc.): `CUDA_ARCHS="89"`
- **Hopper** (H100): `CUDA_ARCHS="90"`
- **Blackwell** (B100, B200, RTX 5090): `CUDA_ARCHS="100"`

Usage:
```bash
# Compile for Ada Lovelace (e.g., RTX 4090)
CUDA_ARCHS="89" cargo build --release

# Compile for Hopper (e.g., H100)
CUDA_ARCHS="90" cargo build --release

# Compile for multiple architectures
CUDA_ARCHS="89,90" cargo build --release
```

If `CUDA_ARCHS` is not specified, the build will compile for all supported architectures, which takes significantly longer.

## Cargo profiles

To use a particular profile, pass `--profile <PROFILE-NAME>` to any Cargo command. The `dev`
profile is used by default, and the `release` profile can also be selected with `--release`.

- The `dev` profile (default) enables fast incremental compilation. It is useful for the usual
  modify-compile-run cycle of software develompent.
- The `lto` profile is like `release`, but has `lto="thin"`. This option provides some performance gains
  at the cost of a few extra seconds of compile time.
- The `release` profile, based on Cargo's default release profile, sets `lto=true`. This option adds
  a lot of compilation time. It's unclear how significant the performance difference
  from `lto="thin"` is, but it's certainly not very obvious.

When running `sp1-gpu-perf` and comparing results, ensure you are using the same profile and compilation
settings. The `lto` profile is likely sufficient for this particular use case.

Further reading: [The Cargo Book, "3.5 Profiles," section on LTO](https://doc.rust-lang.org/cargo/reference/profiles.html#lto).

## Building local GPU prover binary from source
To build the GPU prover binary from source, run the following command from the root of the repository:

```bash
cargo install --locked --root "$HOME/.sp1" --path sp1-gpu/crates/server/
```

## Profiling

### Jaeger

Setup Jaeger:
```
sudo docker run -it --rm -d -p4318:4318 -p4317:4317 -p16686:16686 jaegertracing/all-in-one:latest
```

Run a benchmark:
```
RUST_LOG=debug cargo run --release -p sp1-gpu-perf --bin e2e -- --program fibonacci-200m --trace telemetry
```

To see the traces, go to http://localhost:16686/search.