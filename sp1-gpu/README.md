# SP1 GPU

An implementation of the GPU prover.

## Compilation

### CUDA Architecture Selection

You can speed up compilation times by specifying the target CUDA architecture using the `CUDA_ARCHS` environment variable. This avoids compiling for all supported architectures.

Examples:
- **Ada Lovelace** (RTX 4090, 4080, etc.): `CUDA_ARCHS="89"`
- **Hopper** (H100): `CUDA_ARCHS="90"`
- **Blackwell data center** (B100, B200): `CUDA_ARCHS="100"`
- **Blackwell GeForce** (RTX 5090): `CUDA_ARCHS="120"`

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

### NVIDIA cuPQC NTT

The `nvidia-ntt` feature uses NVIDIA cuPQC for NTT operations. A build without this feature uses sppark.

Install CUDA Toolkit 12.8 or newer. Then download and extract the [cuPQC SDK](https://developer.nvidia.com/cupqc).

Set these environment variables before you build:

```bash
export CUDA_PATH=/usr/local/cuda
export CUDACXX="$CUDA_PATH/bin/nvcc"
export PATH="$CUDA_PATH/bin:$PATH"
export LD_LIBRARY_PATH="$CUDA_PATH/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export CUPQC_SDK_DIR=/path/to/cupqc-sdk
export CUDA_ARCHS=120
```

Set `CUDA_ARCHS` for your GPU. The example targets an RTX 5090.

`CUPQC_SDK_DIR` must contain `lib/libcupqc-ntt.a`. You can omit this variable when the SDK is at `/usr/local/cupqc-sdk`.

Enable the feature on the final package that you build. Cargo passes it to each required SP1 GPU crate.

Build the GPU prover server:

```bash
cargo build --release -p sp1-gpu-server --features nvidia-ntt
```

Install the GPU prover server:

```bash
cargo install --locked --root "$HOME/.sp1" \
    --path sp1-gpu/crates/server --features nvidia-ntt
```

Run the end-to-end benchmark with cuPQC:

```bash
cargo run --release -p sp1-gpu-perf --features nvidia-ntt --bin node -- \
    --program v6/rsp --mode compressed
```

Rebuild an installed server after you change this feature. The feature applies during compilation.

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
