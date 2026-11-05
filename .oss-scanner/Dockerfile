FROM debian:trixie
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates build-essential clang curl git golang-go libssl-dev pkg-config protobuf-compiler \
      libprotobuf-dev python3 xz-utils \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.cargo/bin:${PATH}" \
    GOPROXY="https://proxy.golang.org,https://goproxy.cn,direct" \
    GOSUMDB="sum.golang.org" \
    RUST_BACKTRACE=1 \
    SP1_CIRCUIT_MODE=release \
    RUSTFLAGS="-Copt-level=3 -Cdebug-assertions -Coverflow-checks=y -Cdebuginfo=line-tables-only"
RUN curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs | sh -s -- -y --default-toolchain none

COPY . /src
WORKDIR /src

RUN rustup toolchain install && cargo run -p sp1-cli --no-default-features -- prove install-toolchain

# Same packages and features as the CI test job, so `cargo sp1-test` reuses this build.
RUN cat >> /root/.cargo/config.toml <<'EOF'
[alias]
sp1-test = """test --release --workspace --features native-gnark,experimental,profiling
  --exclude sp1-verifier --exclude sp1-gpu-air --exclude sp1-gpu-basefold --exclude sp1-gpu-challenger
  --exclude sp1-gpu-commit --exclude sp1-gpu-cudart --exclude sp1-gpu-jagged-assist --exclude sp1-gpu-jagged-sumcheck
  --exclude sp1-gpu-jagged-tracegen --exclude sp1-gpu-logup-gkr --exclude sp1-gpu-merkle-tree --exclude sp1-gpu-perf
  --exclude sp1-gpu-prover --exclude sp1-gpu-server --exclude sp1-gpu-shard-prover --exclude sp1-gpu-sys
  --exclude sp1-gpu-tracegen --exclude sp1-gpu-tracing --exclude sp1-gpu-utils --exclude sp1-gpu-zerocheck"""
EOF
RUN cargo sp1-test --no-run
RUN cd crates/recursion/gnark-ffi/go && go mod download

ENV CARGO_NET_OFFLINE=true \
    GOPROXY=off
