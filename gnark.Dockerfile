# syntax=docker/dockerfile:1

FROM ubuntu:24.04@sha256:3f85b7caad41a95462cf5b787d8a04604c8262cdcdf9a472b8c52ef83375fe15 AS chef
RUN apt-get update
RUN apt-get install -y --no-install-recommends ca-certificates clang curl libssl-dev pkg-config git build-essential
RUN curl --proto '=https' --tlsv1.2 --retry 10 --retry-connrefused -fsSL 'https://sh.rustup.rs' | sh -s -- -y --default-toolchain none
RUN curl --proto '=https' --tlsv1.2 --retry 10 --retry-connrefused -fsSL https://go.dev/dl/go1.22.3.linux-amd64.tar.gz | tar xzf - -C /usr/local
ENV PATH="/root/.cargo/bin:/usr/local/go/bin:${PATH}"
WORKDIR /root/program
COPY ./rust-toolchain ./
RUN cargo install cargo-chef

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /root/program/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json
# Build application
COPY . .
RUN cargo build --release --bin sp1-recursion-gnark-ffi

# FROM ubuntu:24.04@sha256:3f85b7caad41a95462cf5b787d8a04604c8262cdcdf9a472b8c52ef83375fe15 AS builder
# RUN apt-get update
# RUN apt-get install -y --no-install-recommends ca-certificates clang curl libssl-dev pkg-config git build-essential
# RUN curl --proto '=https' --tlsv1.2 --retry 10 --retry-connrefused -fsSL 'https://sh.rustup.rs' | sh -s -- -y --default-toolchain none
# RUN curl --proto '=https' --tlsv1.2 --retry 10 --retry-connrefused -fsSL https://go.dev/dl/go1.22.3.linux-amd64.tar.gz | tar xzf - -C /usr/local
# ENV PATH="/root/.cargo/bin:/usr/local/go/bin:${PATH}"
# WORKDIR /root/program
# doesn't work for nightly, so we unfortunately waste a lot of time downloading stuff
# RUN rustup set profile minimal
COPY . .
RUN cargo build --release --bin sp1-recursion-gnark-ffi

# We do not need the Rust toolchain to run the binary!
FROM ubuntu:24.04@sha256:3f85b7caad41a95462cf5b787d8a04604c8262cdcdf9a472b8c52ef83375fe15 AS runtime
WORKDIR /root/program
COPY --from=builder /root/program/target/release/sp1-recursion-gnark-ffi /usr/local/bin
ENTRYPOINT ["/usr/local/bin/sp1-recursion-gnark-ffi"]
