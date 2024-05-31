# syntax=docker/dockerfile:1

# Go: Plonk static library

FROM golang:1.22 AS go

WORKDIR /build

COPY go/go.mod go/go.sum ./
RUN go mod download

COPY go/sp1         ./sp1/
COPY go/*.go        ./
COPY go/babybear.h  ./

RUN CGO_ENABLED=1 GOOS=linux go build -o libsp1gnark.a -buildmode=c-archive .


# Rust: Babybear & CLI app

FROM rust:1.78-bookworm AS rust

COPY --from=go /build/libsp1gnark.a /usr/lib/
COPY --from=go /build/libsp1gnark.h /usr/include/
COPY --from=go /build/babybear.h    /usr/include/

RUN apt-get update
RUN apt-get install -y clang

WORKDIR /build

COPY gnark-cli/build.rs   ./
COPY gnark-cli/src        ./src/
COPY gnark-cli/Cargo.toml ./

RUN cargo install --path . --root /usr


# Entrypoint: Minimal debian installation

FROM debian:bookworm

COPY --from=rust /usr/bin/gnark-cli /usr/bin/
ENTRYPOINT ["/usr/bin/gnark-cli"]
