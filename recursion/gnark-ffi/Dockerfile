# syntax=docker/dockerfile:1

FROM golang:1.22 AS go

WORKDIR /build

COPY go/go.mod go/go.sum ./
RUN go mod download

COPY go/sp1         ./sp1/
COPY go/*.go        ./
COPY go/babybear.h  ./

RUN CGO_ENABLED=1 GOOS=linux go build -o libsp1gnark.a -buildmode=c-archive .

FROM rust:1.78

COPY --from=go /build/libsp1gnark.a /usr/lib/
