SHELL := /bin/bash
.SHELLFLAGS = -e

all:
	@cargo build --all \
	  --exclude aggregation-program \
	  --exclude bls12381-program \
	  --exclude bn254-program \
	  --exclude chess-program \
	  --exclude cycle-tracking-program \
	  --exclude fibonacci-program \
	  --exclude io-program \
	  --exclude is-prime-program \
	  --exclude json-program \
	  --exclude patch-testing-program \
	  --exclude regex-program \
	  --exclude rsa-program \
	  --exclude rsp-program \
	  --exclude ssz-withdrawals-program \
	  --exclude tendermint-program

.PHONY: all examples
