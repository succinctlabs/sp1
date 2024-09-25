# Groth16 Trusted Setup

## Prerequisites

Make sure you have already built the circuits to the `build/groth16` directory.

```
make build-circuits
```

The trusted setup process will overwrite the proving key, verifying key, and the relevant
contracts in the `build/groth16` directory.

## Powers of Tau

Download the powers of tau file for the given number of constraints. You will need to choose the 
number based on the number of constraints in the circuit (nearest power of 2 above the number of constraints).

```
export NB_CONSTRAINTS_LOG2=23
wget https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_${NB_CONSTRAINTS_LOG2}.ptau \
    -O powersOfTau28_hez_final.ptau
```

## Semaphore Install

```
git clone https://github.com/jtguibas/semaphore-gnark-11.git
git checkout ee57a61abfc3924c61ffc0a3d033bb92dfe7bbe8
go build
mv semaphore-mtb-setup semaphore-gnark-11
cp semaphore-gnark-11 ../sp1/crates/prover/
```

## Phase 1 Setup

```
mkdir -p trusted-setup
./semaphore-gnark-11 p1i powersOfTau28_hez_final.ptau trusted-setup/phase1
```

## Phase 2 Setup

```
./semaphore-gnark-11 p2n trusted-setup/phase1 build/groth16/groth16_circuit.bin trusted-setup/phase2 trusted-setup/evals
```

## Phase 2 Contributions

```
./semaphore-gnark-11 p2c trusted-setup/phase2 trusted-setup/phase2-1-jtguibas
./semaphore-gnark-11 p2c trusted-setup/phase2-1-jtguibas trusted-setup/phase2-2-pumatheuma
cp trusted-setup/phase2-2-pumatheuma trusted-setup/phase2-final
```

## Export Keys

```
./semaphore-gnark-11 key trusted-setup/phase1 trusted-setup/phase2-final trusted-setup/evals build/groth16/groth16_circuit.bin
cp pk trusted-setup/groth16_pk.bin
cp vk trusted-setup/groth16_vk.bin
```

## Export Verifier

```
./semaphore-gnark-11 sol vk
cp Groth16Verifier.sol trusted-setup/Groth16Verifier.sol
```

## Override Existing Build

```
cp trusted-setup/groth16_pk.bin build/groth16/groth16_pk.bin
cp trusted-setup/groth16_vk.bin build/groth16/groth16_vk.bin
cp trusted-setup/Groth16Verifier.sol build/groth16/Groth16Verifier.sol
```

## Post Trusted Setup

```
cargo run --bin post_trusted_setup --release -- --build-dir build/groth16
```

## Release

```
make release-circuits
```