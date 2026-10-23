# Threat model

## What this project does and where untrusted input enters
SP1 is a zkVM. It executes RISC-V programs (guest programs, usually compiled from Rust) and proves that the execution was correct. A verifier checks the proof against a verifying key that is derived from the program ELF.

Untrusted input enters in these places:
- Proofs and public values given to a verifier. The prover is never trusted.
- Guest programs (ELF files) and their stdin, given to the executor and the prover. Operators of prover services run programs from users they do not trust.
- Responses from the prover network, received by the SDK client (`crates/sdk/src/network`).

## Components that matter most / least
Most important:
- Soundness of the proof system: the core machine constraints (`crates/core/machine`, `crates/core/compiler`), precompiles, the recursion circuits and machine (`crates/recursion`), and the polynomial commitment and sumcheck code in `slop/crates`.
- Verifiers: `crates/verifier` (Groth16, PLONK and compressed proofs, also used inside guest programs), `crates/prover/src/verify.rs`, and the gnark circuits in `crates/recursion/gnark-ffi/go`.
- Agreement between the executor (`crates/core/executor`, the JIT in `crates/core/jit`) and the constraints. If the executor and the constraints disagree, a valid program can produce a false proof or fail to prove.
- Isolation of the host from guest programs: the JIT, `crates/core/runner` (runs untrusted programs in a child process with a memory limit), and the `untrusted_programs` and `mprotect` features.

Less important but in scope: the SDK, the CLI, and `crates/build`.

Out of scope: `sp1-gpu/` (needs CUDA, which the scanner does not have), `examples/`, `patch-testing/`, `crates/eval`, `crates/perf`, and `audits/`. The patched crates in the `sp1-patches` GitHub organization are separate repositories.

## How to exercise it
- The image is built with `cargo sp1-test --no-run`, which is an alias in `/root/.cargo/config.toml` for the CI test command. Run tests with `cargo sp1-test -- <test name filter>`, or run a test binary in `target/release/deps` directly, to reuse that build. A different `-p` or `--features` set causes a long rebuild.
- Guest test programs are in `crates/test-artifacts/programs` and are prebuilt. The image sets `SP1_SKIP_PROGRAM_BUILD=true`, so changes to a guest program have no effect until you build with `SP1_SKIP_PROGRAM_BUILD=false`. Guest programs compile offline with the `succinct` Rust toolchain.
- On the scan machine (2 CPUs, 8 GB), the executor tests take less than a second, and a small core proof such as `sp1_core_machine` `riscv::tests::test_fibonacci_prove_simple` takes about 30 seconds. The end-to-end tests in `sp1-prover` (`test_e2e_*`) are too slow. For a soundness bug, a small core proof with a modified trace, or a test in `crates/core/machine/src/utils/zerocheck_unit_test.rs`, is a good reproducer.
- The PLONK and Groth16 circuit artifacts are not in the image (they are 8.5 GB). The verifying keys that `crates/verifier` uses are in `crates/verifier/vk-artifacts`. The `sp1-verifier` tests are not prebuilt, because they make full proofs.

## How you rate severity
- Critical: a soundness bug. A proof that a verifier accepts for an execution that did not occur, for wrong public values, or for a different program than the verifying key commits to. This includes a mock proof that the real verifier accepts, and a guest program that escapes the executor or JIT and runs code on the host.
- High: a guest program that reads or writes host memory outside its sandbox without code execution. A panic or crash in a verifier that a proof can cause.
- Medium: a valid program that cannot be proven (a completeness bug). A guest program that makes the host use memory or time without limit.
- Low: a crash in the CLI or build tools on bad local input.

## Exclusions
- Do not report that proving is slow or needs a lot of memory.
- Do not report guest panics or cycle-limit errors as bugs. SP1 supports panic proofs when callers explicitly accept the nonzero exit code. Default verification must reject these proofs. Reaching the cycle limit must return an error.
