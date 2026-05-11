# Guide to Adding Precompiles in SP1

Precompiles are specialized chips that allow you to extend the functionality of vanilla SP1 to execute custom logic more efficiently. A precompile is invoked via an `ecall` instruction; the executor dispatches on the syscall code in `t0` and runs a hand-rolled implementation, while a corresponding AIR chip constrains the work the executor did.

This guide walks through the files you need to touch in the **current** executor architecture. If you are looking at an older guide that talks about `default_syscall_map`, `Syscall` trait `impl`s, or `estimate_area` — those have been replaced.

## Architecture overview

SP1's executor has two backends that both consume the same `SyscallCode`:

- **`crates/core/executor/src/minimal/`** — the **JIT path**. Runs RISC-V via a generated x86_64 trampoline (`sp1_jit`) and is used for fast execution and gas estimation. Syscalls take `&mut impl SyscallContext`. No event emission — only the side effects of the syscall (memory writes, register writes, traps) happen here.
- **`crates/core/executor/src/vm/syscall/`** — the **tracing path**. A pure-Rust interpreter built around `CoreVM` and the `SyscallRuntime` trait. This is the executor that emits the `PrecompileEvent`s consumed by AIR trace generation.

You almost always need to implement a new precompile in **both** backends so that both `execute` and `prove` flows handle it. The JIT path is the source of truth for behavior; the tracing path mirrors it and additionally records the events that drive constraint generation.

On the AIR side, every precompile chip is a variant of the `RiscvAir<F>` enum in `crates/core/machine/src/riscv/mod.rs`. Most chips are generic over a trust mode (`SupervisorMode` for trusted programs / `UserMode` for untrusted programs running under `mprotect`); the convention is to add both a `Foo(FooChip<SupervisorMode>)` and a `FooUser(FooChip<UserMode>)` variant, registered side by side everywhere.

Pick an existing precompile that resembles yours and use it as a template:
- **`uint256_ops`** — recent, simple, no controller chip. Good template for a precompile that just reads/writes a few buffers.
- **`keccak256` / `sha256`** — split into a compute chip plus a `*ControlChip` that manages memory access timing.
- **`weierstrass`**, **`fptower`**, **`edwards`** — parametric over a curve/field; useful if you are adding a new curve at an existing operation.

---

## 1. Add a `SyscallCode` variant

Edit `crates/core/executor/src/syscall_code.rs`.

The `SyscallCode` enum stores a packed `u32`: byte 0 is the syscall id, byte 1 is `should_send` (1 if the handler has its own table — true for any precompile), bytes 2–3 are unused. Pick a fresh value that doesn't collide with anything in the enum.

```rust
pub enum SyscallCode {
    // ...
    /// Executes the `CUSTOM_OP` precompile.
    CUSTOM_OP = 0x00_01_01_XX,
}
```

Then update each of the helper functions on `SyscallCode`:

- **`from_u32`** — add the inverse mapping. (This is hit on every `ecall`, so keep the literal byte pattern in sync with the enum value above.)
- **`as_air_id`** — map your syscall to the `RiscvAirId` of its **supervisor-mode** chip (see step 2).
- **`as_air_id_user`** — map to the user-mode chip's `RiscvAirId`. Return `None` for both if your syscall has no corresponding precompile AIR (e.g. `HALT`, `WRITE`, `COMMIT`).
- **`touched_addresses`** — upper bound on the number of memory words a single invocation can touch. This is used for shape estimation.
- **`touched_pages`** — upper bound on the number of distinct memory pages a single invocation touches. Used by the page-protection (`mprotect`) machinery. Counts both reads and writes; one slice that may straddle a page boundary contributes 2.
- If your syscall maps to a shared chip (e.g. an Fp op), also update `count_map`, `fp_op_map`, or the equivalent so its events get routed correctly.

Also add a matching `pub const` in `crates/zkvm/entrypoint/src/syscalls/mod.rs` so user code can refer to it. The constant must agree with the enum value.

```rust
pub const CUSTOM_OP: u32 = 0x00_01_01_XX;
```

---

## 2. Add a `RiscvAirId` variant

Edit `crates/core/executor/src/air.rs`.

Each chip in the machine has a unique numeric id. Add a variant (or two — supervisor + user) for your chip. Existing ids are stable; **append at the end** rather than renumbering, since the discriminants are serialized in proof metadata.

```rust
pub enum RiscvAirId {
    // ...
    CustomOp = N,
    CustomOpUser = N + 1,
}
```

`as_air_id` / `as_air_id_user` in `SyscallCode` should now reference these.

---

## 3. Define the event type

Create `crates/core/executor/src/events/precompiles/custom_op.rs` with the event struct that records everything the AIR trace generator needs:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default, DeepSizeOf)]
pub struct CustomOpEvent {
    pub clk: u64,
    pub x_ptr: u64,
    pub x: [u64; N],
    pub y_ptr: u64,
    pub y: [u64; N],
    pub x_memory_records: Vec<MemoryReadRecord>,
    pub y_memory_records: Vec<MemoryWriteRecord>,
    pub local_mem_access: Vec<MemoryLocalEvent>,
    // For mprotect-enabled programs:
    pub page_prot_records: CustomOpPageProtRecords,
    pub local_page_prot_access: Vec<PageProtLocalEvent>,
}
```

Then in `crates/core/executor/src/events/precompiles/mod.rs`:

1. Add `mod custom_op;` and `pub use custom_op::*;`.
2. Add a variant to the `PrecompileEvent` enum: `CustomOp(CustomOpEvent)`.
3. Add a match arm in `get_local_mem_events` that pushes `e.local_mem_access.iter()` (and similarly in `get_local_page_prot_events` if your syscall touches pages).

---

## 4. Implement the JIT-path executor

Create `crates/core/executor/src/minimal/precompiles/custom_op.rs`:

```rust
use sp1_jit::{Interrupt, RiscRegister::{X10, X11, X12}, SyscallContext};

pub unsafe fn custom_op(
    ctx: &mut impl SyscallContext,
    arg1: u64,   // value of a0 (X10) — convention is to pass the first pointer here
    arg2: u64,   // value of a1 (X11)
) -> Result<Option<u64>, Interrupt> {
    let x_ptr = arg1;
    let y_ptr = arg2;
    // Any extra args come from explicit register reads:
    let z_ptr = ctx.rr(X12);

    // Page-protection checks. Each `?` returns the appropriate Interrupt on trap.
    let clk = ctx.get_current_clk();
    ctx.read_slice_check(x_ptr, N)?;
    ctx.bump_memory_clk();
    ctx.write_slice_check(y_ptr, N)?;
    ctx.set_clk(clk);

    // Read inputs, compute, write outputs.
    let x = ctx.mr_slice_without_prot(x_ptr, N).to_vec();
    // ... compute ...
    ctx.bump_memory_clk();
    ctx.mw_slice_without_prot(y_ptr, &result);

    Ok(None)
}
```

Then wire it up:

1. Add `pub mod custom_op;` to `crates/core/executor/src/minimal/precompiles/mod.rs`.
2. In `crates/core/executor/src/minimal/ecall.rs`, import the function and add a match arm in `ecall_handler`:

```rust
SyscallCode::CUSTOM_OP => unsafe { custom_op(ctx, arg1, arg2) },
```

Conventions worth following:
- Pointer arguments past `arg1`/`arg2` come from `ctx.rr(Xn)` reads. Look at `uint256_ops` for the pattern with five operands.
- Always do all the page-protection checks first, snapshot `clk` before them with `get_current_clk`, then `set_clk(clk)` before doing the actual reads. The interleaved `bump_memory_clk()` calls match the AIR's expectation for distinct memory access timestamps.

---

## 5. Implement the tracing-path executor

Create `crates/core/executor/src/vm/syscall/custom_op.rs` (or `vm/syscall/precompiles/custom_op.rs` if the precompile naturally lives in the precompile group). The tracing path mirrors the JIT path but additionally builds and records a `CustomOpEvent`. The interface is `SyscallRuntime` rather than `SyscallContext`:

```rust
pub(crate) fn custom_op<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>>(
    rt: &mut RT,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, TrapError> {
    // Mirror the JIT path: page-prot checks, reads, writes.
    // Collect MemoryReadRecord / MemoryWriteRecord / PageProtRecord values
    // and assemble a CustomOpEvent.
    let (local_mem_access, local_page_prot_access) = rt.postprocess_precompile();
    let event = PrecompileEvent::CustomOp(CustomOpEvent { /* ... */ });
    let syscall_event = rt.syscall_event(/* ... */);
    rt.add_precompile_event(SyscallCode::CUSTOM_OP, syscall_event, event);
    Ok(None)
}
```

Register it:

1. Add `mod custom_op;` to `crates/core/executor/src/vm/syscall.rs`.
2. Add the dispatch arm in the same file's syscall handler.

The two implementations must agree exactly on which memory locations they read/write and in which order — any divergence will show up as a constraint failure during proving even though `execute` succeeds.

---

## 6. Define the chip and its AIR

Create `crates/core/machine/src/syscall/precompiles/custom_op/` with `mod.rs` and `air.rs`.

### `air.rs` — the chip struct and constraints

```rust
use crate::{TrustMode, UserMode, SupervisorMode};

#[derive(Default)]
pub struct CustomOpChip<M: TrustMode>(PhantomData<M>);

impl<M: TrustMode> CustomOpChip<M> {
    pub const fn new() -> Self { Self(PhantomData) }
}

#[derive(AlignedBorrow)]
#[repr(C)]
pub struct CustomOpCols<T, M: TrustMode> {
    pub is_real: T,
    pub clk_high: T,
    pub clk_low: T,
    pub x_ptr: T,
    pub y_ptr: T,
    pub x_memory: [MemoryAccessCols<T>; N],
    pub y_memory: [MemoryAccessCols<T>; N],
    // For user mode, add page-prot columns gated on `M::IS_TRUSTED`.
    pub output: FieldOpCols<T, U256Field>,
    _mode: PhantomData<M>,
}

impl<F, M: TrustMode> BaseAir<F> for CustomOpChip<M> {
    fn width(&self) -> usize { /* column count */ }
}

impl<AB, M> Air<AB> for CustomOpChip<M>
where
    AB: SP1AirBuilder,
    M: TrustMode,
{
    fn eval(&self, builder: &mut AB) {
        // Constrain memory accesses, the computation, and the syscall lookup.
    }
}
```

Look at `uint256_ops/air.rs` for the user-vs-supervisor column-count split (`num_uint256_ops_cols_supervisor` / `num_uint256_ops_cols_user`) — the user variant adds columns for page-prot tracking.

### `mod.rs` — `MachineAir`

```rust
impl<F: PrimeField32, M: TrustMode> MachineAir<F> for CustomOpChip<M> {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> &'static str {
        if M::IS_TRUSTED { "CustomOp" } else { "CustomOpUser" }
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        // Skip this chip if the program's trust mode doesn't match.
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return Some(0);
        }
        let nb = input.get_precompile_events(SyscallCode::CUSTOM_OP).len();
        Some(next_multiple_of_32(nb, input.fixed_log2_rows::<F, _>(self)))
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        // Pull events with `input.get_precompile_events(SyscallCode::CUSTOM_OP)`,
        // pattern-match on `PrecompileEvent::CustomOp(e)`, and write columns.
    }
}
```

> **Important**: the AIR's `eval` must constrain *exactly* what the executor does — same memory accesses, in the same order, against the same values. A mismatch causes proof failure even when execution succeeds and tests against the executor alone pass.

---

## 7. Wire the chip into `RiscvAir`

Edit `crates/core/machine/src/riscv/mod.rs`. There are five places to update — searching for any existing precompile name (`Uint256Ops` is a clean recent template) will find all of them.

1. **Import** the chip in the `riscv_chips` module (top of the file).
2. **Enum variants** on `RiscvAir<F>`:
   ```rust
   CustomOp(CustomOpChip<SupervisorMode>),
   CustomOpUser(CustomOpChip<UserMode>),
   ```
3. **`machine()`** — add to the `chips` array around the other precompiles:
   ```rust
   RiscvAir::CustomOp(CustomOpChip::<SupervisorMode>::new()),
   RiscvAir::CustomOpUser(CustomOpChip::<UserMode>::new()),
   ```
4. **`precompile_clusters`** — add `[CustomOp].as_slice(),` (and the matching `[CustomOpUser].as_slice(),` under the `#[cfg(feature = "mprotect")]` user-mode list). Each cluster is one possible per-shard chip set, so each precompile gets its own entry.
5. **`get_chips_and_costs()`** — push both chips and insert their costs into the `costs` map. This is what feeds shape selection and cost estimation; the obsolete `estimate_area` step from older guides has been folded into this function.

If you also need this chip to be available alongside the core CPU chips in the same shard (rare — only for chips that are tightly interleaved with CPU work, like `Sha256` and `Uint256Ops`), add it to `core_cluster_exts` and `core_cluster_special` as well.

Finally, `From<RiscvAirDiscriminants> for RiscvAirId` further down in the file needs an arm mapping `RiscvAirDiscriminants::CustomOp => RiscvAirId::CustomOp` (and the user variant). The compiler will tell you about this one.

---

## 8. Expose the syscall to user programs

Create `crates/zkvm/entrypoint/src/syscalls/custom_op.rs`:

```rust
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_custom_op(x: *mut [u64; N], y: *const [u64; N]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") crate::syscalls::CUSTOM_OP,
            in("a0") x,
            in("a1") y,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
```

Register the module in `crates/zkvm/entrypoint/src/syscalls/mod.rs`:

```rust
mod custom_op;
pub use custom_op::*;
```

The `pub const CUSTOM_OP: u32 = ...` you added in step 1 lives in this same file.

---

## 9. Tests

Create a guest program under `crates/test-artifacts/programs/custom-op-test/` that exercises the new syscall, then expose its ELF in `crates/test-artifacts/src/lib.rs`:

```rust
pub const CUSTOM_OP_ELF: &[u8] = include_elf!("custom-op-test");
```

Add the host-side test next to the AIR (e.g. `crates/core/machine/src/syscall/precompiles/custom_op/mod.rs`):

```rust
#[cfg(test)]
mod tests {
    use crate::utils::run_test_io;
    use sp1_core_executor::Program;
    use test_artifacts::CUSTOM_OP_ELF;

    #[test]
    fn test_custom_op() {
        utils::setup_logger();
        let program = Program::from(CUSTOM_OP_ELF);
        run_test_io::<CpuProver<_, _>>(program, SP1Stdin::new()).unwrap();
    }
}
```

For full coverage you want at least:
- The supervisor-mode path (default).
- The user-mode path (build the test program with untrusted-program / mprotect support enabled and verify the user chip kicks in).
- An end-to-end run through `test_e2e_node` — slow, but it's the only check that exercises recursion verifier compatibility.

---

## Checklist

For a new precompile, you should have touched roughly:

- `crates/core/executor/src/syscall_code.rs` — enum, `from_u32`, both `as_air_id*`, `touched_addresses`, `touched_pages`.
- `crates/core/executor/src/air.rs` — `RiscvAirId` variants (append at the end).
- `crates/core/executor/src/events/precompiles/{name}.rs` + `mod.rs` — event type and `PrecompileEvent` variant.
- `crates/core/executor/src/minimal/precompiles/{name}.rs` + `mod.rs` — JIT executor.
- `crates/core/executor/src/minimal/ecall.rs` — dispatch arm.
- `crates/core/executor/src/vm/syscall/{name}.rs` (or under `precompiles/`) + dispatch in `vm/syscall.rs` — tracing executor.
- `crates/core/machine/src/syscall/precompiles/{name}/{mod,air}.rs` — chip + `MachineAir` + `Air`.
- `crates/core/machine/src/riscv/mod.rs` — imports, `RiscvAir` variants, `machine()`, `precompile_clusters` (+ user variant), `get_chips_and_costs()`, `RiscvAirDiscriminants → RiscvAirId` mapping.
- `crates/zkvm/entrypoint/src/syscalls/{name}.rs` + `mod.rs` — `extern "C"` entrypoint and `pub const` syscall id.
- `crates/test-artifacts/programs/{name}-test/` + `crates/test-artifacts/src/lib.rs` — guest test program and ELF export.

Run `cargo fmt --all -- --check` and `cargo clippy -p sp1-core-executor -p sp1-core-machine --all-targets --all-features -- -D warnings -A incomplete-features` before considering the work done.
