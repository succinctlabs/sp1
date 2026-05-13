use core::{borrow::Borrow, marker::PhantomData, mem::size_of, mem::MaybeUninit};

use slop_air::{Air, AirBuilder, BaseAir};
use slop_algebra::PrimeField32;
use slop_matrix::Matrix;
use sp1_core_executor::{ExecutionRecord, Program, SyscallCode};
use sp1_curves::{weierstrass::WeierstrassParameters, CurveType, EllipticCurve};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::MachineAir;

use crate::{air::SP1CoreAirBuilder, TrustMode};

/// Columns for a Weierstrass scalar-multiplication chip.
///
/// TODO: lay out the columns required to constrain `p ← scalar * p`.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct WeierstrassMulAssignCols<T> {
    /// Whether this row corresponds to a real syscall invocation.
    pub is_real: T,
}

pub const fn num_weierstrass_mul_cols() -> usize {
    size_of::<WeierstrassMulAssignCols<u8>>()
}

/// A chip that constrains scalar multiplication of a Weierstrass curve point by a `u32` scalar.
#[derive(Default)]
pub struct WeierstrassMulAssignChip<E, M: TrustMode> {
    _marker: PhantomData<(E, M)>,
}

impl<E: EllipticCurve + WeierstrassParameters, M: TrustMode> WeierstrassMulAssignChip<E, M> {
    pub const fn new() -> Self {
        Self { _marker: PhantomData }
    }
}

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters, M: TrustMode> MachineAir<F>
    for WeierstrassMulAssignChip<E, M>
{
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> &'static str {
        match (E::CURVE_TYPE, M::IS_TRUSTED) {
            (CurveType::Secp256k1, true) => "Secp256k1MulAssign",
            (CurveType::Secp256k1, false) => "Secp256k1MulAssignUser",
            _ => panic!("Unsupported curve for WeierstrassMulAssignChip"),
        }
    }

    fn num_rows(&self, _input: &Self::Record) -> Option<usize> {
        todo!()
    }

    fn generate_trace_into(
        &self,
        _input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
        _buffer: &mut [MaybeUninit<F>],
    ) {
        todo!()
    }

    fn included(&self, shard: &Self::Record) -> bool {
        // Skeleton: only include the chip variant that matches the program's trust mode, and
        // only when there are events. The real implementation should also honor shard.shape.
        let has_events = match E::CURVE_TYPE {
            CurveType::Secp256k1 => {
                !shard.get_precompile_events(SyscallCode::SECP256K1_MUL).is_empty()
            }
            _ => false,
        };
        has_events && (M::IS_TRUSTED != shard.program.enable_untrusted_programs)
    }
}

impl<F, E: EllipticCurve, M: TrustMode> BaseAir<F> for WeierstrassMulAssignChip<E, M> {
    fn width(&self) -> usize {
        num_weierstrass_mul_cols()
    }
}

impl<AB, E: EllipticCurve, M: TrustMode> Air<AB> for WeierstrassMulAssignChip<E, M>
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        // Placeholder constraint so that machine construction passes the
        // `max_constraint_degree > 0` assert in `Chip::new`. Replace with the real
        // p ← scalar * p constraints once the chip layout lands.
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &WeierstrassMulAssignCols<AB::Var> = (*local).borrow();
        builder.assert_bool(local.is_real);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sp1_core_executor::{
        ExecutionRecord, ExecutionReport, GasEstimatingVMEnum, MinimalExecutor, Program,
        SP1CoreOpts, SupervisorMode, SyscallCode, TracingVMEnum,
    };
    use sp1_hypercube::air::PROOF_NONCE_NUM_WORDS;
    use test_artifacts::SECP256K1_MUL_ELF;

    /// Runs the secp256k1 scalar-multiplication test program end-to-end through both the JIT
    /// executor and the tracing executor, without proving.
    ///
    /// This exercises the full executor wiring for `SECP256K1_MUL`:
    ///
    /// - Phase 1 (`MinimalExecutor`, the JIT path) hits the entrypoint syscall →
    ///   `ecall_handler` dispatch → `weierstrass_mul_assign_syscall` → `ec_mul` →
    ///   `sw_scalar_mul_k256` chain and produces compressed `MinimalTrace` chunks.
    /// - Phase 2 replays each chunk twice:
    ///   - `GasEstimatingVMEnum` accumulates an `ExecutionReport` (instruction / syscall counts,
    ///     gas, cycle-tracker labels).
    ///   - `TracingVMEnum` accumulates an `ExecutionRecord` populated with the precompile events
    ///     (`PrecompileEvent::Secp256k1Mul`) that the AIR would normally consume. We don't
    ///     actually run the AIR, so this chip's stubbed `eval` / `generate_trace_into` never
    ///     fire — which is the whole point while the chip is still incomplete.
    ///
    /// The four `mul_assign` invocations in the test program show up both in the
    /// `ExecutionReport`'s `syscall_counts` and in the tracing record's `Secp256k1Mul` event
    /// list.
    #[test]
    fn test_run_secp256k1_mul_executor_only() {
        let program = Program::from(&SECP256K1_MUL_ELF).unwrap();
        let program = Arc::new(program);

        // Phase 1: produce trace chunks via the JIT executor. `max_trace_size = Some(...)` is
        // what enables chunk recording — with `None` the chunks come back empty.
        let opts = SP1CoreOpts::default();
        let mut executor = MinimalExecutor::<SupervisorMode>::new(
            program.clone(),
            false,
            Some(opts.minimal_trace_chunk_threshold),
        );
        let mut chunks = Vec::new();
        while let Some(chunk) = executor.execute_chunk() {
            chunks.push(chunk);
        }
        assert!(executor.is_done(), "executor did not reach halt");

        let proof_nonce = [0u32; PROOF_NONCE_NUM_WORDS];

        // Phase 2a: gas-estimating replay → ExecutionReport.
        let mut report = ExecutionReport::default();
        for chunk in &chunks {
            let mut vm =
                GasEstimatingVMEnum::new(chunk, program.clone(), proof_nonce, opts.clone());
            report += vm.execute().expect("gas-estimating replay failed");
        }
        println!("\n=== ExecutionReport ===\n{report}=== end ===");

        // Phase 2b: tracing replay → ExecutionRecord with PrecompileEvents.
        let mut total_mul_events = 0usize;
        for chunk in &chunks {
            let mut record =
                ExecutionRecord::new(program.clone(), proof_nonce, opts.global_dependencies_opt);
            let mut vm = TracingVMEnum::new(
                chunk,
                program.clone(),
                opts.clone(),
                proof_nonce,
                &mut record,
            );
            vm.execute().expect("tracing replay failed");
            drop(vm);

            total_mul_events += record.get_precompile_events(SyscallCode::SECP256K1_MUL).len();
        }
        println!("tracing executor emitted {total_mul_events} Secp256k1Mul events");

        // The guest program issues `mul_assign` four times. Both the report's syscall counter
        // and the tracing record's event count should agree on that number.
        assert_eq!(report.syscall_counts[SyscallCode::SECP256K1_MUL], 4);
        assert_eq!(total_mul_events, 4);
    }
}
