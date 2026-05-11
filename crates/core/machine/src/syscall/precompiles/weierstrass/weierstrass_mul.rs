use core::{marker::PhantomData, mem::size_of, mem::MaybeUninit};

use slop_air::{Air, BaseAir};
use slop_algebra::PrimeField32;
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
    fn eval(&self, _builder: &mut AB) {
        // TODO: constrain `p ← scalar * p` for a Weierstrass curve point and a BigUint scalar.
    }
}
