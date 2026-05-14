use core::{borrow::Borrow, marker::PhantomData, mem::size_of, mem::MaybeUninit};

use slop_air::{Air, BaseAir};
use slop_algebra::PrimeField32;
use slop_matrix::Matrix;
use sp1_core_executor::{ExecutionRecord, Program, SyscallCode};
use sp1_curves::{weierstrass::WeierstrassParameters, CurveType, EllipticCurve};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::MachineAir;

use crate::{air::SP1CoreAirBuilder, TrustMode};

/// Columns for the internal Add chip used by the EC scalar-multiplication controller.
///
/// TODO: lay out the columns required to constrain the internal `add` step:
/// `ort = ird + irt`, plus `(clock, c, first_add_marker, inverse_fam)` and the EC
/// add formula's intermediate columns, wired to the internal memory and syscall buses.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct WeierstrassMulInternalAddCols<T> {
    /// Whether this row corresponds to a real internal add step.
    pub is_real: T,
}

pub const fn num_weierstrass_mul_internal_add_cols() -> usize {
    size_of::<WeierstrassMulInternalAddCols<u8>>()
}

/// A chip that constrains a single non-first `add` step inside the EC scalar-multiplication
/// chain. The first add is folded into the controller chip; this chip handles every subsequent
/// add (i.e., those with `first_add_marker != 0`).
#[derive(Default)]
pub struct WeierstrassMulInternalAddChip<E, M: TrustMode> {
    _marker: PhantomData<(E, M)>,
}

impl<E: EllipticCurve + WeierstrassParameters, M: TrustMode> WeierstrassMulInternalAddChip<E, M> {
    pub const fn new() -> Self {
        Self { _marker: PhantomData }
    }
}

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters, M: TrustMode> MachineAir<F>
    for WeierstrassMulInternalAddChip<E, M>
{
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> &'static str {
        match (E::CURVE_TYPE, M::IS_TRUSTED) {
            (CurveType::Secp256k1, true) => "Secp256k1MulInternalAdd",
            (CurveType::Secp256k1, false) => "Secp256k1MulInternalAddUser",
            _ => panic!("Unsupported curve for WeierstrassMulInternalAddChip"),
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
        // only when there are scalar-mul events. The real implementation should also honor
        // shard.shape.
        let has_events = match E::CURVE_TYPE {
            CurveType::Secp256k1 => {
                !shard.get_precompile_events(SyscallCode::SECP256K1_MUL).is_empty()
            }
            _ => false,
        };
        has_events && (M::IS_TRUSTED != shard.program.enable_untrusted_programs)
    }
}

impl<F, E: EllipticCurve, M: TrustMode> BaseAir<F> for WeierstrassMulInternalAddChip<E, M> {
    fn width(&self) -> usize {
        num_weierstrass_mul_internal_add_cols()
    }
}

impl<AB, E: EllipticCurve, M: TrustMode> Air<AB> for WeierstrassMulInternalAddChip<E, M>
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        // Placeholder constraint so that machine construction passes the
        // `max_constraint_degree > 0` assert in `Chip::new`. Replace with the real
        // internal-add constraints once the chip layout lands.
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &WeierstrassMulInternalAddCols<AB::Var> = (*local).borrow();
        builder.assert_bool(local.is_real);
    }
}
