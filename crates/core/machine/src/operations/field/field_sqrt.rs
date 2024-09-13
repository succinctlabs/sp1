use std::fmt::Debug;

use num::BigUint;
use p3_air::AirBuilder;
use p3_field::PrimeField32;
use sp1_curves::params::{limbs_from_vec, FieldParameters, Limbs};
use sp1_derive::AlignedBorrow;

use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, FieldOperation},
    ByteOpcode,
};
use sp1_stark::air::SP1AirBuilder;

use super::{field_op::FieldOpCols, range::FieldLtCols};
use crate::air::WordAirBuilder;
use p3_field::AbstractField;

/// A set of columns to compute the square root in emulated arithmetic.
///
/// *Safety*: The `FieldSqrtCols` asserts that `multiplication.result` is a square root of the given
/// input lying within the range `[0, modulus)` with the least significant bit `lsb`.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldSqrtCols<T, P: FieldParameters> {
    /// The multiplication operation to verify that the sqrt and the input match.
    ///
    /// In order to save space, we actually store the sqrt of the input in `multiplication.result`
    /// since we'll receive the input again in the `eval` function.
    pub multiplication: FieldOpCols<T, P>,

    pub range: FieldLtCols<T, P>,

    // The least significant bit of the square root.
    pub lsb: T,
}

impl<F: PrimeField32, P: FieldParameters> FieldSqrtCols<F, P> {
    /// Populates the trace.
    ///
    /// `P` is the parameter of the field that each limb lives in.
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        shard: u32,
        a: &BigUint,
        sqrt_fn: impl Fn(&BigUint) -> BigUint,
    ) -> BigUint {
        let modulus = P::modulus();
        assert!(a < &modulus);
        let sqrt = sqrt_fn(a);

        // Use FieldOpCols to compute result * result.
        let sqrt_squared =
            self.multiplication.populate(record, shard, &sqrt, &sqrt, FieldOperation::Mul);

        // If the result is indeed the square root of a, then result * result = a.
        assert_eq!(sqrt_squared, a.clone());

        // This is a hack to save a column in FieldSqrtCols. We will receive the value a again in
        // the eval function, so we'll overwrite it with the sqrt.
        self.multiplication.result = P::to_limbs_field::<F, _>(&sqrt);

        // Populate the range columns.
        self.range.populate(record, shard, &sqrt, &modulus);

        let sqrt_bytes = P::to_limbs(&sqrt);
        self.lsb = F::from_canonical_u8(sqrt_bytes[0] & 1);

        let and_event = ByteLookupEvent {
            shard,
            opcode: ByteOpcode::AND,
            a1: self.lsb.as_canonical_u32() as u16,
            a2: 0,
            b: sqrt_bytes[0],
            c: 1,
        };
        record.add_byte_lookup_event(and_event);

        // Add the byte range check for `sqrt`.
        record.add_u8_range_checks(
            shard,
            self.multiplication
                .result
                .0
                .as_slice()
                .iter()
                .map(|x| x.as_canonical_u32() as u8)
                .collect::<Vec<_>>()
                .as_slice(),
        );

        sqrt
    }
}

impl<V: Copy, P: FieldParameters> FieldSqrtCols<V, P>
where
    Limbs<V, P::Limbs>: Copy,
{
    /// Calculates the square root of `a`.
    pub fn eval<AB: SP1AirBuilder<Var = V>>(
        &self,
        builder: &mut AB,
        a: &Limbs<AB::Var, P::Limbs>,
        is_odd: impl Into<AB::Expr>,
        is_real: impl Into<AB::Expr> + Clone,
    ) where
        V: Into<AB::Expr>,
    {
        // As a space-saving hack, we store the sqrt of the input in `self.multiplication.result`
        // even though it's technically not the result of the multiplication. Now, we should
        // retrieve that value and overwrite that member variable with a.
        let sqrt = self.multiplication.result;
        let mut multiplication = self.multiplication.clone();
        multiplication.result = *a;

        // Compute sqrt * sqrt. We pass in P since we want its BaseField to be the mod.
        multiplication.eval(builder, &sqrt, &sqrt, FieldOperation::Mul, is_real.clone());

        let modulus_limbs = P::to_limbs_field_vec(&P::modulus());
        self.range.eval(
            builder,
            &sqrt,
            &limbs_from_vec::<AB::Expr, P::Limbs, AB::F>(modulus_limbs),
            is_real.clone(),
        );

        // Range check that `sqrt` limbs are bytes.
        builder.slice_range_check_u8(sqrt.0.as_slice(), is_real.clone());

        // Assert that the square root is the positive one, i.e., with least significant bit 0.
        // This is done by computing LSB = least_significant_byte & 1.
        builder.assert_bool(self.lsb);
        builder.when(is_real.clone()).assert_eq(self.lsb, is_odd);
        builder.send_byte(
            ByteOpcode::AND.as_field::<AB::F>(),
            self.lsb,
            sqrt[0],
            AB::F::one(),
            is_real,
        );
    }
}

#[cfg(test)]
mod tests {
    use num::{BigUint, One, Zero};
    use p3_air::BaseAir;
    use p3_field::{Field, PrimeField32};
    use sp1_core_executor::{ExecutionRecord, Program};
    use sp1_curves::params::{FieldParameters, Limbs};
    use sp1_stark::air::{MachineAir, SP1AirBuilder};

    use crate::utils::{pad_to_power_of_two, uni_stark_prove as prove, uni_stark_verify as verify};
    use core::{
        borrow::{Borrow, BorrowMut},
        mem::size_of,
    };
    use num::bigint::RandBigInt;
    use p3_air::Air;
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_matrix::{dense::RowMajorMatrix, Matrix};
    use rand::thread_rng;
    use sp1_core_executor::events::ByteRecord;
    use sp1_curves::edwards::ed25519::{ed25519_sqrt, Ed25519BaseField};
    use sp1_derive::AlignedBorrow;
    use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, StarkGenericConfig};

    use super::FieldSqrtCols;

    #[derive(AlignedBorrow, Debug)]
    pub struct TestCols<T, P: FieldParameters> {
        pub a: Limbs<T, P::Limbs>,
        pub sqrt: FieldSqrtCols<T, P>,
    }

    pub const NUM_TEST_COLS: usize = size_of::<TestCols<u8, Ed25519BaseField>>();

    struct EdSqrtChip<P: FieldParameters> {
        pub _phantom: std::marker::PhantomData<P>,
    }

    impl<P: FieldParameters> EdSqrtChip<P> {
        pub const fn new() -> Self {
            Self { _phantom: std::marker::PhantomData }
        }
    }

    impl<F: PrimeField32, P: FieldParameters> MachineAir<F> for EdSqrtChip<P> {
        type Record = ExecutionRecord;

        type Program = Program;

        fn name(&self) -> String {
            "EdSqrtChip".to_string()
        }

        fn generate_trace(
            &self,
            _: &ExecutionRecord,
            output: &mut ExecutionRecord,
        ) -> RowMajorMatrix<F> {
            let mut rng = thread_rng();
            let num_rows = 1 << 8;
            let mut operands: Vec<BigUint> = (0..num_rows - 2)
                .map(|_| {
                    // Take the square of a random number to make sure that the square root exists.
                    let a = rng.gen_biguint(256);
                    let sq = a.clone() * a.clone();
                    // We want to mod by the ed25519 modulus.
                    sq % &Ed25519BaseField::modulus()
                })
                .collect();

            // hardcoded edge cases.
            operands.extend(vec![BigUint::zero(), BigUint::one()]);

            let rows = operands
                .iter()
                .map(|a| {
                    let mut blu_events = Vec::new();
                    let mut row = [F::zero(); NUM_TEST_COLS];
                    let cols: &mut TestCols<F, P> = row.as_mut_slice().borrow_mut();
                    cols.a = P::to_limbs_field::<F, _>(a);
                    cols.sqrt.populate(&mut blu_events, 1, a, ed25519_sqrt);
                    output.add_byte_lookup_events(blu_events);
                    row
                })
                .collect::<Vec<_>>();
            // Convert the trace to a row major matrix.
            let mut trace =
                RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_TEST_COLS);

            // Pad the trace to a power of two.
            pad_to_power_of_two::<NUM_TEST_COLS, F>(&mut trace.values);

            trace
        }

        fn included(&self, _: &Self::Record) -> bool {
            true
        }
    }

    impl<F: Field, P: FieldParameters> BaseAir<F> for EdSqrtChip<P> {
        fn width(&self) -> usize {
            NUM_TEST_COLS
        }
    }

    impl<AB, P: FieldParameters> Air<AB> for EdSqrtChip<P>
    where
        AB: SP1AirBuilder,
        Limbs<AB::Var, P::Limbs>: Copy,
    {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.row_slice(0);
            let local: &TestCols<AB::Var, P> = (*local).borrow();

            // eval verifies that local.sqrt.result is indeed the square root of local.a.
            local.sqrt.eval(builder, &local.a, AB::F::zero(), AB::F::one());
        }
    }

    #[test]
    fn generate_trace() {
        let chip: EdSqrtChip<Ed25519BaseField> = EdSqrtChip::new();
        let shard = ExecutionRecord::default();
        let _: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        // println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let chip: EdSqrtChip<Ed25519BaseField> = EdSqrtChip::new();
        let shard = ExecutionRecord::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
