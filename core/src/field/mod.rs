pub mod event;

use crate::air::FieldAirBuilder;
use crate::air::MachineAir;
use crate::air::SP1AirBuilder;
use crate::runtime::ExecutionRecord;
use crate::utils::pad_to_power_of_two;
use core::borrow::Borrow;
use core::borrow::BorrowMut;
use core::mem::size_of;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, Field, PrimeField};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use p3_maybe_rayon::prelude::*; //{ParallelIterator, ParallelSlice,};
use sp1_derive::AlignedBorrow;

use tracing::instrument;

/// The number of main trace columns for `FieldLTUChip`.
pub const NUM_FIELD_COLS: usize = size_of::<FieldLTUCols<u8>>();
const WIDTH: usize = 1;
/// A chip that implements less than within the field.
#[derive(Default)]
pub struct FieldLTUChip;

/// The column layout for the chip.
#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct FieldLTUCols<T> {
    /// The result of the `LT` operation on `a` and `b`
    pub lt: T,

    /// The first field operand.
    pub b: T,

    /// The second field operand.
    pub c: T,

    /// The difference between `b` and `c` in little-endian order.
    pub diff_bits: [T; LTU_NB_BITS + 1],

    // TODO:  Support multiplicities > 1.  Right now there can be duplicate rows.
    // pub multiplicities: T,
    pub is_real: T,
}

#[derive(Debug, Clone, AlignedBorrow, Copy)]
#[repr(C)]
pub struct PackedFieldLTUCols<T> {
    packed_chips: [FieldLTUCols<T>; WIDTH],
}

impl<F: PrimeField> MachineAir<F> for FieldLTUChip {
    fn name(&self) -> String {
        "FieldLTU".to_string()
    }

    #[instrument(name = "generate FieldLTU trace", skip_all)]
    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let rows = input
            .field_events
            .par_chunks_exact(WIDTH)
            .map(|events| {
                let mut row = [F::zero(); NUM_FIELD_COLS * WIDTH];
                let packed_cols: &mut PackedFieldLTUCols<F> = row.as_mut_slice().borrow_mut();
                for (i, event) in events.iter().enumerate() {
                    let mut cols = packed_cols.packed_chips[i];
                    let diff = event.b.wrapping_sub(event.c).wrapping_add(1 << LTU_NB_BITS);
                    cols.b = F::from_canonical_u32(event.b);
                    cols.c = F::from_canonical_u32(event.c);
                    for i in 0..cols.diff_bits.len() {
                        cols.diff_bits[i] = F::from_canonical_u32((diff >> i) & 1);
                    }
                    let max = 1 << LTU_NB_BITS;
                    if diff >= max {
                        panic!("diff overflow");
                    }
                    cols.lt = F::from_bool(event.ltu);
                    cols.is_real = F::one();
                }
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_FIELD_COLS * WIDTH,
        );

        // Pad the trace to a power of two.
        const width: usize = NUM_FIELD_COLS * WIDTH;
        pad_to_power_of_two::<width, F>(&mut trace.values);

        trace
    }
}

pub const LTU_NB_BITS: usize = 29;

impl<F: Field> BaseAir<F> for FieldLTUChip {
    fn width(&self) -> usize {
        NUM_FIELD_COLS * WIDTH
    }
}

impl<AB: SP1AirBuilder> Air<AB> for FieldLTUChip {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_packed: &PackedFieldLTUCols<AB::Var> = main.row_slice(0).borrow();
        let local_packed_chips: Vec<FieldLTUCols<AB::Var>> = local_packed.packed_chips.to_vec();
        local_packed_chips.iter().for_each(|local| {
            // Dummy constraint for normalizing to degree 3.
            builder.assert_eq(local.b * local.b * local.b, local.b * local.b * local.b);

            // Verify that lt is a boolean.
            builder.assert_bool(local.lt);

            // Verify that the diff bits are boolean.
            for i in 0..local.diff_bits.len() {
                builder.assert_bool(local.diff_bits[i]);
            }

            // Verify the decomposition of b - c.
            let mut diff = AB::Expr::zero();
            for i in 0..local.diff_bits.len() {
                diff += local.diff_bits[i] * AB::F::from_canonical_u32(1 << i);
            }
            builder.when(local.is_real).assert_eq(
                local.b - local.c + AB::F::from_canonical_u32(1 << LTU_NB_BITS),
                diff,
            );

            // Assert that the output is correct.
            builder
                .when(local.is_real)
                .assert_eq(local.lt, AB::Expr::one() - local.diff_bits[LTU_NB_BITS]);

            // Receive the field operation.
            builder.receive_field_op(local.lt, local.b, local.c, local.is_real);
        });
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;

    use crate::{
        air::MachineAir,
        utils::{uni_stark_prove as prove, uni_stark_verify as verify},
    };
    use rand::{thread_rng, Rng};

    use super::{FieldLTUChip,event::FieldEvent};
    use crate::{
        runtime::{ExecutionRecord, Opcode},
        utils::{BabyBearPoseidon2, StarkUtils},
    };

    #[test]
    fn generate_trace() {
        let mut shard = ExecutionRecord::default();
        shard.field_events = vec![FieldEvent::new(true,1,2)];
        let chip = FieldLTUChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let mut shard = ExecutionRecord::default();
        for i in 0..1000 {
            let operand_1 = 1; //thread_rng().gen_range(0..u32::MAX);
            let operand_2 = 2; //thread_rng().gen_range(0..u32::MAX);
            let result = true; //operand_1 < operand_2;
//	    println!("{:?} < {:?} = {:?}", operand_1,operand_2,result);


            shard
                .field_events
                .push(FieldEvent::new(result, operand_1, operand_2));
        }
        for i in 0..1000 {
            let operand_1 = 1 + i; //thread_rng().gen_range(0..u32::MAX);
            let operand_2 = 2 + i; //thread_rng().gen_range(0..u32::MAX);
            let result = true; //operand_1 < operand_2;
//	    println!("{:?} < {:?} = {:?}", operand_1,operand_2,result);


            shard
                .field_events
                .push(FieldEvent::new(result, operand_1, operand_2));
        }

        let chip = FieldLTUChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
