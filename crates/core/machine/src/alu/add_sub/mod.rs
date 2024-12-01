use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator};
use sp1_core_executor::{
    events::{AluEvent, ByteLookupEvent, ByteRecord},
    ExecutionRecord, Opcode, Program, DEFAULT_PC_INC,
};
use sp1_derive::AlignedBorrow;
use sp1_stark::{
    air::{MachineAir, SP1AirBuilder},
    Word,
};

use crate::{
    operations::AddOperation,
    utils::{next_power_of_two, zeroed_f_vec},
};

/// The number of main trace columns for `AddSubChip`.
pub const NUM_ADD_SUB_COLS: usize = size_of::<AddSubCols<u8>>();

/// A chip that implements addition for the opcode ADD and SUB.
///
/// SUB is basically an ADD with a re-arrangement of the operands and result.
/// E.g. given the standard ALU op variable name and positioning of `a` = `b` OP `c`,
/// `a` = `b` + `c` should be verified for ADD, and `b` = `a` + `c` (e.g. `a` = `b` - `c`)
/// should be verified for SUB.
#[derive(Default)]
pub struct AddSubChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct AddSubCols<T> {
    /// The shard number, used for byte lookup table.
    pub shard: T,
    /// The program counter.
    pub pc: T,

    /// The nonce of the operation.
    pub nonce: T,

    /// Instance of `AddOperation` to handle addition logic in `AddSubChip`'s ALU operations.
    /// It's result will be `a` for the add operation and `b` for the sub operation.
    pub add_operation: AddOperation<T>,

    /// The first input operand.  This will be `b` for add operations and `c` for sub operations.
    pub operand_1: Word<T>,

    /// The second input operand.  This will be `c` for both operations.
    pub operand_2: Word<T>,

    /// Boolean to indicate whether the row is for an add operation.
    pub is_add: T,

    /// Boolean to indicate whether the row is for a sub operation.
    pub is_sub: T,
}

impl<F: PrimeField> MachineAir<F> for AddSubChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "AddSub".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the rows for the trace.
        let chunk_size =
            std::cmp::max((input.add_events.len() + input.sub_events.len()) / num_cpus::get(), 1);
        let merged_events =
            input.add_events.iter().chain(input.sub_events.iter()).collect::<Vec<_>>();
        let nb_rows = merged_events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_ADD_SUB_COLS);

        values.chunks_mut(chunk_size * NUM_ADD_SUB_COLS).enumerate().par_bridge().for_each(
            |(i, rows)| {
                rows.chunks_mut(NUM_ADD_SUB_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut AddSubCols<F> = row.borrow_mut();

                    if idx < merged_events.len() {
                        let mut byte_lookup_events = Vec::new();
                        let event = &merged_events[idx];
                        self.event_to_row(event, cols, &mut byte_lookup_events);
                    }
                    cols.nonce = F::from_canonical_usize(idx);
                });
            },
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_ADD_SUB_COLS)
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let chunk_size =
            std::cmp::max((input.add_events.len() + input.sub_events.len()) / num_cpus::get(), 1);

        let event_iter =
            input.add_events.chunks(chunk_size).chain(input.sub_events.chunks(chunk_size));

        let blu_batches = event_iter
            .par_bridge()
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = [F::zero(); NUM_ADD_SUB_COLS];
                    let cols: &mut AddSubCols<F> = row.as_mut_slice().borrow_mut();
                    self.event_to_row(event, cols, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.add_events.is_empty()
        }
    }
}

impl AddSubChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField>(
        &self,
        event: &AluEvent,
        cols: &mut AddSubCols<F>,
        blu: &mut impl ByteRecord,
    ) {
        cols.pc = F::from_canonical_u32(event.pc);

        let is_add = event.opcode == Opcode::ADD;
        cols.is_add = F::from_bool(is_add);
        cols.is_sub = F::from_bool(!is_add);

        let operand_1 = if is_add { event.b } else { event.a };
        let operand_2 = event.c;

        cols.add_operation.populate(blu, operand_1, operand_2);
        cols.operand_1 = Word::from(operand_1);
        cols.operand_2 = Word::from(operand_2);
    }
}

impl<F> BaseAir<F> for AddSubChip {
    fn width(&self) -> usize {
        NUM_ADD_SUB_COLS
    }
}

impl<AB> Air<AB> for AddSubChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &AddSubCols<AB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &AddSubCols<AB::Var> = (*next).borrow();

        let is_real = local.is_add + local.is_sub;
        builder.assert_bool(local.is_add);
        builder.assert_bool(local.is_sub);
        builder.assert_bool(is_real.clone());

        let opcode = AB::Expr::from_f(Opcode::ADD.as_field()) * local.is_add
            + AB::Expr::from_f(Opcode::SUB.as_field()) * local.is_sub;

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder.when_transition().assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        // Evaluate the addition operation.
        AddOperation::<AB::F>::eval(
            builder,
            local.operand_1,
            local.operand_2,
            local.add_operation,
            is_real.clone(),
        );

        // Receive the arguments.  There are separate receives for ADD and SUB.
        // For add, `add_operation.value` is `a`, `operand_1` is `b`, and `operand_2` is `c`.
        builder.receive_instruction(
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.pc,
            local.pc + AB::Expr::from_canonical_u32(DEFAULT_PC_INC),
            AB::Expr::zero(),
            opcode.clone(),
            local.add_operation.value,
            local.operand_1,
            local.operand_2,
            AB::Expr::zero(),
            local.nonce,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.is_add,
        );

        // For sub, `operand_1` is `a`, `add_operation.value` is `b`, and `operand_2` is `c`.
        builder.receive_instruction(
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.pc,
            local.pc + AB::Expr::from_canonical_u32(DEFAULT_PC_INC),
            AB::Expr::zero(),
            opcode,
            local.operand_1,
            local.add_operation.value,
            local.operand_2,
            AB::Expr::zero(),
            local.nonce,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.is_sub,
        );
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{thread_rng, Rng};
    use sp1_core_executor::{events::AluEvent, ExecutionRecord, Opcode, DEFAULT_PC_INC};
    use sp1_stark::{air::MachineAir, baby_bear_poseidon2::BabyBearPoseidon2, StarkGenericConfig};

    use super::AddSubChip;
    use crate::utils::{uni_stark_prove as prove, uni_stark_verify as verify};

    #[test]
    fn generate_trace() {
        let mut shard = ExecutionRecord::default();
        shard.add_events = vec![AluEvent::new(0, Opcode::ADD, 14, 8, 6)];
        let chip = AddSubChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let mut shard = ExecutionRecord::default();
        for i in 0..255 {
            let operand_1 = thread_rng().gen_range(0..u32::MAX);
            let operand_2 = thread_rng().gen_range(0..u32::MAX);
            let result = operand_1.wrapping_add(operand_2);
            shard.add_events.push(AluEvent::new(
                i * DEFAULT_PC_INC,
                Opcode::ADD,
                result,
                operand_1,
                operand_2,
            ));
        }
        for i in 0..255 {
            let operand_1 = thread_rng().gen_range(0..u32::MAX);
            let operand_2 = thread_rng().gen_range(0..u32::MAX);
            let result = operand_1.wrapping_sub(operand_2);
            shard.add_events.push(AluEvent::new(
                i * DEFAULT_PC_INC,
                Opcode::SUB,
                result,
                operand_1,
                operand_2,
            ));
        }

        let chip = AddSubChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
