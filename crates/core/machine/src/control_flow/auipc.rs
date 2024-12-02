use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::{Air, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use rayon::iter::{ParallelBridge, ParallelIterator};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ExecutionRecord, Opcode, Program, DEFAULT_PC_INC, UNUSED_PC,
};
use sp1_derive::AlignedBorrow;
use sp1_stark::{
    air::{MachineAir, SP1AirBuilder},
    Word,
};
use std::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use crate::{
    operations::BabyBearWordRangeChecker,
    utils::{next_power_of_two, zeroed_f_vec},
};

#[derive(Default)]
pub struct AUIPCChip;

pub const NUM_AUIPC_COLS: usize = size_of::<AUIPCColumns<u8>>();

impl<F> BaseAir<F> for AUIPCChip {
    fn width(&self) -> usize {
        NUM_AUIPC_COLS
    }
}

/// The column layout for AUIPC/UNIMP/EBREAK instructions.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AUIPCColumns<T> {
    /// The program counter of the instruction.
    pub pc: Word<T>,

    /// The value of the first operand.
    pub op_a_value: Word<T>,
    /// The value of the second operand.
    pub op_b_value: Word<T>,
    /// The value of the third operand.
    pub op_c_value: Word<T>,

    /// BabyBear range checker for the program counter.
    pub pc_range_checker: BabyBearWordRangeChecker<T>,

    /// The AUIPC nonce for the ADD operation.
    pub auipc_nonce: T,

    /// Whether the instruction is an AUIPC instruction.
    pub is_auipc: T,

    /// Whether the instruction is an unimplemented instruction.
    pub is_unimp: T,

    /// Whether the instruction is an ebreak instruction.
    pub is_ebreak: T,
}

impl<AB> Air<AB> for AUIPCChip
where
    AB: SP1AirBuilder,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &AUIPCColumns<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_auipc);
        builder.assert_bool(local.is_unimp);
        builder.assert_bool(local.is_ebreak);
        let is_real = local.is_auipc + local.is_unimp + local.is_ebreak;
        builder.assert_bool(is_real.clone());

        let opcode = AB::Expr::from_canonical_u32(Opcode::AUIPC as u32) * local.is_auipc
            + AB::Expr::from_canonical_u32(Opcode::UNIMP as u32) * local.is_unimp
            + AB::Expr::from_canonical_u32(Opcode::EBREAK as u32) * local.is_ebreak;

        builder.receive_instruction(
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.pc.reduce::<AB>(),
            local.pc.reduce::<AB>() + AB::Expr::from_canonical_u32(DEFAULT_PC_INC),
            AB::Expr::zero(),
            opcode,
            local.op_a_value,
            local.op_b_value,
            local.op_c_value,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            is_real,
        );

        // Verify that the opcode is never UNIMP or EBREAK.
        builder.assert_zero(local.is_unimp);
        builder.assert_zero(local.is_ebreak);

        // Range check the pc.
        BabyBearWordRangeChecker::<AB::F>::range_check(
            builder,
            local.pc,
            local.pc_range_checker,
            local.is_auipc.into(),
        );

        // Verify that op_a == pc + op_b.
        builder.send_instruction(
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::from_canonical_u32(UNUSED_PC),
            AB::Expr::from_canonical_u32(UNUSED_PC + DEFAULT_PC_INC),
            AB::Expr::zero(),
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            local.op_a_value,
            local.pc,
            local.op_b_value,
            AB::Expr::zero(),
            local.auipc_nonce,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.is_auipc,
        );
    }
}

impl<F: PrimeField32> MachineAir<F> for AUIPCChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "AUIPC".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let chunk_size = std::cmp::max((input.auipc_events.len()) / num_cpus::get(), 1);
        let nb_rows = input.auipc_events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_AUIPC_COLS);

        let blu_events = values
            .chunks_mut(chunk_size * NUM_AUIPC_COLS)
            .enumerate()
            .par_bridge()
            .map(|(i, rows)| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                rows.chunks_mut(NUM_AUIPC_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut AUIPCColumns<F> = row.borrow_mut();

                    if idx < input.auipc_events.len() {
                        let event = &input.auipc_events[idx];
                        cols.is_auipc = F::from_bool(event.opcode == Opcode::AUIPC);
                        cols.is_unimp = F::from_bool(event.opcode == Opcode::UNIMP);
                        cols.is_ebreak = F::from_bool(event.opcode == Opcode::EBREAK);
                        cols.pc = event.pc.into();
                        if event.opcode == Opcode::AUIPC {
                            cols.pc_range_checker.populate(cols.pc, &mut blu);
                        }
                        cols.op_a_value = event.a.into();
                        cols.op_b_value = event.b.into();
                        cols.op_c_value = event.c.into();
                        cols.auipc_nonce = F::from_canonical_u32(
                            input
                                .nonce_lookup
                                .get(event.auipc_nonce.0 as usize)
                                .copied()
                                .unwrap_or_default(),
                        );
                    }
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_events.iter().collect_vec());

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_AUIPC_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.auipc_events.is_empty()
        }
    }
}
