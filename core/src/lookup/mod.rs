mod builder;
mod debug;
mod interaction;

pub use builder::InteractionBuilder;
pub use debug::*;
pub use interaction::*;

use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use p3_air::{Air, BaseAir};
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_maybe_rayon::prelude::ParallelIterator;
use p3_maybe_rayon::prelude::ParallelSlice;
use sp1_derive::AlignedBorrow;

use crate::air::MachineAir;
use crate::air::{SP1AirBuilder, Word};
use crate::alu::AluEvent;
use crate::operations::AddOperation;
use crate::runtime::MemoryRecordEnum;
use crate::runtime::{ExecutionRecord, Opcode, Program};
use crate::stark::MachineRecord;
use crate::utils::pad_to_power_of_two;

// memory instruction -> Add, for addr = b + c
// memory unsigned, need sub
// branch -> 1 slt OR sltu
// jump -> add
// auipc -> add

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum InteractionEvent {
    Memory(MemoryInteraction),
    Alu(AluInteraction),
    Syscall(SyscallInteraction),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemoryInteraction {
    pub shard: u32,
    pub clk: u32,
    pub addr: u32,
    pub value: u32,
    pub prev_shard: u32,
    pub prev_clk: u32,
    pub prev_value: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AluInteraction {
    pub is_send: bool,
    pub shard: u32,
    pub clk: u32,
    pub opcode: Opcode,
    pub a: u32,
    pub b: u32,
    pub c: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SyscallInteraction {
    pub is_send: bool,
    pub shard: u32,
    pub clk: u32,
    pub syscall_id: u32,
    pub arg1: u32,
    pub arg2: u32,
}

impl InteractionEvent {
    pub fn from_alu_event(is_send: bool, event: &AluEvent) -> Self {
        InteractionEvent::Alu(AluInteraction {
            is_send,
            shard: event.shard,
            clk: event.clk,
            opcode: event.opcode,
            a: event.a,
            b: event.b,
            c: event.c,
        })
    }

    pub fn from_syscall(
        is_send: bool,
        shard: u32,
        clk: u32,
        syscall_id: u32,
        arg1: u32,
        arg2: u32,
    ) -> Self {
        todo!();
    }

    pub fn from_memory_record(record: &MemoryRecordEnum) -> Self {
        let interaction = match record {
            MemoryRecordEnum::Read(record) => MemoryInteraction {
                shard: record.shard,
                clk: record.timestamp,
                addr: record.value,
                value: record.value,
                prev_shard: record.prev_shard,
                prev_clk: record.prev_timestamp,
                prev_value: record.value,
            },
            MemoryRecordEnum::Write(record) => MemoryInteraction {
                shard: record.shard,
                clk: record.timestamp,
                addr: record.value,
                value: record.value,
                prev_shard: record.prev_shard,
                prev_clk: record.prev_timestamp,
                prev_value: record.prev_value,
            },
        };
        InteractionEvent::Memory(interaction)
    }
}

/// The number of main trace columns for `AddSubChip`.
pub const NUM_INTERACTION_COLS: usize = size_of::<InteractionCols<u8>>();

#[derive(Default)]
pub struct InteractionChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct InteractionCols<T> {
    pub interaction_kind: T,

    pub multiplicity: T,

    pub values: [T; 13],

    // Used for verifying the memory access is in the correct order.
    pub is_memory_access_prev: T,

    pub is_real: T,
}

impl<F: PrimeField> MachineAir<F> for InteractionChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Interaction".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the rows for the trace.
        let chunk_size = std::cmp::max(
            (input.add_events.len() + input.sub_events.len()) / num_cpus::get(),
            1,
        );

        let rows_and_records = input
            .interaction_events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut record = ExecutionRecord::default();
                let rows = events
                    .iter()
                    .map(|event| {
                        let mut row = [F::zero(); NUM_INTERACTION_COLS];
                        let cols: &mut InteractionCols<F> = row.as_mut_slice().borrow_mut();
                        // let is_add = event.opcode == Opcode::ADD;
                        // cols.shard = F::from_canonical_u32(event.shard);
                        // cols.channel = F::from_canonical_u32(event.channel);
                        // cols.is_add = F::from_bool(is_add);
                        // cols.is_sub = F::from_bool(!is_add);

                        // let operand_1 = if is_add { event.b } else { event.a };
                        // let operand_2 = event.c;

                        // cols.add_operation.populate(
                        //     &mut record,
                        //     event.shard,
                        //     event.channel,
                        //     operand_1,
                        //     operand_2,
                        // );
                        // cols.operand_1 = Word::from(operand_1);
                        // cols.operand_2 = Word::from(operand_2);
                        row
                    })
                    .collect::<Vec<_>>();
                (rows, record)
            })
            .collect::<Vec<_>>();

        let mut rows: Vec<[F; NUM_INTERACTION_COLS]> = vec![];
        for mut row_and_record in rows_and_records {
            rows.extend(row_and_record.0);
            // output.append(&mut row_and_record.1);
        }

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_INTERACTION_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_INTERACTION_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.add_events.is_empty() || !shard.sub_events.is_empty()
    }
}

impl<F> BaseAir<F> for InteractionChip {
    fn width(&self) -> usize {
        NUM_INTERACTION_COLS
    }
}

impl<AB> Air<AB> for InteractionChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &InteractionCols<AB::Var> = (*local).borrow();

        // // Receive the arguments.  There are seperate receives for ADD and SUB.
        // // For add, `add_operation.value` is `a`, `operand_1` is `b`, and `operand_2` is `c`.
        // builder.receive_alu(
        //     Opcode::ADD.as_field::<AB::F>(),
        //     local.add_operation.value,
        //     local.operand_1,
        //     local.operand_2,
        //     local.shard,
        //     local.channel,
        //     local.is_add,
        // );

        // // For sub, `operand_1` is `a`, `add_operation.value` is `b`, and `operand_2` is `c`.
        // builder.receive_alu(
        //     Opcode::SUB.as_field::<AB::F>(),
        //     local.operand_1,
        //     local.add_operation.value,
        //     local.operand_2,
        //     local.shard,
        //     local.channel,
        //     local.is_sub,
        // );

        // let is_real = local.is_add + local.is_sub;
        // builder.assert_bool(local.is_add);
        // builder.assert_bool(local.is_sub);
        // builder.assert_bool(is_real);
    }
}

#[cfg(test)]
mod tests {
    // use p3_baby_bear::BabyBear;
    // use p3_matrix::dense::RowMajorMatrix;

    // use crate::{
    //     air::MachineAir,
    //     stark::StarkGenericConfig,
    //     utils::{uni_stark_prove as prove, uni_stark_verify as verify},
    // };
    // use rand::{thread_rng, Rng};

    // use crate::{
    //     alu::AluEvent,
    //     runtime::{ExecutionRecord, Opcode},
    //     utils::BabyBearPoseidon2,
    // };

    // #[test]
    // fn generate_trace() {
    //     let mut shard = ExecutionRecord::default();
    //     shard.add_events = vec![AluEvent::new(0, 0, 0, Opcode::ADD, 14, 8, 6)];
    //     let chip = AddSubChip::default();
    //     let trace: RowMajorMatrix<BabyBear> =
    //         chip.generate_trace(&shard, &mut ExecutionRecord::default());
    //     println!("{:?}", trace.values)
    // }

    // #[test]
    // fn prove_babybear() {
    //     let config = BabyBearPoseidon2::new();
    //     let mut challenger = config.challenger();

    //     let mut shard = ExecutionRecord::default();
    //     for i in 0..1000 {
    //         let operand_1 = thread_rng().gen_range(0..u32::MAX);
    //         let operand_2 = thread_rng().gen_range(0..u32::MAX);
    //         let result = operand_1.wrapping_add(operand_2);
    //         shard.add_events.push(AluEvent::new(
    //             0,
    //             i % 2,
    //             0,
    //             Opcode::ADD,
    //             result,
    //             operand_1,
    //             operand_2,
    //         ));
    //     }
    //     for i in 0..1000 {
    //         let operand_1 = thread_rng().gen_range(0..u32::MAX);
    //         let operand_2 = thread_rng().gen_range(0..u32::MAX);
    //         let result = operand_1.wrapping_sub(operand_2);
    //         shard.add_events.push(AluEvent::new(
    //             0,
    //             i % 2,
    //             0,
    //             Opcode::SUB,
    //             result,
    //             operand_1,
    //             operand_2,
    //         ));
    //     }

    //     let chip = AddSubChip::default();
    //     let trace: RowMajorMatrix<BabyBear> =
    //         chip.generate_trace(&shard, &mut ExecutionRecord::default());
    //     let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

    //     let mut challenger = config.challenger();
    //     verify(&config, &chip, &mut challenger, &proof).unwrap();
    // }
}
