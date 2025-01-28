use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::{IntoParallelRefIterator, ParallelIterator, ParallelSlice};
use sp1_core_executor::{
    events::{AluEvent, ByteLookupEvent, ByteRecord},
    ByteOpcode, ExecutionRecord, Opcode, Program, DEFAULT_PC_INC,
};
use sp1_derive::AlignedBorrow;
use sp1_stark::{
    air::{MachineAir, SP1AirBuilder},
    Word,
};

use crate::utils::pad_rows_fixed;

/// The number of main trace columns for `BitwiseChip`.
pub const NUM_BITWISE_COLS: usize = size_of::<BitwiseCols<u8>>();

/// A chip that implements bitwise operations for the opcodes XOR, OR, and AND.
#[derive(Default)]
pub struct BitwiseChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct BitwiseCols<T> {
    /// The program counter.
    pub pc: T,

    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// Whether the first operand is not register 0.
    pub op_a_not_0: T,

    /// If the opcode is XOR.
    pub is_xor: T,

    // If the opcode is OR.
    pub is_or: T,

    /// If the opcode is AND.
    pub is_and: T,
}

impl<F: PrimeField32> MachineAir<F> for BitwiseChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Bitwise".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut rows = input
            .bitwise_events
            .par_iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_BITWISE_COLS];
                let cols: &mut BitwiseCols<F> = row.as_mut_slice().borrow_mut();
                let mut blu = Vec::new();
                self.event_to_row(event, cols, &mut blu);
                row
            })
            .collect::<Vec<_>>();

        // Pad the trace to a power of two.
        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_BITWISE_COLS],
            input.fixed_log2_rows::<F, _>(self),
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_BITWISE_COLS)
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let chunk_size = std::cmp::max(input.bitwise_events.len() / num_cpus::get(), 1);

        let blu_batches = input
            .bitwise_events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = [F::zero(); NUM_BITWISE_COLS];
                    let cols: &mut BitwiseCols<F> = row.as_mut_slice().borrow_mut();
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
            !shard.bitwise_events.is_empty()
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl BitwiseChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField>(
        &self,
        event: &AluEvent,
        cols: &mut BitwiseCols<F>,
        blu: &mut impl ByteRecord,
    ) {
        cols.pc = F::from_canonical_u32(event.pc);

        let a = event.a.to_le_bytes();
        let b = event.b.to_le_bytes();
        let c = event.c.to_le_bytes();

        cols.a = Word::from(event.a);
        cols.b = Word::from(event.b);
        cols.c = Word::from(event.c);
        cols.op_a_not_0 = F::from_bool(!event.op_a_0);

        cols.is_xor = F::from_bool(event.opcode == Opcode::XOR);
        cols.is_or = F::from_bool(event.opcode == Opcode::OR);
        cols.is_and = F::from_bool(event.opcode == Opcode::AND);

        if !event.op_a_0 {
            for ((b_a, b_b), b_c) in a.into_iter().zip(b).zip(c) {
                let byte_event = ByteLookupEvent {
                    opcode: ByteOpcode::from(event.opcode),
                    a1: b_a as u16,
                    a2: 0,
                    b: b_b,
                    c: b_c,
                };
                blu.add_byte_lookup_event(byte_event);
            }
        }
    }
}

impl<F> BaseAir<F> for BitwiseChip {
    fn width(&self) -> usize {
        NUM_BITWISE_COLS
    }
}

impl<AB> Air<AB> for BitwiseChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &BitwiseCols<AB::Var> = (*local).borrow();

        // Get the opcode for the operation.
        let opcode = local.is_xor * ByteOpcode::XOR.as_field::<AB::F>()
            + local.is_or * ByteOpcode::OR.as_field::<AB::F>()
            + local.is_and * ByteOpcode::AND.as_field::<AB::F>();

        // Get a multiplicity of `1` only for a true row.
        let mult = local.is_xor + local.is_or + local.is_and;
        for ((a, b), c) in local.a.into_iter().zip(local.b).zip(local.c) {
            builder.send_byte(opcode.clone(), a, b, c, local.op_a_not_0);
        }

        // SAFETY: We check that a padding row has `op_a_not_0 == 0`, to prevent a padding row sending byte lookups.
        builder.when(local.op_a_not_0).assert_one(mult.clone());

        // Get the cpu opcode, which corresponds to the opcode being sent in the CPU table.
        let cpu_opcode = local.is_xor * Opcode::XOR.as_field::<AB::F>()
            + local.is_or * Opcode::OR.as_field::<AB::F>()
            + local.is_and * Opcode::AND.as_field::<AB::F>();

        // Receive the arguments.
        // SAFETY: This checks the following.
        // - `next_pc = pc + 4`
        // - `num_extra_cycles = 0`
        // - `op_a_val` is constrained by the byte lookups when `op_a_not_0 == 1`
        // - `op_a_not_0` is correct, due to the sent `op_a_0` being equal to `1 - op_a_not_0`
        // - `op_a_immutable = 0`
        // - `is_memory = 0`
        // - `is_syscall = 0`
        // - `is_halt = 0`
        // Note that `is_xor + is_or + is_and` is checked to be boolean below.
        builder.receive_instruction(
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.pc,
            local.pc + AB::Expr::from_canonical_u32(DEFAULT_PC_INC),
            AB::Expr::zero(),
            cpu_opcode,
            local.a,
            local.b,
            local.c,
            AB::Expr::one() - local.op_a_not_0,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.is_xor + local.is_or + local.is_and,
        );

        // SAFETY: All selectors `is_xor`, `is_or`, `is_and` are checked to be boolean.
        // Each "real" row has exactly one selector turned on, as `is_real`, the sum of the three selectors, is boolean.
        // Therefore, the `opcode` and `cpu_opcode` matches the corresponding opcode.
        let is_real = local.is_xor + local.is_or + local.is_and;
        builder.assert_bool(local.is_xor);
        builder.assert_bool(local.is_or);
        builder.assert_bool(local.is_and);
        builder.assert_bool(is_real);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::print_stdout)]

    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{thread_rng, Rng};
    use sp1_core_executor::{
        events::{AluEvent, MemoryRecordEnum},
        ExecutionRecord, Instruction, Opcode, Program,
    };
    use sp1_stark::{
        air::MachineAir, baby_bear_poseidon2::BabyBearPoseidon2, CpuProver, MachineProver,
        StarkGenericConfig, Val,
    };

    use crate::{
        io::SP1Stdin,
        riscv::RiscvAir,
        utils::{run_malicious_test, uni_stark_prove, uni_stark_verify},
    };

    use super::BitwiseChip;

    #[test]
    fn generate_trace() {
        let mut shard = ExecutionRecord::default();
        shard.bitwise_events = vec![AluEvent::new(0, Opcode::XOR, 25, 10, 19, false)];
        let chip = BitwiseChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let mut shard = ExecutionRecord::default();
        shard.bitwise_events = [
            AluEvent::new(0, Opcode::XOR, 25, 10, 19, false),
            AluEvent::new(0, Opcode::OR, 27, 10, 19, false),
            AluEvent::new(0, Opcode::AND, 2, 10, 19, false),
        ]
        .repeat(1000);
        let chip = BitwiseChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof = uni_stark_prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        uni_stark_verify(&config, &chip, &mut challenger, &proof).unwrap();
    }

    #[test]
    fn test_malicious_bitwise() {
        const NUM_TESTS: usize = 5;

        for opcode in [Opcode::XOR, Opcode::OR, Opcode::AND] {
            for _ in 0..NUM_TESTS {
                let op_a = thread_rng().gen_range(0..u32::MAX);
                let op_b = thread_rng().gen_range(0..u32::MAX);
                let op_c = thread_rng().gen_range(0..u32::MAX);

                let correct_op_a = if opcode == Opcode::XOR {
                    op_b ^ op_c
                } else if opcode == Opcode::OR {
                    op_b | op_c
                } else {
                    op_b & op_c
                };

                assert!(op_a != correct_op_a);

                let instructions = vec![
                    Instruction::new(opcode, 5, op_b, op_c, true, true),
                    Instruction::new(Opcode::ADD, 10, 0, 0, false, false),
                ];
                let program = Program::new(instructions, 0, 0);
                let stdin = SP1Stdin::new();

                type P = CpuProver<BabyBearPoseidon2, RiscvAir<BabyBear>>;

                let malicious_trace_pv_generator = move |prover: &P,
                                                         record: &mut ExecutionRecord|
                      -> Vec<(
                    String,
                    RowMajorMatrix<Val<BabyBearPoseidon2>>,
                )> {
                    let mut malicious_record = record.clone();
                    malicious_record.cpu_events[0].a = op_a;
                    if let Some(MemoryRecordEnum::Write(mut write_record)) =
                        malicious_record.cpu_events[0].a_record
                    {
                        write_record.value = op_a;
                    }
                    malicious_record.bitwise_events[0].a = op_a;
                    prover.generate_traces(&malicious_record)
                };

                let result =
                    run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
                assert!(result.is_err() && result.unwrap_err().is_local_cumulative_sum_failing());
            }
        }
    }
}
