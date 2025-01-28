use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField, PrimeField32};
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
    /// The program counter.
    pub pc: T,

    /// Instance of `AddOperation` to handle addition logic in `AddSubChip`'s ALU operations.
    /// It's result will be `a` for the add operation and `b` for the sub operation.
    pub add_operation: AddOperation<T>,

    /// The first input operand.  This will be `b` for add operations and `a` for sub operations.
    pub operand_1: Word<T>,

    /// The second input operand.  This will be `c` for both operations.
    pub operand_2: Word<T>,

    /// Whether the first operand is not register 0.
    pub op_a_not_0: T,

    /// Boolean to indicate whether the row is for an add operation.
    pub is_add: T,

    /// Boolean to indicate whether the row is for a sub operation.
    pub is_sub: T,
}

impl<F: PrimeField32> MachineAir<F> for AddSubChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "AddSub".to_string()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = next_power_of_two(
            input.add_events.len() + input.sub_events.len(),
            input.fixed_log2_rows::<F, _>(self),
        );
        Some(nb_rows)
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
        let padded_nb_rows = <AddSubChip as MachineAir<F>>::num_rows(self, input).unwrap();
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

    fn local_only(&self) -> bool {
        true
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
        cols.op_a_not_0 = F::from_bool(!event.op_a_0);
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

        // SAFETY: All selectors `is_add` and `is_sub` are checked to be boolean.
        // Each "real" row has exactly one selector turned on, as `is_real = is_add + is_sub` is boolean.
        // Therefore, the `opcode` matches the corresponding opcode of the instruction.
        let is_real = local.is_add + local.is_sub;
        builder.assert_bool(local.is_add);
        builder.assert_bool(local.is_sub);
        builder.assert_bool(is_real.clone());

        let opcode = AB::Expr::from_f(Opcode::ADD.as_field()) * local.is_add
            + AB::Expr::from_f(Opcode::SUB.as_field()) * local.is_sub;

        // Evaluate the addition operation.
        // This is enforced only when `op_a_not_0 == 1`.
        // `op_a_val` doesn't need to be constrained when `op_a_not_0 == 0`.
        AddOperation::<AB::F>::eval(
            builder,
            local.operand_1,
            local.operand_2,
            local.add_operation,
            local.op_a_not_0.into(),
        );

        // SAFETY: We check that a padding row has `op_a_not_0 == 0`, to prevent a padding row sending byte lookups.
        builder.when(local.op_a_not_0).assert_one(is_real.clone());

        // Receive the arguments.  There are separate receives for ADD and SUB.
        // For add, `add_operation.value` is `a`, `operand_1` is `b`, and `operand_2` is `c`.
        // SAFETY: This checks the following. Note that in this case `opcode = Opcode::ADD`
        // - `next_pc = pc + 4`
        // - `num_extra_cycles = 0`
        // - `op_a_val` is constrained by the `AddOperation` when `op_a_not_0 == 1`
        // - `op_a_not_0` is correct, due to the sent `op_a_0` being equal to `1 - op_a_not_0`
        // - `op_a_immutable = 0`
        // - `is_memory = 0`
        // - `is_syscall = 0`
        // - `is_halt = 0`
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
            AB::Expr::one() - local.op_a_not_0,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.is_add,
        );

        // For sub, `operand_1` is `a`, `add_operation.value` is `b`, and `operand_2` is `c`.
        // SAFETY: This checks the following. Note that in this case `opcode = Opcode::SUB`
        // - `next_pc = pc + 4`
        // - `num_extra_cycles = 0`
        // - `op_a_val` is constrained by the `AddOperation` when `op_a_not_0 == 1`
        // - `op_a_not_0` is correct, due to the sent `op_a_0` being equal to `1 - op_a_not_0`
        // - `op_a_immutable = 0`
        // - `is_memory = 0`
        // - `is_syscall = 0`
        // - `is_halt = 0`
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
            AB::Expr::one() - local.op_a_not_0,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.is_sub,
        );
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
        ExecutionRecord, Instruction, Opcode, DEFAULT_PC_INC,
    };
    use sp1_stark::{
        air::MachineAir, baby_bear_poseidon2::BabyBearPoseidon2, chip_name, CpuProver,
        MachineProver, StarkGenericConfig, Val,
    };
    use std::sync::LazyLock;

    use super::*;
    use crate::{
        io::SP1Stdin,
        riscv::RiscvAir,
        utils::{run_malicious_test, uni_stark_prove as prove, uni_stark_verify as verify},
    };

    /// Lazily initialized record for use across multiple tests.
    /// Consists of random `ADD` and `SUB` instructions.
    static SHARD: LazyLock<ExecutionRecord> = LazyLock::new(|| {
        let add_events = (0..1)
            .flat_map(|i| {
                [{
                    let operand_1 = 1u32;
                    let operand_2 = 2u32;
                    let result = operand_1.wrapping_add(operand_2);
                    AluEvent::new(i % 2, Opcode::ADD, result, operand_1, operand_2, false)
                }]
            })
            .collect::<Vec<_>>();
        let _sub_events = (0..255)
            .flat_map(|i| {
                [{
                    let operand_1 = thread_rng().gen_range(0..u32::MAX);
                    let operand_2 = thread_rng().gen_range(0..u32::MAX);
                    let result = operand_1.wrapping_add(operand_2);
                    AluEvent::new(i % 2, Opcode::SUB, result, operand_1, operand_2, false)
                }]
            })
            .collect::<Vec<_>>();
        ExecutionRecord { add_events, ..Default::default() }
    });

    #[test]
    fn generate_trace() {
        let mut shard = ExecutionRecord::default();
        shard.add_events = vec![AluEvent::new(0, Opcode::ADD, 14, 8, 6, false)];
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
        for i in 0..1 {
            let operand_1 = thread_rng().gen_range(0..u32::MAX);
            let operand_2 = thread_rng().gen_range(0..u32::MAX);
            let result = operand_1.wrapping_add(operand_2);
            shard.add_events.push(AluEvent::new(
                i * DEFAULT_PC_INC,
                Opcode::ADD,
                result,
                operand_1,
                operand_2,
                false,
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
                false,
            ));
        }

        let chip = AddSubChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }

    #[cfg(feature = "sys")]
    #[test]
    fn test_generate_trace_ffi_eq_rust() {
        let shard = LazyLock::force(&SHARD);

        let chip = AddSubChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(shard, &mut ExecutionRecord::default());
        let trace_ffi = generate_trace_ffi(shard);

        assert_eq!(trace_ffi, trace);
    }

    #[cfg(feature = "sys")]
    fn generate_trace_ffi(input: &ExecutionRecord) -> RowMajorMatrix<BabyBear> {
        use rayon::slice::ParallelSlice;

        use crate::utils::pad_rows_fixed;

        type F = BabyBear;

        let chunk_size =
            std::cmp::max((input.add_events.len() + input.sub_events.len()) / num_cpus::get(), 1);

        let events = input.add_events.iter().chain(input.sub_events.iter()).collect::<Vec<_>>();
        let row_batches = events
            .par_chunks(chunk_size)
            .map(|events| {
                let rows = events
                    .iter()
                    .map(|event| {
                        let mut row = [F::zero(); NUM_ADD_SUB_COLS];
                        let cols: &mut AddSubCols<F> = row.as_mut_slice().borrow_mut();
                        unsafe {
                            crate::sys::add_sub_event_to_row_babybear(event, cols);
                        }
                        row
                    })
                    .collect::<Vec<_>>();
                rows
            })
            .collect::<Vec<_>>();

        let mut rows: Vec<[F; NUM_ADD_SUB_COLS]> = vec![];
        for row_batch in row_batches {
            rows.extend(row_batch);
        }

        pad_rows_fixed(&mut rows, || [F::zero(); NUM_ADD_SUB_COLS], None);

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_ADD_SUB_COLS)
    }

    #[test]
    fn test_malicious_add_sub() {
        const NUM_TESTS: usize = 5;

        for opcode in [Opcode::ADD, Opcode::SUB] {
            for _ in 0..NUM_TESTS {
                let op_a = thread_rng().gen_range(0..u32::MAX);
                let op_b = thread_rng().gen_range(0..u32::MAX);
                let op_c = thread_rng().gen_range(0..u32::MAX);

                let correct_op_a = if opcode == Opcode::ADD {
                    op_b.wrapping_add(op_c)
                } else {
                    op_b.wrapping_sub(op_c)
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
                    if opcode == Opcode::ADD {
                        malicious_record.add_events[0].a = op_a;
                    } else if opcode == Opcode::SUB {
                        malicious_record.sub_events[0].a = op_a;
                    } else {
                        unreachable!()
                    }

                    let mut traces = prover.generate_traces(&malicious_record);

                    let add_sub_chip_name = chip_name!(AddSubChip, BabyBear);
                    for (chip_name, trace) in traces.iter_mut() {
                        if *chip_name == add_sub_chip_name {
                            // Add the add instructions are added first to the trace, before the sub instructions.
                            let index = if opcode == Opcode::ADD { 0 } else { 1 };

                            let first_row = trace.row_mut(index);
                            let first_row: &mut AddSubCols<BabyBear> = first_row.borrow_mut();
                            if opcode == Opcode::ADD {
                                first_row.add_operation.value = op_a.into();
                            } else {
                                first_row.add_operation.value = op_b.into();
                            }
                        }
                    }

                    traces
                };

                let result =
                    run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
                println!("Result for {:?}: {:?}", opcode, result);
                let add_sub_chip_name = chip_name!(AddSubChip, BabyBear);
                assert!(
                    result.is_err()
                        && result.unwrap_err().is_constraints_failing(&add_sub_chip_name)
                );
            }
        }
    }
}
