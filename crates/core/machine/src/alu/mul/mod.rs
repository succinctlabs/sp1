use core::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};

use hashbrown::HashMap;
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField, PrimeField32};
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::{ParallelBridge, ParallelIterator, ParallelSlice};
use sp1_core_executor::{
    events::{AluEvent, ByteLookupEvent, ByteRecord},
    ExecutionRecord, Opcode, Program, CLK_INC, PC_INC,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{air::MachineAir, Word};
use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::{
    adapter::{
        register::r_type::{RTypeReader, RTypeReaderInput},
        state::{CPUState, CPUStateInput},
    },
    air::{SP1CoreAirBuilder, SP1Operation},
    operations::{MulOperation, MulOperationInput},
    utils::next_multiple_of_32,
};

/// The number of main trace columns for `MulChip`.
pub const NUM_MUL_COLS: usize = size_of::<MulCols<u8>>();

/// A chip that implements multiplication for the multiplication opcodes.
#[derive(Default)]
pub struct MulChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, StructReflection, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MulCols<T> {
    /// The current shard, timestamp, program counter of the CPU.
    pub state: CPUState<T>,

    /// The adapter to read program and register information.
    pub adapter: RTypeReader<T>,

    /// The output operand.
    pub a: Word<T>,

    /// Instance of `MulOperation` to handle multiplication logic in `MulChip`'s ALU operations.
    pub mul_operation: MulOperation<T>,

    /// Whether the operation is MUL.
    pub is_mul: T,

    /// Whether the operation is MULH.
    pub is_mulh: T,

    /// Whether the operation is MULHU.
    pub is_mulhu: T,

    /// Whether the operation is MULHSU.
    pub is_mulhsu: T,

    /// Whether the operation is MULW.
    pub is_mulw: T,
}

impl<F: PrimeField32> MachineAir<F> for MulChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "Mul"
    }

    fn column_names(&self) -> Vec<String> {
        MulCols::<F>::struct_reflection().unwrap()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows =
            next_multiple_of_32(input.mul_events.len(), input.fixed_log2_rows::<F, _>(self));
        Some(nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        // Generate the trace rows for each event.
        let nb_rows = input.mul_events.len();
        let padded_nb_rows = <MulChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let chunk_size = std::cmp::max((nb_rows + 1) / num_cpus::get(), 1);

        unsafe {
            let padding_start = nb_rows * NUM_MUL_COLS;
            let padding_size = (padded_nb_rows - nb_rows) * NUM_MUL_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, nb_rows * NUM_MUL_COLS) };

        values.chunks_mut(chunk_size * NUM_MUL_COLS).enumerate().par_bridge().for_each(
            |(i, rows)| {
                rows.chunks_mut(NUM_MUL_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut MulCols<F> = row.borrow_mut();

                    if idx < nb_rows {
                        let mut byte_lookup_events = Vec::new();
                        let event = &input.mul_events[idx];
                        cols.adapter.populate(&mut byte_lookup_events, event.1);
                        self.event_to_row(&event.0, cols, &mut byte_lookup_events);
                        cols.state.populate(&mut byte_lookup_events, event.0.clk, event.0.pc);
                    }
                });
            },
        );
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let chunk_size = std::cmp::max(input.mul_events.len() / num_cpus::get(), 1);

        let blu_batches = input
            .mul_events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = [F::zero(); NUM_MUL_COLS];
                    let cols: &mut MulCols<F> = row.as_mut_slice().borrow_mut();
                    cols.adapter.populate(&mut blu, event.1);
                    self.event_to_row(&event.0, cols, &mut blu);
                    cols.state.populate(&mut blu, event.0.clk, event.0.pc);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect::<Vec<_>>());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.mul_events.is_empty()
        }
    }
}

impl MulChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField>(
        &self,
        event: &AluEvent,
        cols: &mut MulCols<F>,
        blu: &mut impl ByteRecord,
    ) {
        cols.mul_operation.populate(
            blu,
            event.b,
            event.c,
            event.opcode == Opcode::MULH,
            event.opcode == Opcode::MULHSU,
            event.opcode == Opcode::MULW,
        );

        cols.is_mul = F::from_bool(event.opcode == Opcode::MUL);
        cols.is_mulh = F::from_bool(event.opcode == Opcode::MULH);
        cols.is_mulhu = F::from_bool(event.opcode == Opcode::MULHU);
        cols.is_mulhsu = F::from_bool(event.opcode == Opcode::MULHSU);
        cols.is_mulw = F::from_bool(event.opcode == Opcode::MULW);
        cols.a = Word::from(event.a);
    }
}

impl<F> BaseAir<F> for MulChip {
    fn width(&self) -> usize {
        NUM_MUL_COLS
    }
}

impl<AB> Air<AB> for MulChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MulCols<AB::Var> = (*local).borrow();

        let is_real =
            local.is_mul + local.is_mulh + local.is_mulhu + local.is_mulhsu + local.is_mulw;

        // Constrain the multiplication operation over `op_b`, `op_c` and the selectors.
        <MulOperation<AB::F> as SP1Operation<AB>>::eval(
            builder,
            MulOperationInput::new(
                local.a.map(|x| x.into()),
                local.adapter.b().map(|x| x.into()),
                local.adapter.c().map(|x| x.into()),
                local.mul_operation,
                is_real.clone(),
                local.is_mul.into(),
                local.is_mulh.into(),
                local.is_mulw.into(),
                local.is_mulhu.into(),
                local.is_mulhsu.into(),
            ),
        );

        // Calculate the opcode.
        let opcode = {
            builder.assert_bool(local.is_mul);
            builder.assert_bool(local.is_mulh);
            builder.assert_bool(local.is_mulhu);
            builder.assert_bool(local.is_mulw);
            builder.assert_bool(local.is_mulhsu);
            builder.assert_bool(is_real.clone());

            let mul: AB::Expr = AB::F::from_canonical_u32(Opcode::MUL as u32).into();
            let mulh: AB::Expr = AB::F::from_canonical_u32(Opcode::MULH as u32).into();
            let mulhu: AB::Expr = AB::F::from_canonical_u32(Opcode::MULHU as u32).into();
            let mulhsu: AB::Expr = AB::F::from_canonical_u32(Opcode::MULHSU as u32).into();
            let mulw: AB::Expr = AB::F::from_canonical_u32(Opcode::MULW as u32).into();
            local.is_mul * mul
                + local.is_mulh * mulh
                + local.is_mulhu * mulhu
                + local.is_mulhsu * mulhsu
                + local.is_mulw * mulw
        };

        // Compute instruction field constants for each opcode
        let funct3 = local.is_mul * AB::Expr::from_canonical_u8(Opcode::MUL.funct3().unwrap())
            + local.is_mulh * AB::Expr::from_canonical_u8(Opcode::MULH.funct3().unwrap())
            + local.is_mulhu * AB::Expr::from_canonical_u8(Opcode::MULHU.funct3().unwrap())
            + local.is_mulhsu * AB::Expr::from_canonical_u8(Opcode::MULHSU.funct3().unwrap())
            + local.is_mulw * AB::Expr::from_canonical_u8(Opcode::MULW.funct3().unwrap());
        let funct7 = local.is_mul * AB::Expr::from_canonical_u8(Opcode::MUL.funct7().unwrap())
            + local.is_mulh * AB::Expr::from_canonical_u8(Opcode::MULH.funct7().unwrap())
            + local.is_mulhu * AB::Expr::from_canonical_u8(Opcode::MULHU.funct7().unwrap())
            + local.is_mulhsu * AB::Expr::from_canonical_u8(Opcode::MULHSU.funct7().unwrap())
            + local.is_mulw * AB::Expr::from_canonical_u8(Opcode::MULW.funct7().unwrap());

        let mul_base = Opcode::MUL.base_opcode().0;
        let mulh_base = Opcode::MULH.base_opcode().0;
        let mulhu_base = Opcode::MULHU.base_opcode().0;
        let mulhsu_base = Opcode::MULHSU.base_opcode().0;
        let mulw_base = Opcode::MULW.base_opcode().0;

        let mul_base_expr = AB::Expr::from_canonical_u32(mul_base);
        let mulh_base_expr = AB::Expr::from_canonical_u32(mulh_base);
        let mulhu_base_expr = AB::Expr::from_canonical_u32(mulhu_base);
        let mulhsu_base_expr = AB::Expr::from_canonical_u32(mulhsu_base);
        let mulw_base_expr = AB::Expr::from_canonical_u32(mulw_base);

        let calculated_base_opcode = local.is_mul * mul_base_expr
            + local.is_mulh * mulh_base_expr
            + local.is_mulhu * mulhu_base_expr
            + local.is_mulhsu * mulhsu_base_expr
            + local.is_mulw * mulw_base_expr;

        let mul_instr_type = Opcode::MUL.instruction_type().0 as u32;
        let mulh_instr_type = Opcode::MULH.instruction_type().0 as u32;
        let mulhu_instr_type = Opcode::MULHU.instruction_type().0 as u32;
        let mulhsu_instr_type = Opcode::MULHSU.instruction_type().0 as u32;
        let mulw_instr_type = Opcode::MULW.instruction_type().0 as u32;

        let calculated_instr_type = local.is_mul * AB::Expr::from_canonical_u32(mul_instr_type)
            + local.is_mulh * AB::Expr::from_canonical_u32(mulh_instr_type)
            + local.is_mulhu * AB::Expr::from_canonical_u32(mulhu_instr_type)
            + local.is_mulhsu * AB::Expr::from_canonical_u32(mulhsu_instr_type)
            + local.is_mulw * AB::Expr::from_canonical_u32(mulw_instr_type);

        // Constrain the state of the CPU.
        // The program counter and timestamp increment by `4` and `8`.
        <CPUState<AB::F> as SP1Operation<AB>>::eval(
            builder,
            CPUStateInput::new(
                local.state,
                [
                    local.state.pc[0] + AB::F::from_canonical_u32(PC_INC),
                    local.state.pc[1].into(),
                    local.state.pc[2].into(),
                ],
                AB::Expr::from_canonical_u32(CLK_INC),
                is_real.clone(),
            ),
        );

        // This chip is for the case `rd != x0`.
        builder.assert_zero(local.adapter.op_a_0);
        // Constrain the program and register reads.
        let a_expr = local.a.map(|x| x.into());
        let alu_reader_input = RTypeReaderInput::<AB, AB::Expr>::new(
            local.state.clk_high::<AB>(),
            local.state.clk_low::<AB>(),
            local.state.pc,
            opcode,
            [calculated_instr_type, calculated_base_opcode, funct3, funct7],
            a_expr,
            local.adapter,
            is_real.clone(),
        );
        <RTypeReader<AB::F> as SP1Operation<AB>>::eval(builder, alu_reader_input);
    }
}

// #[cfg(test)]
// mod tests {
//     use crate::{
//         io::SP1Stdin,
//         riscv::RiscvAir,
//         utils::{run_malicious_test, run_test_machine, setup_test_machine},
//     };
//     use sp1_primitives::SP1Field;
//     use slop_matrix::dense::RowMajorMatrix;
//     use rand::{thread_rng, Rng};
//     use sp1_core_executor::{
//         events::{AluEvent, MemoryRecordEnum},
//         ExecutionRecord, Instruction, Opcode, Program,
//     };
//     use sp1_hypercube::{
//         air::{MachineAir, SP1_PROOF_NUM_PV_ELTS},
//         koala_bear_poseidon2::SP1InnerPcs,
//         Chip, CpuProver, MachineProver, StarkMachine, Val,
//     };

//     use super::MulChip;

//     #[test]
//     fn generate_trace_mul() {
//         let mut shard = ExecutionRecord::default();

//         // Fill mul_events with 10^7 MULHSU events.
//         let mut mul_events: Vec<AluEvent> = Vec::new();
//         for _ in 0..10i32.pow(7) {
//             mul_events.push(AluEvent::new(
//                 0,
//                 Opcode::MULHSU,
//                 0x80004000,
//                 0x80000000,
//                 0xffff8000,
//                 false,
//             ));
//         }
//         shard.mul_events = mul_events;
//         let chip = MulChip::default();
//         let _trace: RowMajorMatrix<SP1Field> =
//             chip.generate_trace(&shard, &mut ExecutionRecord::default());
//     }

//     #[test]
//     fn prove_koalabear() {
//         let mut shard = ExecutionRecord::default();
//         let mut mul_events: Vec<AluEvent> = Vec::new();

//         let mul_instructions: Vec<(Opcode, u32, u32, u32)> = vec![
//             (Opcode::MUL, 0x00001200, 0x00007e00, 0xb6db6db7),
//             (Opcode::MUL, 0x00001240, 0x00007fc0, 0xb6db6db7),
//             (Opcode::MUL, 0x00000000, 0x00000000, 0x00000000),
//             (Opcode::MUL, 0x00000001, 0x00000001, 0x00000001),
//             (Opcode::MUL, 0x00000015, 0x00000003, 0x00000007),
//             (Opcode::MUL, 0x00000000, 0x00000000, 0xffff8000),
//             (Opcode::MUL, 0x00000000, 0x80000000, 0x00000000),
//             (Opcode::MUL, 0x00000000, 0x80000000, 0xffff8000),
//             (Opcode::MUL, 0x0000ff7f, 0xaaaaaaab, 0x0002fe7d),
//             (Opcode::MUL, 0x0000ff7f, 0x0002fe7d, 0xaaaaaaab),
//             (Opcode::MUL, 0x00000000, 0xff000000, 0xff000000),
//             (Opcode::MUL, 0x00000001, 0xffffffff, 0xffffffff),
//             (Opcode::MUL, 0xffffffff, 0xffffffff, 0x00000001),
//             (Opcode::MUL, 0xffffffff, 0x00000001, 0xffffffff),
//             (Opcode::MULHU, 0x00000000, 0x00000000, 0x00000000),
//             (Opcode::MULHU, 0x00000000, 0x00000001, 0x00000001),
//             (Opcode::MULHU, 0x00000000, 0x00000003, 0x00000007),
//             (Opcode::MULHU, 0x00000000, 0x00000000, 0xffff8000),
//             (Opcode::MULHU, 0x00000000, 0x80000000, 0x00000000),
//             (Opcode::MULHU, 0x7fffc000, 0x80000000, 0xffff8000),
//             (Opcode::MULHU, 0x0001fefe, 0xaaaaaaab, 0x0002fe7d),
//             (Opcode::MULHU, 0x0001fefe, 0x0002fe7d, 0xaaaaaaab),
//             (Opcode::MULHU, 0xfe010000, 0xff000000, 0xff000000),
//             (Opcode::MULHU, 0xfffffffe, 0xffffffff, 0xffffffff),
//             (Opcode::MULHU, 0x00000000, 0xffffffff, 0x00000001),
//             (Opcode::MULHU, 0x00000000, 0x00000001, 0xffffffff),
//             (Opcode::MULHSU, 0x00000000, 0x00000000, 0x00000000),
//             (Opcode::MULHSU, 0x00000000, 0x00000001, 0x00000001),
//             (Opcode::MULHSU, 0x00000000, 0x00000003, 0x00000007),
//             (Opcode::MULHSU, 0x00000000, 0x00000000, 0xffff8000),
//             (Opcode::MULHSU, 0x00000000, 0x80000000, 0x00000000),
//             (Opcode::MULHSU, 0x80004000, 0x80000000, 0xffff8000),
//             (Opcode::MULHSU, 0xffff0081, 0xaaaaaaab, 0x0002fe7d),
//             (Opcode::MULHSU, 0x0001fefe, 0x0002fe7d, 0xaaaaaaab),
//             (Opcode::MULHSU, 0xff010000, 0xff000000, 0xff000000),
//             (Opcode::MULHSU, 0xffffffff, 0xffffffff, 0xffffffff),
//             (Opcode::MULHSU, 0xffffffff, 0xffffffff, 0x00000001),
//             (Opcode::MULHSU, 0x00000000, 0x00000001, 0xffffffff),
//             (Opcode::MULH, 0x00000000, 0x00000000, 0x00000000),
//             (Opcode::MULH, 0x00000000, 0x00000001, 0x00000001),
//             (Opcode::MULH, 0x00000000, 0x00000003, 0x00000007),
//             (Opcode::MULH, 0x00000000, 0x00000000, 0xffff8000),
//             (Opcode::MULH, 0x00000000, 0x80000000, 0x00000000),
//             (Opcode::MULH, 0x00000000, 0x80000000, 0x00000000),
//             (Opcode::MULH, 0xffff0081, 0xaaaaaaab, 0x0002fe7d),
//             (Opcode::MULH, 0xffff0081, 0x0002fe7d, 0xaaaaaaab),
//             (Opcode::MULH, 0x00010000, 0xff000000, 0xff000000),
//             (Opcode::MULH, 0x00000000, 0xffffffff, 0xffffffff),
//             (Opcode::MULH, 0xffffffff, 0xffffffff, 0x00000001),
//             (Opcode::MULH, 0xffffffff, 0x00000001, 0xffffffff),
//         ];
//         for t in mul_instructions.iter() {
//             mul_events.push(AluEvent::new(0, t.0, t.1, t.2, t.3, false));
//         }

//         // Append more events until we have 1000 tests.
//         for _ in 0..(1000 - mul_instructions.len()) {
//             mul_events.push(AluEvent::new(0, Opcode::MUL, 1, 1, 1, false));
//         }

//         shard.mul_events = mul_events;

//         // Run setup.
//         let air = MulChip::default();
//         let config = SP1InnerPcs::new();
//         let chip = Chip::new(air);
//         let (pk, vk) = setup_test_machine(StarkMachine::new(
//             config.clone(),
//             vec![chip],
//             SP1_PROOF_NUM_PV_ELTS,
//             true,
//         ));

//         // Run the test.
//         let air = MulChip::default();
//         let chip: Chip<SP1Field, MulChip> = Chip::new(air);
//         let machine = StarkMachine::new(config.clone(), vec![chip], SP1_PROOF_NUM_PV_ELTS, true);
//         run_test_machine::<SP1InnerPcs, MulChip>(vec![shard], machine, pk, vk).unwrap();
//     }

//     #[test]
//     fn test_malicious_mul() {
//         const NUM_TESTS: usize = 5;

//         for opcode in [Opcode::MUL, Opcode::MULH, Opcode::MULHU, Opcode::MULHSU] {
//             for _ in 0..NUM_TESTS {
//                 let (correct_op_a, op_b, op_c) = if opcode == Opcode::MUL {
//                     let op_b = thread_rng().gen_range(0..i32::MAX);
//                     let op_c = thread_rng().gen_range(0..i32::MAX);
//                     ((op_b.overflowing_mul(op_c).0) as u32, op_b as u32, op_c as u32)
//                 } else if opcode == Opcode::MULH {
//                     let op_b = thread_rng().gen_range(0..i32::MAX);
//                     let op_c = thread_rng().gen_range(0..i32::MAX);
//                     let result = (op_b as i64) * (op_c as i64);
//                     (((result >> 32) as i32) as u32, op_b as u32, op_c as u32)
//                 } else if opcode == Opcode::MULHU {
//                     let op_b = thread_rng().gen_range(0..u32::MAX);
//                     let op_c = thread_rng().gen_range(0..u32::MAX);
//                     let result: u64 = (op_b as u64) * (op_c as u64);
//                     ((result >> 32) as u32, op_b as u32, op_c as u32)
//                 } else if opcode == Opcode::MULHSU {
//                     let op_b = thread_rng().gen_range(0..i32::MAX);
//                     let op_c = thread_rng().gen_range(0..u32::MAX);
//                     let result: i64 = (op_b as i64) * (op_c as i64);
//                     ((result >> 32) as u32, op_b as u32, op_c as u32)
//                 } else {
//                     unreachable!()
//                 };

//                 let op_a = thread_rng().gen_range(0..u32::MAX);
//                 assert!(op_a != correct_op_a);

//                 let instructions = vec![
//                     Instruction::new(opcode, 5, op_b, op_c, true, true),
//                     Instruction::new(Opcode::ADD, 10, 0, 0, false, false),
//                 ];

//                 let program = Program::new(instructions, 0, 0);
//                 let stdin = SP1Stdin::new();

//                 type P = CpuProver<SP1InnerPcs, RiscvAir<SP1Field>>;

//                 let malicious_trace_pv_generator = move |prover: &P,
//                                                          record: &mut ExecutionRecord|
//                       -> Vec<(
//                     String,
//                     RowMajorMatrix<Val<SP1InnerPcs>>,
//                 )> {
//                     let mut malicious_record = record.clone();
//                     malicious_record.cpu_events[0].a = op_a as u32;
//                     if let Some(MemoryRecordEnum::Write(mut write_record)) =
//                         malicious_record.cpu_events[0].a_record
//                     {
//                         write_record.value = op_a as u32;
//                     }
//                     malicious_record.mul_events[0].a = op_a;
//                     prover.generate_traces(&malicious_record)
//                 };

//                 let result =
//                     run_malicious_test::<P>(program, stdin,
// Box::new(malicious_trace_pv_generator));                 assert!(result.is_err() &&
// result.unwrap_err().is_constraints_failing());             }
//         }
//     }
// }
