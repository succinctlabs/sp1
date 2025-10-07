use crate::{builder::SP1RecursionAirBuilder, *};
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir, PairBuilder};
use p3_field::{Field, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_machine::utils::next_power_of_two;
use sp1_derive::AlignedBorrow;
use sp1_stark::air::MachineAir;
use std::iter::zip;
#[cfg(feature = "sys")]
use {
    p3_baby_bear::BabyBear, p3_field::AbstractField, p3_maybe_rayon::prelude::*,
    std::borrow::BorrowMut,
};

pub const NUM_BASE_ALU_ENTRIES_PER_ROW: usize = 4;

#[derive(Default)]
pub struct BaseAluChip;

pub const NUM_BASE_ALU_COLS: usize = core::mem::size_of::<BaseAluCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BaseAluCols<F: Copy> {
    pub values: [BaseAluValueCols<F>; NUM_BASE_ALU_ENTRIES_PER_ROW],
}

pub const NUM_BASE_ALU_VALUE_COLS: usize = core::mem::size_of::<BaseAluValueCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BaseAluValueCols<F: Copy> {
    pub vals: BaseAluIo<F>,
}

pub const NUM_BASE_ALU_PREPROCESSED_COLS: usize =
    core::mem::size_of::<BaseAluPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BaseAluPreprocessedCols<F: Copy> {
    pub accesses: [BaseAluAccessCols<F>; NUM_BASE_ALU_ENTRIES_PER_ROW],
}

pub const NUM_BASE_ALU_ACCESS_COLS: usize = core::mem::size_of::<BaseAluAccessCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BaseAluAccessCols<F: Copy> {
    pub addrs: BaseAluIo<Address<F>>,
    pub is_add: F,
    pub is_sub: F,
    pub is_mul: F,
    pub is_div: F,
    pub mult: F,
}

impl<F: Field> BaseAir<F> for BaseAluChip {
    fn width(&self) -> usize {
        NUM_BASE_ALU_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for BaseAluChip {
    type Record = ExecutionRecord<F>;

    type Program = crate::RecursionProgram<F>;

    fn name(&self) -> String {
        "BaseAlu".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BASE_ALU_PREPROCESSED_COLS
    }

    fn preprocessed_num_rows(&self, program: &Self::Program, instrs_len: usize) -> Option<usize> {
        let nb_rows = instrs_len.div_ceil(NUM_BASE_ALU_ENTRIES_PER_ROW);
        let fixed_log2_rows = program.fixed_log2_rows(self);
        Some(match fixed_log2_rows {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(nb_rows, None),
        })
    }

    #[cfg(not(feature = "sys"))]
    fn generate_preprocessed_trace(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        unimplemented!("To generate traces, enable feature `sp1-recursion-core/sys`");
    }

    #[cfg(feature = "sys")]
    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        assert_eq!(
            std::any::TypeId::of::<F>(),
            std::any::TypeId::of::<BabyBear>(),
            "generate_preprocessed_trace only supports BabyBear field"
        );

        let instrs = unsafe {
            std::mem::transmute::<Vec<&BaseAluInstr<F>>, Vec<&BaseAluInstr<BabyBear>>>(
                program
                    .inner
                    .iter()
                    .filter_map(|instruction| match instruction {
                        Instruction::BaseAlu(x) => Some(x),
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
            )
        };
        let padded_nb_rows = self.preprocessed_num_rows(program, instrs.len()).unwrap();
        let mut values = vec![BabyBear::zero(); padded_nb_rows * NUM_BASE_ALU_PREPROCESSED_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = instrs.len() * NUM_BASE_ALU_ACCESS_COLS;
        values[..populate_len].par_chunks_mut(NUM_BASE_ALU_ACCESS_COLS).zip_eq(instrs).for_each(
            |(row, instr)| {
                let access: &mut BaseAluAccessCols<_> = row.borrow_mut();
                unsafe {
                    crate::sys::alu_base_instr_to_row_babybear(instr, access);
                }
            },
        );

        // Convert the trace to a row major matrix.
        Some(RowMajorMatrix::new(
            unsafe { std::mem::transmute::<Vec<BabyBear>, Vec<F>>(values) },
            NUM_BASE_ALU_PREPROCESSED_COLS,
        ))
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = input.base_alu_events.len().div_ceil(NUM_BASE_ALU_ENTRIES_PER_ROW);
        let fixed_log2_rows = input.fixed_log2_rows(self);
        Some(match fixed_log2_rows {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(nb_rows, None),
        })
    }

    #[cfg(not(feature = "sys"))]
    fn generate_trace(&self, _input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        unimplemented!("To generate traces, enable feature `sp1-recursion-core/sys`");
    }

    #[cfg(feature = "sys")]
    fn generate_trace(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        assert_eq!(
            std::any::TypeId::of::<F>(),
            std::any::TypeId::of::<BabyBear>(),
            "generate_trace only supports BabyBear field"
        );

        let events = unsafe {
            std::mem::transmute::<&Vec<BaseAluIo<F>>, &Vec<BaseAluIo<BabyBear>>>(
                &input.base_alu_events,
            )
        };
        let padded_nb_rows = self.num_rows(input).unwrap();
        let mut values = vec![BabyBear::zero(); padded_nb_rows * NUM_BASE_ALU_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = events.len() * NUM_BASE_ALU_VALUE_COLS;
        values[..populate_len].par_chunks_mut(NUM_BASE_ALU_VALUE_COLS).zip_eq(events).for_each(
            |(row, &vals)| {
                let cols: &mut BaseAluValueCols<_> = row.borrow_mut();
                unsafe {
                    crate::sys::alu_base_event_to_row_babybear(&vals, cols);
                }
            },
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            unsafe { std::mem::transmute::<Vec<BabyBear>, Vec<F>>(values) },
            NUM_BASE_ALU_COLS,
        )
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<AB> Air<AB> for BaseAluChip
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &BaseAluCols<AB::Var> = (*local).borrow();
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &BaseAluPreprocessedCols<AB::Var> = (*prep_local).borrow();

        for (
            BaseAluValueCols { vals: BaseAluIo { out, in1, in2 } },
            BaseAluAccessCols { addrs, is_add, is_sub, is_mul, is_div, mult },
        ) in zip(local.values, prep_local.accesses)
        {
            // Check exactly one flag is enabled.
            let is_real = is_add + is_sub + is_mul + is_div;
            builder.assert_bool(is_real.clone());

            builder.when(is_add).assert_eq(in1 + in2, out);
            builder.when(is_sub).assert_eq(in1, in2 + out);
            builder.when(is_mul).assert_eq(out, in1 * in2);
            builder.when(is_div).assert_eq(in2 * out, in1);

            builder.receive_single(addrs.in1, in1, is_real.clone());

            builder.receive_single(addrs.in2, in2, is_real);

            builder.send_single(addrs.out, out, mult);
        }
    }
}

#[cfg(all(test, feature = "sys"))]
mod tests {
    use crate::{chips::test_fixtures, runtime::instruction as instr};
    use machine::tests::test_recursion_linear_program;
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, StarkGenericConfig};

    use super::*;

    fn generate_trace_reference(
        input: &ExecutionRecord<BabyBear>,
        _: &mut ExecutionRecord<BabyBear>,
    ) -> RowMajorMatrix<BabyBear> {
        let events = &input.base_alu_events;
        let padded_nb_rows = BaseAluChip.num_rows(input).unwrap();
        let mut values = vec![BabyBear::zero(); padded_nb_rows * NUM_BASE_ALU_COLS];

        let populate_len = events.len() * NUM_BASE_ALU_VALUE_COLS;
        values[..populate_len].par_chunks_mut(NUM_BASE_ALU_VALUE_COLS).zip_eq(events).for_each(
            |(row, &vals)| {
                let cols: &mut BaseAluValueCols<_> = row.borrow_mut();
                *cols = BaseAluValueCols { vals };
            },
        );

        RowMajorMatrix::new(values, NUM_BASE_ALU_COLS)
    }

    #[test]
    fn generate_trace() {
        let shard = test_fixtures::shard();
        let mut execution_record = test_fixtures::default_execution_record();
        let trace = BaseAluChip.generate_trace(&shard, &mut execution_record);
        assert!(trace.height() >= test_fixtures::MIN_TEST_CASES);

        assert_eq!(trace, generate_trace_reference(&shard, &mut execution_record));
    }

    fn generate_preprocessed_trace_reference(
        program: &RecursionProgram<BabyBear>,
    ) -> RowMajorMatrix<BabyBear> {
        type F = BabyBear;

        let instrs = program
            .inner
            .iter()
            .filter_map(|instruction| match instruction {
                Instruction::BaseAlu(x) => Some(x),
                _ => None,
            })
            .collect::<Vec<_>>();
        let padded_nb_rows = BaseAluChip.preprocessed_num_rows(program, instrs.len()).unwrap();
        let mut values = vec![F::zero(); padded_nb_rows * NUM_BASE_ALU_PREPROCESSED_COLS];

        let populate_len = instrs.len() * NUM_BASE_ALU_ACCESS_COLS;
        values[..populate_len].par_chunks_mut(NUM_BASE_ALU_ACCESS_COLS).zip_eq(instrs).for_each(
            |(row, instr)| {
                let BaseAluInstr { opcode, mult, addrs } = instr;
                let access: &mut BaseAluAccessCols<_> = row.borrow_mut();
                *access = BaseAluAccessCols {
                    addrs: addrs.to_owned(),
                    is_add: F::from_bool(false),
                    is_sub: F::from_bool(false),
                    is_mul: F::from_bool(false),
                    is_div: F::from_bool(false),
                    mult: mult.to_owned(),
                };
                let target_flag = match opcode {
                    BaseAluOpcode::AddF => &mut access.is_add,
                    BaseAluOpcode::SubF => &mut access.is_sub,
                    BaseAluOpcode::MulF => &mut access.is_mul,
                    BaseAluOpcode::DivF => &mut access.is_div,
                };
                *target_flag = F::from_bool(true);
            },
        );

        RowMajorMatrix::new(values, NUM_BASE_ALU_PREPROCESSED_COLS)
    }

    #[test]
    #[ignore = "Failing due to merge conflicts. Will be fixed shortly."]
    fn generate_preprocessed_trace() {
        let program = test_fixtures::program();
        let trace = BaseAluChip.generate_preprocessed_trace(&program).unwrap();
        assert!(trace.height() >= test_fixtures::MIN_TEST_CASES);

        assert_eq!(trace, generate_preprocessed_trace_reference(&program));
    }

    #[test]
    pub fn four_ops() {
        type SC = BabyBearPoseidon2;
        type F = <SC as StarkGenericConfig>::Val;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut random_felt = move || -> F { rng.sample(rand::distributions::Standard) };
        let mut addr = 0;

        let instructions = (0..1000)
            .flat_map(|_| {
                let quot = random_felt();
                let in2 = random_felt();
                let in1 = in2 * quot;
                let alloc_size = 6;
                let a = (0..alloc_size).map(|x| x + addr).collect::<Vec<_>>();
                addr += alloc_size;
                [
                    instr::mem_single(MemAccessKind::Write, 4, a[0], in1),
                    instr::mem_single(MemAccessKind::Write, 4, a[1], in2),
                    instr::base_alu(BaseAluOpcode::AddF, 1, a[2], a[0], a[1]),
                    instr::mem_single(MemAccessKind::Read, 1, a[2], in1 + in2),
                    instr::base_alu(BaseAluOpcode::SubF, 1, a[3], a[0], a[1]),
                    instr::mem_single(MemAccessKind::Read, 1, a[3], in1 - in2),
                    instr::base_alu(BaseAluOpcode::MulF, 1, a[4], a[0], a[1]),
                    instr::mem_single(MemAccessKind::Read, 1, a[4], in1 * in2),
                    instr::base_alu(BaseAluOpcode::DivF, 1, a[5], a[0], a[1]),
                    instr::mem_single(MemAccessKind::Read, 1, a[5], quot),
                ]
            })
            .collect::<Vec<Instruction<F>>>();

        test_recursion_linear_program(instructions);
    }
}
