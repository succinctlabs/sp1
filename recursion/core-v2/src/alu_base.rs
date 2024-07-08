use core::borrow::Borrow;
use p3_air::PairBuilder;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::Field;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::MachineAir;
use sp1_core::utils::pad_to_power_of_two;
use sp1_derive::AlignedBorrow;
use std::borrow::BorrowMut;

use crate::{builder::SP1RecursionAirBuilder, *};

#[derive(Default)]
pub struct BaseAluChip {}

pub const NUM_BASE_ALU_COLS: usize = core::mem::size_of::<BaseAluCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BaseAluCols<F: Copy> {
    pub vals: BaseAluIo<F>,
    pub sum: F,
    pub diff: F,
    pub product: F,
    pub quotient: F,
}

pub const NUM_BASE_ALU_PREPROCESSED_COLS: usize =
    core::mem::size_of::<BaseAluPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BaseAluPreprocessedCols<F: Copy> {
    pub addrs: BaseAluIo<Address<F>>,
    pub is_add: F,
    pub is_sub: F,
    pub is_mul: F,
    pub is_div: F,
    pub mult: F,
    pub is_real: F,
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
        "Base field Alu".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BASE_ALU_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let rows = program
            .instructions
            .iter()
            .filter_map(|instruction| {
                let Instruction::BaseAlu(BaseAluInstr {
                    opcode,
                    mult,
                    addrs,
                }) = instruction
                else {
                    return None;
                };
                let mult = mult.to_owned();

                let mut row = [F::zero(); NUM_BASE_ALU_PREPROCESSED_COLS];
                let cols: &mut BaseAluPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                *cols = BaseAluPreprocessedCols {
                    addrs: addrs.to_owned(),
                    is_add: F::from_bool(false),
                    is_sub: F::from_bool(false),
                    is_mul: F::from_bool(false),
                    is_div: F::from_bool(false),
                    mult,
                    is_real: F::from_bool(true),
                };
                let target_flag = match opcode {
                    Opcode::AddF => &mut cols.is_add,
                    Opcode::SubF => &mut cols.is_sub,
                    Opcode::MulF => &mut cols.is_mul,
                    Opcode::DivF => &mut cols.is_div,
                    _ => panic!("Invalid opcode: {:?}", opcode),
                };
                *target_flag = F::from_bool(true);

                Some(row)
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_BASE_ALU_PREPROCESSED_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_BASE_ALU_PREPROCESSED_COLS, F>(&mut trace.values);

        Some(trace)
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn generate_trace(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let base_alu_events = input.base_alu_events.clone();

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let rows = base_alu_events
            .into_iter()
            .map(|vals| {
                let mut row = [F::zero(); NUM_BASE_ALU_COLS];

                let BaseAluEvent {
                    in1: v1, in2: v2, ..
                } = vals;

                let cols: &mut BaseAluCols<_> = row.as_mut_slice().borrow_mut();
                *cols = BaseAluCols {
                    vals,
                    sum: v1 + v2,
                    diff: v1 - v2,
                    product: v1 * v2,
                    quotient: v1.try_div(v2).unwrap_or(F::one()),
                };

                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_BASE_ALU_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_BASE_ALU_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, _record: &Self::Record) -> bool {
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

        let BaseAluCols {
            vals: BaseAluIo { out, in1, in2 },
            sum,
            diff,
            product,
            quotient,
        } = local;

        // Check exactly one flag is enabled.
        builder.when(prep_local.is_real).assert_one(
            prep_local.is_add + prep_local.is_sub + prep_local.is_mul + prep_local.is_div,
        );

        let mut when_add = builder.when(prep_local.is_add);
        when_add.assert_eq(*out, *sum);
        when_add.assert_eq(*in1 + *in2, *sum);

        let mut when_sub = builder.when(prep_local.is_sub);
        when_sub.assert_eq(*out, *diff);
        when_sub.assert_eq(*in1, *in2 + *diff);

        let mut when_mul = builder.when(prep_local.is_mul);
        when_mul.assert_eq(*out, *product);
        when_mul.assert_eq(*in1 * *in2, *product);

        let mut when_div = builder.when(prep_local.is_div);
        when_div.assert_eq(*out, *quotient);
        when_div.assert_eq(*in1, *in2 * *quotient);

        // local.is_real is 0 or 1
        // builder.assert_zero(local.is_real * (AB::Expr::one() - local.is_real));

        builder.receive_single(prep_local.addrs.in1, *in1, prep_local.is_real);

        builder.receive_single(prep_local.addrs.in2, *in2, prep_local.is_real);

        builder.send_single(prep_local.addrs.out, *out, prep_local.mult);
    }
}

#[cfg(test)]
mod tests {
    use machine::RecursionAir;
    use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;

    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sp1_core::{
        air::MachineAir,
        stark::StarkGenericConfig,
        utils::{run_test_machine, BabyBearPoseidon2},
    };
    use sp1_recursion_core::stark::config::BabyBearPoseidon2Outer;

    use super::*;

    use crate::runtime::instruction as instr;

    #[test]
    fn generate_trace() {
        type F = BabyBear;

        let shard = ExecutionRecord {
            base_alu_events: vec![BaseAluIo {
                out: F::one(),
                in1: F::one(),
                in2: F::one(),
            }],
            ..Default::default()
        };
        let chip = BaseAluChip::default();
        let trace: RowMajorMatrix<F> = chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    pub fn four_ops() {
        type SC = BabyBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;
        type A = RecursionAir<F, 3>;

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
                    instr::base_alu(Opcode::AddF, 1, a[2], a[0], a[1]),
                    instr::mem_single(MemAccessKind::Read, 1, a[2], in1 + in2),
                    instr::base_alu(Opcode::SubF, 1, a[3], a[0], a[1]),
                    instr::mem_single(MemAccessKind::Read, 1, a[3], in1 - in2),
                    instr::base_alu(Opcode::MulF, 1, a[4], a[0], a[1]),
                    instr::mem_single(MemAccessKind::Read, 1, a[4], in1 * in2),
                    instr::base_alu(Opcode::DivF, 1, a[5], a[0], a[1]),
                    instr::mem_single(MemAccessKind::Read, 1, a[5], quot),
                ]
            })
            .collect::<Vec<Instruction<F>>>();

        let program = RecursionProgram { instructions };

        let config = SC::new();

        let mut runtime =
            Runtime::<F, EF, DiffusionMatrixBabyBear>::new(&program, BabyBearPoseidon2::new().perm);
        runtime.run();
        let machine = A::machine(config);
        let (pk, vk) = machine.setup(&program);
        let result = run_test_machine(runtime.record, machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }
    }
}
