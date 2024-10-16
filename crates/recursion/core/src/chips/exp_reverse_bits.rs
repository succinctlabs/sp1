#![allow(clippy::needless_range_loop)]

use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir, PairBuilder};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_machine::utils::pad_rows_fixed;
use sp1_derive::AlignedBorrow;
use sp1_stark::air::{BaseAirBuilder, ExtensionAirBuilder, MachineAir, SP1AirBuilder};
use std::borrow::BorrowMut;
use tracing::instrument;

use crate::{
    builder::SP1RecursionAirBuilder,
    runtime::{ExecutionRecord, RecursionProgram},
    ExpReverseBitsInstr, Instruction,
};

use super::mem::MemoryAccessCols;

pub const NUM_EXP_REVERSE_BITS_LEN_COLS: usize = core::mem::size_of::<ExpReverseBitsLenCols<u8>>();
pub const NUM_EXP_REVERSE_BITS_LEN_PREPROCESSED_COLS: usize =
    core::mem::size_of::<ExpReverseBitsLenPreprocessedCols<u8>>();

#[derive(Clone, Debug, Copy, Default)]
pub struct ExpReverseBitsLenChip<const DEGREE: usize>;

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct ExpReverseBitsLenPreprocessedCols<T: Copy> {
    pub x_mem: MemoryAccessCols<T>,
    pub exponent_mem: MemoryAccessCols<T>,
    pub result_mem: MemoryAccessCols<T>,
    pub iteration_num: T,
    pub is_first: T,
    pub is_last: T,
    pub is_real: T,
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExpReverseBitsLenCols<T: Copy> {
    /// The base of the exponentiation.
    pub x: T,

    /// The current bit of the exponent. This is read from memory.
    pub current_bit: T,

    /// The previous accumulator squared.
    pub prev_accum_squared: T,

    /// Is set to the value local.prev_accum_squared * local.multiplier.
    pub prev_accum_squared_times_multiplier: T,

    /// The accumulator of the current iteration.
    pub accum: T,

    /// The accumulator squared.
    pub accum_squared: T,

    /// A column which equals x if `current_bit` is on, and 1 otherwise.
    pub multiplier: T,
}

impl<F, const DEGREE: usize> BaseAir<F> for ExpReverseBitsLenChip<DEGREE> {
    fn width(&self) -> usize {
        NUM_EXP_REVERSE_BITS_LEN_COLS
    }
}

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for ExpReverseBitsLenChip<DEGREE> {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "ExpReverseBitsLen".to_string()
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn preprocessed_width(&self) -> usize {
        NUM_EXP_REVERSE_BITS_LEN_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_EXP_REVERSE_BITS_LEN_PREPROCESSED_COLS]> = Vec::new();
        program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::ExpReverseBitsLen(instr) = instruction {
                    Some(instr)
                } else {
                    None
                }
            })
            .for_each(|instruction| {
                let ExpReverseBitsInstr { addrs, mult } = instruction;
                let mut row_add =
                    vec![[F::zero(); NUM_EXP_REVERSE_BITS_LEN_PREPROCESSED_COLS]; addrs.exp.len()];
                row_add.iter_mut().enumerate().for_each(|(i, row)| {
                    let row: &mut ExpReverseBitsLenPreprocessedCols<F> =
                        row.as_mut_slice().borrow_mut();
                    row.iteration_num = F::from_canonical_u32(i as u32);
                    row.is_first = F::from_bool(i == 0);
                    row.is_last = F::from_bool(i == addrs.exp.len() - 1);
                    row.is_real = F::one();
                    row.x_mem = MemoryAccessCols { addr: addrs.base, mult: -F::from_bool(i == 0) };
                    row.exponent_mem = MemoryAccessCols { addr: addrs.exp[i], mult: F::neg_one() };
                    row.result_mem = MemoryAccessCols {
                        addr: addrs.result,
                        mult: *mult * F::from_bool(i == addrs.exp.len() - 1),
                    };
                });
                rows.extend(row_add);
            });

        // Pad the trace to a power of two.
        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_EXP_REVERSE_BITS_LEN_PREPROCESSED_COLS],
            program.fixed_log2_rows(self),
        );

        let trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect(),
            NUM_EXP_REVERSE_BITS_LEN_PREPROCESSED_COLS,
        );
        Some(trace)
    }

    #[instrument(name = "generate exp reverse bits len trace", level = "debug", skip_all, fields(rows = input.exp_reverse_bits_len_events.len()))]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut overall_rows = Vec::new();
        input.exp_reverse_bits_len_events.iter().for_each(|event| {
            let mut rows = vec![vec![F::zero(); NUM_EXP_REVERSE_BITS_LEN_COLS]; event.exp.len()];

            let mut accum = F::one();

            rows.iter_mut().enumerate().for_each(|(i, row)| {
                let cols: &mut ExpReverseBitsLenCols<F> = row.as_mut_slice().borrow_mut();

                let prev_accum = accum;
                accum = prev_accum
                    * prev_accum
                    * if event.exp[i] == F::one() { event.base } else { F::one() };

                cols.x = event.base;
                cols.current_bit = event.exp[i];
                cols.accum = accum;
                cols.accum_squared = accum * accum;
                cols.prev_accum_squared = prev_accum * prev_accum;
                cols.multiplier = if event.exp[i] == F::one() { event.base } else { F::one() };
                cols.prev_accum_squared_times_multiplier =
                    cols.prev_accum_squared * cols.multiplier;
                if i == event.exp.len() {
                    assert_eq!(event.result, accum);
                }
            });

            overall_rows.extend(rows);
        });

        // Pad the trace to a power of two.
        pad_rows_fixed(
            &mut overall_rows,
            || [F::zero(); NUM_EXP_REVERSE_BITS_LEN_COLS].to_vec(),
            input.fixed_log2_rows(self),
        );

        // Convert the trace to a row major matrix.
        let trace = RowMajorMatrix::new(
            overall_rows.into_iter().flatten().collect(),
            NUM_EXP_REVERSE_BITS_LEN_COLS,
        );

        #[cfg(debug_assertions)]
        println!(
            "exp reverse bits len trace dims is width: {:?}, height: {:?}",
            trace.width(),
            trace.height()
        );

        trace
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<const DEGREE: usize> ExpReverseBitsLenChip<DEGREE> {
    pub fn eval_exp_reverse_bits_len<
        AB: BaseAirBuilder + ExtensionAirBuilder + SP1RecursionAirBuilder + SP1AirBuilder,
    >(
        &self,
        builder: &mut AB,
        local: &ExpReverseBitsLenCols<AB::Var>,
        local_prepr: &ExpReverseBitsLenPreprocessedCols<AB::Var>,
        next: &ExpReverseBitsLenCols<AB::Var>,
        next_prepr: &ExpReverseBitsLenPreprocessedCols<AB::Var>,
    ) {
        // Dummy constraints to normalize to DEGREE when DEGREE > 3.
        if DEGREE > 3 {
            let lhs = (0..DEGREE).map(|_| local_prepr.is_real.into()).product::<AB::Expr>();
            let rhs = (0..DEGREE).map(|_| local_prepr.is_real.into()).product::<AB::Expr>();
            builder.assert_eq(lhs, rhs);
        }

        // Constrain mem read for x.  The read mult is one for only the first row, and zero for all
        // others.
        builder.send_single(local_prepr.x_mem.addr, local.x, local_prepr.x_mem.mult);

        // Ensure that the value at the x memory access is unchanged when not `is_last`.
        builder
            .when_transition()
            .when(next_prepr.is_real)
            .when_not(local_prepr.is_last)
            .assert_eq(local.x, next.x);

        // Constrain mem read for exponent's bits.  The read mult is one for all real rows.
        builder.send_single(
            local_prepr.exponent_mem.addr,
            local.current_bit,
            local_prepr.exponent_mem.mult,
        );

        // The accumulator needs to start with the multiplier for every `is_first` row.
        builder.when(local_prepr.is_first).assert_eq(local.accum, local.multiplier);

        // `multiplier` is x if the current bit is 1, and 1 if the current bit is 0.
        builder
            .when(local_prepr.is_real)
            .when(local.current_bit)
            .assert_eq(local.multiplier, local.x);
        builder
            .when(local_prepr.is_real)
            .when_not(local.current_bit)
            .assert_eq(local.multiplier, AB::Expr::one());

        // To get `next.accum`, we multiply `local.prev_accum_squared` by `local.multiplier` when
        // not `is_last`.
        builder.when(local_prepr.is_real).assert_eq(
            local.prev_accum_squared_times_multiplier,
            local.prev_accum_squared * local.multiplier,
        );

        builder
            .when(local_prepr.is_real)
            .when_not(local_prepr.is_first)
            .assert_eq(local.accum, local.prev_accum_squared_times_multiplier);

        // Constrain the accum_squared column.
        builder.when(local_prepr.is_real).assert_eq(local.accum_squared, local.accum * local.accum);

        builder
            .when_transition()
            .when(next_prepr.is_real)
            .when_not(local_prepr.is_last)
            .assert_eq(next.prev_accum_squared, local.accum_squared);

        // Constrain mem write for the result.
        builder.send_single(local_prepr.result_mem.addr, local.accum, local_prepr.result_mem.mult);
    }

    pub const fn do_exp_bit_memory_access<T: Copy>(
        local: &ExpReverseBitsLenPreprocessedCols<T>,
    ) -> T {
        local.is_real
    }
}

impl<AB, const DEGREE: usize> Air<AB> for ExpReverseBitsLenChip<DEGREE>
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &ExpReverseBitsLenCols<AB::Var> = (*local).borrow();
        let next: &ExpReverseBitsLenCols<AB::Var> = (*next).borrow();
        let prep = builder.preprocessed();
        let (prep_local, prep_next) = (prep.row_slice(0), prep.row_slice(1));
        let prep_local: &ExpReverseBitsLenPreprocessedCols<_> = (*prep_local).borrow();
        let prep_next: &ExpReverseBitsLenPreprocessedCols<_> = (*prep_next).borrow();
        self.eval_exp_reverse_bits_len::<AB>(builder, local, prep_local, next, prep_next);
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use p3_util::reverse_bits_len;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sp1_core_machine::utils::setup_logger;
    use sp1_stark::{air::MachineAir, StarkGenericConfig};
    use std::iter::once;

    use p3_baby_bear::BabyBear;
    use p3_field::{AbstractField, PrimeField32};
    use p3_matrix::dense::RowMajorMatrix;

    use crate::{
        chips::exp_reverse_bits::ExpReverseBitsLenChip,
        machine::tests::run_recursion_test_machines,
        runtime::{instruction as instr, ExecutionRecord},
        stark::BabyBearPoseidon2Outer,
        ExpReverseBitsEvent, Instruction, MemAccessKind, RecursionProgram,
    };

    #[test]
    fn prove_babybear_circuit_erbl() {
        setup_logger();
        type SC = BabyBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut random_felt = move || -> F { F::from_canonical_u32(rng.gen_range(0..1 << 16)) };
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut random_bit = move || rng.gen_range(0..2);
        let mut addr = 0;

        let instructions = (1..15)
            .flat_map(|i| {
                let base = random_felt();
                let exponent_bits = vec![random_bit(); i];
                let exponent = F::from_canonical_u32(
                    exponent_bits.iter().enumerate().fold(0, |acc, (i, x)| acc + x * (1 << i)),
                );
                let result =
                    base.exp_u64(reverse_bits_len(exponent.as_canonical_u32() as usize, i) as u64);

                let alloc_size = i + 2;
                let exp_a = (0..i).map(|x| x + addr + 1).collect::<Vec<_>>();
                let exp_a_clone = exp_a.clone();
                let x_a = addr;
                let result_a = addr + alloc_size - 1;
                addr += alloc_size;
                let exp_bit_instructions = (0..i).map(move |j| {
                    instr::mem_single(
                        MemAccessKind::Write,
                        1,
                        exp_a_clone[j] as u32,
                        F::from_canonical_u32(exponent_bits[j]),
                    )
                });
                once(instr::mem_single(MemAccessKind::Write, 1, x_a as u32, base))
                    .chain(exp_bit_instructions)
                    .chain(once(instr::exp_reverse_bits_len(
                        1,
                        F::from_canonical_u32(x_a as u32),
                        exp_a
                            .into_iter()
                            .map(|bit| F::from_canonical_u32(bit as u32))
                            .collect_vec(),
                        F::from_canonical_u32(result_a as u32),
                    )))
                    .chain(once(instr::mem_single(MemAccessKind::Read, 1, result_a as u32, result)))
            })
            .collect::<Vec<Instruction<F>>>();

        let program = RecursionProgram { instructions, ..Default::default() };

        run_recursion_test_machines(program);
    }

    #[test]
    fn generate_erbl_circuit_trace() {
        type F = BabyBear;

        let shard = ExecutionRecord {
            exp_reverse_bits_len_events: vec![ExpReverseBitsEvent {
                base: F::two(),
                exp: vec![F::zero(), F::one(), F::one()],
                result: F::two().exp_u64(0b110),
            }],
            ..Default::default()
        };
        let chip = ExpReverseBitsLenChip::<3>;
        let trace: RowMajorMatrix<F> = chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }
}
