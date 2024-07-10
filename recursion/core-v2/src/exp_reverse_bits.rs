#![allow(clippy::needless_range_loop)]

use crate::mem::MemoryPreprocessedCols;
// use crate::memory::{MemoryReadSingleCols, MemoryReadWriteSingleCols};
use crate::runtime::Opcode;
use core::borrow::Borrow;
use itertools::Itertools;
use p3_air::PairBuilder;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_util::reverse_bits_len;
use sp1_core::air::{BaseAirBuilder, ExtensionAirBuilder, MachineAir, SP1AirBuilder};
use sp1_core::utils::pad_rows_fixed;
use sp1_derive::AlignedBorrow;
use sp1_recursion_core::air::{Block, IsZeroOperation, RecursionMemoryAirBuilder};
use std::borrow::BorrowMut;
use tracing::instrument;

// use crate::memory::MemoryRecord;
use crate::builder::SP1RecursionAirBuilder;
use crate::runtime::{ExecutionRecord, RecursionProgram};

pub const NUM_EXP_REVERSE_BITS_LEN_COLS: usize = core::mem::size_of::<ExpReverseBitsLenCols<u8>>();

#[derive(Default)]
pub struct ExpReverseBitsLenChip<const DEGREE: usize> {
    pub fixed_log2_rows: Option<usize>,
    pub pad: bool,
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExpReverseBitsLenPreprocessedCols<T: Copy> {
    pub x_memory: MemoryPreprocessedCols<T>,
    pub exponent_memory: MemoryPreprocessedCols<T>,
    pub len: T,
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

    /// The length parameter of the exponentiation. This is decremented by 1 every iteration.
    pub len: T,

    /// The current bit of the exponent. This is read from memory.
    pub current_bit: T,

    /// The previous accumulator squared.
    pub prev_accum_squared: T,

    /// The accumulator of the current iteration.
    pub accum: T,

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

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        None
    }

    #[instrument(name = "generate exp reverse bits len trace", level = "debug", skip_all, fields(rows = input.exp_reverse_bits_len_events.len()))]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut overall_rows = Vec::new();
        input.exp_reverse_bits_len_events.iter().for_each(|event| {
            let mut rows = vec![
                vec![F::zero(); NUM_EXP_REVERSE_BITS_LEN_COLS];
                event.len.as_canonical_u32() as usize
            ];

            let mut accum = F::one();

            rows.iter_mut().enumerate().for_each(|(i, row)| {
                let cols: &mut ExpReverseBitsLenCols<F> = row.as_mut_slice().borrow_mut();

                let prev_accum = accum;
                accum = prev_accum
                    * prev_accum
                    * if event.exp[i] == F::one() {
                        event.base
                    } else {
                        F::one()
                    };

                cols.x = event.base;
                cols.current_bit = event.exp[i];
                cols.len = event.len;
                cols.accum = accum;
                cols.prev_accum_squared = prev_accum * prev_accum;
                cols.multiplier = if event.exp[i] == F::one() {
                    // The event may change the value stored in the x memory access, and we need to
                    // use the previous value.
                    event.base
                } else {
                    F::one()
                };
                if i == event.len.as_canonical_u32() as usize {
                    assert_eq!(event.result, accum);
                }
            });

            overall_rows.extend(rows);
        });

        // Pad the trace to a power of two.
        if self.pad {
            pad_rows_fixed(
                &mut overall_rows,
                || [F::zero(); NUM_EXP_REVERSE_BITS_LEN_COLS].to_vec(),
                self.fixed_log2_rows,
            );
        }

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
        AB: BaseAirBuilder + ExtensionAirBuilder + RecursionMemoryAirBuilder + SP1AirBuilder,
    >(
        &self,
        builder: &mut AB,
        local: &ExpReverseBitsLenCols<AB::Var>,
        prepr: &ExpReverseBitsLenPreprocessedCols<AB::Var>,
        next: &ExpReverseBitsLenCols<AB::Var>,
        memory_access: AB::Var,
    ) {
        // Dummy constraints to normalize to DEGREE when DEGREE > 3.
        // if DEGREE > 3 {
        //     let lhs = (0..DEGREE)
        //         .map(|_| local.is_real.into())
        //         .product::<AB::Expr>();
        //     let rhs = (0..DEGREE)
        //         .map(|_| local.is_real.into())
        //         .product::<AB::Expr>();
        //     builder.assert_eq(lhs, rhs);
        // }

        // // Constraint that the operands are sent from the CPU table.
        // let operands = [
        //     local.clk.into(),
        //     local.base_ptr.into(),
        //     local.ptr.into(),
        //     local.len.into(),
        // ];
        // builder.receive_table(
        //     Opcode::ExpReverseBitsLen.as_field::<AB::F>(),
        //     &operands,
        //     local.is_first.result,
        // );

        // IsZeroOperation::<AB::F>::eval(
        //     builder,
        //     AB::Expr::one() - local.len,
        //     local.is_last,
        //     local.is_real.into(),
        // );
        // // Assert that the boolean columns are boolean.
        // builder.assert_bool(local.is_real);

        // let current_bit_val = local.current_bit.access.value;

        // // Probably redundant, but we assert here that the current bit value is boolean.
        // builder.assert_bool(current_bit_val);

        // // Assert that `is_first` is on for the first row.
        // builder.when_first_row().assert_one(local.is_first.result);

        // // Assert that the next row after a row for which `is_last` is on has `is_first` on.
        // builder
        //     .when_transition()
        //     .when(next.is_real * local.is_last.result)
        //     .assert_one(next.is_first.result);

        // // The accumulator needs to start with the multiplier for every `is_first` row.
        // builder
        //     .when(local.is_first.result)
        //     .assert_eq(local.accum, local.multiplier);

        // // Assert that the last real row has `is_last` on.
        // builder
        //     .when(local.is_real * (AB::Expr::one() - next.is_real))
        //     .assert_one(local.is_last.result);

        // // `multiplier` is x if the current bit is 1, and 1 if the current bit is 0.
        // builder
        //     .when(current_bit_val)
        //     .assert_eq(local.multiplier, local.x.prev_value);
        // builder
        //     .when(local.is_real)
        //     .when_not(current_bit_val)
        //     .assert_eq(local.multiplier, AB::Expr::one());

        // // To get `next.accum`, we multiply `local.prev_accum_squared` by `local.multiplier` when not
        // // `is_last`.
        // builder
        //     .when_transition()
        //     .when_not(local.is_last.result)
        //     .assert_eq(local.accum, local.prev_accum_squared * local.multiplier);

        // // Constrain the accum_squared column.
        // builder
        //     .when_transition()
        //     .when_not(local.is_last.result)
        //     .assert_eq(next.prev_accum_squared, local.accum * local.accum);

        // // Constrain the memory address `base_ptr` to be the same as the next, as long as not `is_last`.
        // builder
        //     .when_transition()
        //     .when_not(local.is_last.result)
        //     .assert_eq(local.base_ptr, next.base_ptr);

        // // The `len` counter must decrement when not `is_last`.
        // builder
        //     .when_transition()
        //     .when(local.is_real)
        //     .when_not(local.is_last.result)
        //     .assert_eq(local.len, next.len + AB::Expr::one());

        // // The `iteration_num` counter must increment when not `is_last`.
        // builder
        //     .when_transition()
        //     .when(local.is_real)
        //     .when_not(local.is_last.result)
        //     .assert_eq(local.iteration_num + AB::Expr::one(), next.iteration_num);

        // // The `iteration_num` counter must be 0 iff `is_first` is on.
        // builder
        //     .when(local.is_first.result)
        //     .assert_eq(local.iteration_num, AB::Expr::zero());

        // // Access the memory for current_bit.
        // builder.recursion_eval_memory_access_single(
        //     local.clk,
        //     local.ptr,
        //     &local.current_bit,
        //     memory_access,
        // );

        // // Constrain that the x_mem_access_flag is true when `is_first` or `is_last`.
        // builder.when(local.is_real).assert_eq(
        //     local.x_mem_access_flag,
        //     local.is_first.result + local.is_last.result
        //         - local.is_first.result * local.is_last.result,
        // );

        // // Access the memory for x.
        // // This only needs to be done for the first and last iterations.
        // builder.recursion_eval_memory_access_single(
        //     local.clk,
        //     local.base_ptr,
        //     &local.x,
        //     local.x_mem_access_flag,
        // );

        // // The `base_ptr` column stays the same when not `is_last`.
        // builder
        //     .when_transition()
        //     .when(next.is_real)
        //     .when_not(local.is_last.result)
        //     .assert_eq(next.base_ptr, local.base_ptr);

        // // Ensure sequential `clk` values.
        // builder
        //     .when_transition()
        //     .when_not(local.is_last.result)
        //     .when(next.is_real)
        //     .assert_eq(local.clk + AB::Expr::one(), next.clk);

        // // Ensure that the value at the x memory access is unchanged when not `is_last`.
        // builder
        //     .when_not(local.is_last.result)
        //     .assert_eq(local.x.access.value, local.x.prev_value);

        // // Ensure that the value at the x memory access is `accum` when `is_last`.
        // builder
        //     .when(local.is_last.result)
        //     .assert_eq(local.accum, local.x.access.value);
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
        let prep_local = prep.row_slice(0);
        // self.eval_exp_reverse_bits_len::<AB>(
        //     builder,
        //     local,
        //     next,
        //     Self::do_exp_bit_memory_access::<AB::Var>(local),
        // );
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use p3_util::reverse_bits_len;
    use std::time::Instant;

    use p3_baby_bear::BabyBear;
    use p3_baby_bear::DiffusionMatrixBabyBear;
    use p3_field::AbstractField;
    use p3_matrix::{dense::RowMajorMatrix, Matrix};
    use p3_poseidon2::Poseidon2;
    use p3_poseidon2::Poseidon2ExternalMatrixGeneral;
    use sp1_core::stark::StarkGenericConfig;
    use sp1_core::{
        air::MachineAir,
        utils::{uni_stark_prove, uni_stark_verify, BabyBearPoseidon2},
    };

    use crate::exp_reverse_bits::ExpReverseBitsLenChip;
    use crate::runtime::ExecutionRecord;
    use crate::ExpReverseBitsEvent;

    #[test]
    fn prove_babybear() {
        // let config = BabyBearPoseidon2::compressed();
        // let mut challenger = config.challenger();

        // let chip = ExpReverseBitsLenChip::<5> {
        //     pad: true,
        //     fixed_log2_rows: None,
        // };

        // let test_xs = (1..16).map(BabyBear::from_canonical_u32).collect_vec();

        // let test_exponents: Vec<u32> = (1..16).collect_vec();

        // let mut input_exec = ExecutionRecord::<BabyBear>::default();
        // for (x, exponent) in test_xs.into_iter().zip_eq(test_exponents) {
        //     let num_bits = exponent.ilog2() + 1;
        //     let exp_bits: [u32; 32] = (0..32)
        //         .map(|i| (exponent >> i) & 1)
        //         .collect_vec()
        //         .try_into()
        //         .unwrap();
        //     let event = ExpReverseBitsEvent {
        //         base: x,
        //         exp: exp_bits.map(BabyBear::from_canonical_u32),
        //         len: BabyBear::from_canonical_u32(num_bits),
        //         result: x.exp_u64(reverse_bits_len(exponent as usize, num_bits as usize) as u64),
        //     };
        //     input_exec.exp_reverse_bits_len_events.push(event);
        // }
        // println!(
        //     "input exec: {:?}",
        //     input_exec.exp_reverse_bits_len_events.len()
        // );
        // let trace: RowMajorMatrix<BabyBear> =
        //     chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());
        // println!(
        //     "trace dims is width: {:?}, height: {:?}",
        //     trace.width(),
        //     trace.height()
        // );

        // let start = Instant::now();
        // let proof = uni_stark_prove(&config, &chip, &mut challenger, trace);
        // let duration = start.elapsed().as_secs_f64();
        // println!("proof duration = {:?}", duration);

        // let mut challenger: p3_challenger::DuplexChallenger<
        //     BabyBear,
        //     Poseidon2<BabyBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>,
        //     16,
        //     8,
        // > = config.challenger();
        // let start = Instant::now();
        // uni_stark_verify(&config, &chip, &mut challenger, &proof)
        //     .expect("expected proof to be valid");

        // let duration = start.elapsed().as_secs_f64();
        // println!("verify duration = {:?}", duration);
    }
}
