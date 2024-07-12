#![allow(clippy::needless_range_loop)]

use crate::air::{Block, IsZeroOperation, RecursionMemoryAirBuilder};
use crate::memory::{MemoryReadSingleCols, MemoryReadWriteSingleCols};
use crate::runtime::Opcode;
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_util::reverse_bits_len;
use sp1_core::air::{BaseAirBuilder, ExtensionAirBuilder, MachineAir, SP1AirBuilder};
use sp1_core::utils::{next_power_of_two, par_for_each_row};
use sp1_derive::AlignedBorrow;
use std::borrow::BorrowMut;
use tracing::instrument;

use crate::air::SP1RecursionAirBuilder;
use crate::memory::MemoryRecord;
use crate::runtime::{ExecutionRecord, RecursionProgram};

pub const NUM_EXP_REVERSE_BITS_LEN_COLS: usize = core::mem::size_of::<ExpReverseBitsLenCols<u8>>();

#[derive(Default)]
pub struct ExpReverseBitsLenChip<const DEGREE: usize> {
    pub fixed_log2_rows: Option<usize>,
    pub pad: bool,
}

#[derive(Debug, Clone)]
pub struct ExpReverseBitsLenEvent<F> {
    /// The clk cycle for the event.
    pub clk: F,

    /// Memory records to keep track of the value stored in the x parameter, and the current bit
    /// of the exponent being scanned.
    pub x: MemoryRecord<F>,
    pub current_bit: MemoryRecord<F>,

    /// The length parameter of the function.
    pub len: F,

    /// The previous accumulator value, needed to compute the current accumulator value.
    pub prev_accum: F,

    /// The current accumulator value.
    pub accum: F,

    /// A pointer to the memory address storing the exponent.
    pub ptr: F,

    /// A pointer to the memory address storing the base.
    pub base_ptr: F,

    /// Which step (in the range 0..len) of the computation we are in.
    pub iteration_num: F,
}

impl<F: PrimeField32> ExpReverseBitsLenEvent<F> {
    /// A way to construct a list of dummy events from input x and clk, used for testing.
    pub fn dummy_from_input(x: F, exponent: u32, len: F, timestamp: F) -> Vec<Self> {
        let mut events = Vec::new();
        let mut new_len = len;
        let mut new_exponent = exponent;
        let mut accum = F::one();

        for i in 0..len.as_canonical_u32() {
            let current_bit = new_exponent % 2;
            let prev_accum = accum;
            accum = prev_accum * prev_accum * if current_bit == 0 { F::one() } else { x };
            events.push(Self {
                clk: timestamp + F::from_canonical_u32(i),
                x: MemoryRecord::new_write(
                    F::one(),
                    Block::from([
                        if i == len.as_canonical_u32() - 1 {
                            accum
                        } else {
                            x
                        },
                        F::zero(),
                        F::zero(),
                        F::zero(),
                    ]),
                    timestamp + F::from_canonical_u32(i),
                    Block::from([x, F::zero(), F::zero(), F::zero()]),
                    timestamp + F::from_canonical_u32(i) - F::one(),
                ),
                current_bit: MemoryRecord::new_read(
                    F::zero(),
                    Block::from([
                        F::from_canonical_u32(current_bit),
                        F::zero(),
                        F::zero(),
                        F::zero(),
                    ]),
                    timestamp + F::from_canonical_u32(i),
                    timestamp + F::from_canonical_u32(i) - F::one(),
                ),
                len: new_len,
                prev_accum,
                accum,
                ptr: F::from_canonical_u32(i),
                base_ptr: F::one(),
                iteration_num: F::from_canonical_u32(i),
            });
            new_exponent /= 2;
            new_len -= F::one();
        }
        assert_eq!(
            accum,
            x.exp_u64(reverse_bits_len(exponent as usize, len.as_canonical_u32() as usize) as u64)
        );
        events
    }
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExpReverseBitsLenCols<T: Copy> {
    pub clk: T,

    /// The base of the exponentiation.
    pub x: MemoryReadWriteSingleCols<T>,

    /// The length parameter of the exponentiation. This is decremented by 1 every iteration.
    pub len: T,

    /// The current bit of the exponent. This is read from memory.
    pub current_bit: MemoryReadSingleCols<T>,

    /// The previous accumulator squared.
    pub prev_accum_squared: T,

    /// The accumulator of the current iteration.
    pub accum: T,

    /// A flag column to check whether the current row represents the last iteration of the computation.
    pub is_last: IsZeroOperation<T>,

    /// A flag column to check whether the current row represents the first iteration of the computation.
    pub is_first: IsZeroOperation<T>,

    /// A column to count up from 0 to the length of the exponent.
    pub iteration_num: T,

    /// A column which equals x if `current_bit` is on, and 1 otherwise.
    pub multiplier: T,

    /// The memory address storing the exponent.
    pub ptr: T,

    /// The memory address storing the base.
    pub base_ptr: T,

    /// A flag column to check whether the base_ptr memory is accessed. Is equal to `is_first` OR
    /// `is_last`.
    pub x_mem_access_flag: T,

    pub is_real: T,
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

    #[instrument(name = "generate exp reverse bits len trace", level = "debug", skip_all, fields(rows = input.exp_reverse_bits_len_events.len()))]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let nb_events = input.exp_reverse_bits_len_events.len();
        let nb_rows = if self.pad {
            next_power_of_two(nb_events, self.fixed_log2_rows)
        } else {
            nb_events
        };
        let mut values = vec![F::zero(); nb_rows * NUM_EXP_REVERSE_BITS_LEN_COLS];

        par_for_each_row(&mut values, NUM_EXP_REVERSE_BITS_LEN_COLS, |i, row| {
            if i >= nb_events {
                return;
            }
            let event = &input.exp_reverse_bits_len_events[i];
            let cols: &mut ExpReverseBitsLenCols<F> = row.borrow_mut();

            cols.clk = event.clk;

            cols.x.populate(&event.x);
            cols.current_bit.populate(&event.current_bit);
            cols.len = event.len;
            cols.accum = event.accum;
            cols.prev_accum_squared = event.prev_accum * event.prev_accum;
            cols.is_last.populate(F::one() - event.len);
            cols.is_first.populate(event.iteration_num);
            cols.is_real = F::one();
            cols.iteration_num = event.iteration_num;
            cols.multiplier =
                if event.current_bit.value == Block([F::one(), F::zero(), F::zero(), F::zero()]) {
                    // The event may change the value stored in the x memory access, and we need to
                    // use the previous value.
                    event.x.prev_value[0]
                } else {
                    F::one()
                };
            cols.ptr = event.ptr;
            cols.base_ptr = event.base_ptr;
            cols.x_mem_access_flag =
                F::from_bool(cols.len == F::one() || cols.iteration_num == F::zero());
        });

        // Convert the trace to a row major matrix.
        let trace = RowMajorMatrix::new(values, NUM_EXP_REVERSE_BITS_LEN_COLS);

        #[cfg(debug_assertions)]
        println!(
            "exp reverse bits len trace dims is width: {:?}, height: {:?}",
            trace.width(),
            trace.height()
        );

        trace
    }

    fn included(&self, record: &Self::Record) -> bool {
        !record.exp_reverse_bits_len_events.is_empty()
    }
}

impl<const DEGREE: usize> ExpReverseBitsLenChip<DEGREE> {
    pub fn eval_exp_reverse_bits_len<
        AB: BaseAirBuilder + ExtensionAirBuilder + RecursionMemoryAirBuilder + SP1AirBuilder,
    >(
        &self,
        builder: &mut AB,
        local: &ExpReverseBitsLenCols<AB::Var>,
        next: &ExpReverseBitsLenCols<AB::Var>,
        memory_access: AB::Var,
    ) {
        // Dummy constraints to normalize to DEGREE when DEGREE > 3.
        if DEGREE > 3 {
            let lhs = (0..DEGREE)
                .map(|_| local.is_real.into())
                .product::<AB::Expr>();
            let rhs = (0..DEGREE)
                .map(|_| local.is_real.into())
                .product::<AB::Expr>();
            builder.assert_eq(lhs, rhs);
        }

        // Constraint that the operands are sent from the CPU table.
        let operands = [
            local.clk.into(),
            local.base_ptr.into(),
            local.ptr.into(),
            local.len.into(),
        ];
        builder.receive_table(
            Opcode::ExpReverseBitsLen.as_field::<AB::F>(),
            &operands,
            local.is_first.result,
        );

        // Make sure that local.is_first.result is not on for fake rows, so we don't receive operands
        // for a fake row.
        builder
            .when_not(local.is_real)
            .assert_zero(local.is_first.result);

        IsZeroOperation::<AB::F>::eval(
            builder,
            AB::Expr::one() - local.len,
            local.is_last,
            local.is_real.into(),
        );

        IsZeroOperation::<AB::F>::eval(
            builder,
            local.iteration_num.into(),
            local.is_first,
            local.is_real.into(),
        );

        // All real columns need to be in succession.
        builder
            .when_transition()
            .assert_zero((AB::Expr::one() - local.is_real) * next.is_real);

        // Assert that the boolean columns are boolean.
        builder.assert_bool(local.is_real);

        let current_bit_val = local.current_bit.access.value;

        // Probably redundant, but we assert here that the current bit value is boolean.
        builder.assert_bool(current_bit_val);

        // Assert that `is_first` is on for the first row.
        builder.when_first_row().assert_one(local.is_first.result);

        // Assert that the next row after a row for which `is_last` is on has `is_first` on.
        builder
            .when_transition()
            .when(next.is_real * local.is_last.result)
            .assert_one(next.is_first.result);

        // The accumulator needs to start with the multiplier for every `is_first` row.
        builder
            .when(local.is_first.result)
            .assert_eq(local.accum, local.multiplier);

        // Assert that the last real row has `is_last` on.
        builder
            .when_transition()
            .when(local.is_real * (AB::Expr::one() - next.is_real))
            .assert_one(local.is_last.result);

        builder
            .when_last_row()
            .when(local.is_real)
            .assert_one(local.is_last.result);

        // `multiplier` is x if the current bit is 1, and 1 if the current bit is 0.
        builder
            .when(current_bit_val)
            .assert_eq(local.multiplier, local.x.prev_value);
        builder
            .when(local.is_real)
            .when_not(current_bit_val)
            .assert_eq(local.multiplier, AB::Expr::one());

        // To get `next.accum`, we multiply `local.prev_accum_squared` by `local.multiplier` when not
        // `is_first`.
        builder
            .when_not(local.is_first.result)
            .assert_eq(local.accum, local.prev_accum_squared * local.multiplier);

        // Constrain the accum_squared column.
        builder
            .when_transition()
            .when_not(local.is_last.result)
            .assert_eq(next.prev_accum_squared, local.accum * local.accum);

        // Constrain the memory address `base_ptr` to be the same as the next, as long as not `is_last`.
        builder
            .when_transition()
            .when_not(local.is_last.result)
            .assert_eq(local.base_ptr, next.base_ptr);

        // Constrain the memory address `ptr` to increment by one except when
        // `is_last`
        builder
            .when_transition()
            .when(next.is_real)
            .when_not(local.is_last.result)
            .assert_eq(next.ptr, local.ptr + AB::Expr::one());

        // The `len` counter must decrement when not `is_last`.
        builder
            .when_transition()
            .when(local.is_real)
            .when_not(local.is_last.result)
            .assert_eq(local.len, next.len + AB::Expr::one());

        // The `iteration_num` counter must increment when not `is_last`.
        builder
            .when_transition()
            .when(local.is_real)
            .when_not(local.is_last.result)
            .assert_eq(local.iteration_num + AB::Expr::one(), next.iteration_num);

        // The `iteration_num` counter must be 0 iff `is_first` is on.
        builder
            .when(local.is_first.result)
            .assert_eq(local.iteration_num, AB::Expr::zero());

        // Access the memory for current_bit.
        builder.recursion_eval_memory_access_single(
            local.clk,
            local.ptr,
            &local.current_bit,
            memory_access,
        );

        // Constrain that the x_mem_access_flag is true when `is_first` or `is_last`.
        builder.when(local.is_real).assert_eq(
            local.x_mem_access_flag,
            local.is_first.result + local.is_last.result
                - local.is_first.result * local.is_last.result,
        );

        // Make sure that x is only accessed when `is_real` is 1.
        builder
            .when_not(local.is_real)
            .assert_zero(local.x_mem_access_flag);

        // Access the memory for x.
        // This only needs to be done for the first and last iterations.
        builder.recursion_eval_memory_access_single(
            local.clk,
            local.base_ptr,
            &local.x,
            local.x_mem_access_flag,
        );

        // The `base_ptr` column stays the same when not `is_last`.
        builder
            .when_transition()
            .when(next.is_real)
            .when_not(local.is_last.result)
            .assert_eq(next.base_ptr, local.base_ptr);

        // Ensure sequential `clk` values.
        builder
            .when_transition()
            .when_not(local.is_last.result)
            .when(next.is_real)
            .assert_eq(local.clk + AB::Expr::one(), next.clk);

        // Ensure that the value at the x memory access is unchanged when not `is_last`.
        builder
            .when_transition()
            .when(next.is_real)
            .when_not(local.is_last.result)
            .assert_eq(local.x.access.value, next.x.prev_value);

        builder
            .when_transition()
            .when_not(local.is_last.result)
            .assert_eq(local.x.access.value, local.x.prev_value);

        // Ensure that the value at the x memory access is `accum` when `is_last`.
        builder
            .when(local.is_last.result)
            .assert_eq(local.accum, local.x.access.value);
    }

    pub const fn do_exp_bit_memory_access<T: Copy>(local: &ExpReverseBitsLenCols<T>) -> T {
        local.is_real
    }
}

impl<AB, const DEGREE: usize> Air<AB> for ExpReverseBitsLenChip<DEGREE>
where
    AB: SP1RecursionAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &ExpReverseBitsLenCols<AB::Var> = (*local).borrow();
        let next: &ExpReverseBitsLenCols<AB::Var> = (*next).borrow();
        self.eval_exp_reverse_bits_len::<AB>(
            builder,
            local,
            next,
            Self::do_exp_bit_memory_access::<AB::Var>(local),
        );
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
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
    use crate::exp_reverse_bits::ExpReverseBitsLenEvent;
    use crate::runtime::ExecutionRecord;

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::compressed();
        let mut challenger = config.challenger();

        let chip = ExpReverseBitsLenChip::<5> {
            pad: true,
            fixed_log2_rows: None,
        };

        let test_xs = (1..16).map(BabyBear::from_canonical_u32).collect_vec();

        let test_exponents = (1..16).collect_vec();

        let mut input_exec = ExecutionRecord::<BabyBear>::default();
        for (x, exponent) in test_xs.into_iter().zip_eq(test_exponents) {
            let mut events = ExpReverseBitsLenEvent::dummy_from_input(
                x,
                exponent,
                BabyBear::from_canonical_u32(exponent.ilog2() + 1),
                x,
            );
            input_exec.exp_reverse_bits_len_events.append(&mut events);
        }
        println!(
            "input exec: {:?}",
            input_exec.exp_reverse_bits_len_events.len()
        );
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());
        println!(
            "trace dims is width: {:?}, height: {:?}",
            trace.width(),
            trace.height()
        );

        let start = Instant::now();
        let proof = uni_stark_prove(&config, &chip, &mut challenger, trace);
        let duration = start.elapsed().as_secs_f64();
        println!("proof duration = {:?}", duration);

        let mut challenger: p3_challenger::DuplexChallenger<
            BabyBear,
            Poseidon2<BabyBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>,
            16,
            8,
        > = config.challenger();
        let start = Instant::now();
        uni_stark_verify(&config, &chip, &mut challenger, &proof)
            .expect("expected proof to be valid");

        let duration = start.elapsed().as_secs_f64();
        println!("verify duration = {:?}", duration);
    }
}
