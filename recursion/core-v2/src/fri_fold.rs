#![allow(clippy::needless_range_loop)]

use crate::mem::MemoryPreprocessedColsNoVal;
use crate::{FriFoldInstr, Instruction};
use core::borrow::Borrow;
use itertools::Itertools;
use p3_air::PairBuilder;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::{BaseAirBuilder, BinomialExtension, MachineAir};
use sp1_core::utils::pad_rows_fixed;
use sp1_derive::AlignedBorrow;
use sp1_recursion_core::air::Block;
use std::borrow::BorrowMut;
use tracing::instrument;

use crate::builder::SP1RecursionAirBuilder;
// use crate::memory::MemoryRecord;
use crate::runtime::{ExecutionRecord, RecursionProgram};

pub const NUM_FRI_FOLD_COLS: usize = core::mem::size_of::<FriFoldCols<u8>>();
pub const NUM_FRI_FOLD_PREPROCESSED_COLS: usize =
    core::mem::size_of::<FriFoldPreprocessedCols<u8>>();

#[derive(Default)]
pub struct FriFoldChip<const DEGREE: usize> {
    pub fixed_log2_rows: Option<usize>,
    pub pad: bool,
}

/// The preprocessed columns for a FRI fold invocation.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct FriFoldPreprocessedCols<T: Copy> {
    /// Iteration number.
    pub m: T,

    pub is_last_iteration: T,

    pub z_mem: MemoryPreprocessedColsNoVal<T>,
    pub alpha_mem: MemoryPreprocessedColsNoVal<T>,
    pub x_mem: MemoryPreprocessedColsNoVal<T>,

    pub alpha_pow_input_mem: MemoryPreprocessedColsNoVal<T>,
    pub ro_input_mem: MemoryPreprocessedColsNoVal<T>,

    pub ro_output_mem: MemoryPreprocessedColsNoVal<T>,
    pub alpha_pow_output_mem: MemoryPreprocessedColsNoVal<T>,

    pub p_at_x_mem: MemoryPreprocessedColsNoVal<T>,
    pub p_at_z_mem: MemoryPreprocessedColsNoVal<T>,

    pub is_real: T,
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct FriFoldCols<T: Copy> {
    pub z: Block<T>,
    pub alpha: Block<T>,
    pub x: T,

    pub p_at_x: Block<T>,
    pub p_at_z: Block<T>,

    pub alpha_pow_input: Block<T>,
    pub ro_input: Block<T>,

    pub alpha_pow_output: Block<T>,
    pub ro_output: Block<T>,
}

impl<F, const DEGREE: usize> BaseAir<F> for FriFoldChip<DEGREE> {
    fn width(&self) -> usize {
        NUM_FRI_FOLD_COLS
    }
}

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for FriFoldChip<DEGREE> {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "FriFold".to_string()
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn preprocessed_width(&self) -> usize {
        NUM_FRI_FOLD_PREPROCESSED_COLS
    }
    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_FRI_FOLD_PREPROCESSED_COLS]> = Vec::new();
        program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::FriFold(instr) = instruction {
                    Some(instr)
                } else {
                    None
                }
            })
            .for_each(|instruction| {
                let FriFoldInstr {
                    base_single_addrs,
                    ext_single_addrs,
                    ext_vec_addrs,
                    alpha_pow_mults,
                    ro_mults,
                } = instruction;
                let mut row_add =
                    vec![[F::zero(); NUM_FRI_FOLD_PREPROCESSED_COLS]; ext_vec_addrs.ps_at_z.len()];
                row_add.iter_mut().enumerate().for_each(|(i, row)| {
                    let row: &mut FriFoldPreprocessedCols<F> = row.as_mut_slice().borrow_mut();

                    row.m = F::from_canonical_u32(i as u32);
                    row.is_last_iteration = F::from_bool(i == ext_vec_addrs.ps_at_z.len() - 1);

                    // Only need to read z, x, and alpha once, hence the multiplicities.
                    row.z_mem = MemoryPreprocessedColsNoVal {
                        addr: ext_single_addrs.z,
                        read_mult: F::from_bool(i == 0),
                        write_mult: F::zero(),
                        is_real: F::one(),
                    };
                    row.x_mem = MemoryPreprocessedColsNoVal {
                        addr: base_single_addrs.x,
                        read_mult: F::from_bool(i == 0),
                        write_mult: F::zero(),
                        is_real: F::from_bool(i == 0),
                    };
                    row.alpha_mem = MemoryPreprocessedColsNoVal {
                        addr: ext_single_addrs.alpha,
                        read_mult: F::from_bool(i == 0),
                        write_mult: F::zero(),
                        is_real: F::one(),
                    };

                    // Read the memory for the input vectors.
                    row.alpha_pow_input_mem = MemoryPreprocessedColsNoVal {
                        addr: ext_vec_addrs.alpha_pow_input[i],
                        read_mult: F::one(),
                        write_mult: F::zero(),
                        is_real: F::one(),
                    };
                    row.ro_input_mem = MemoryPreprocessedColsNoVal {
                        addr: ext_vec_addrs.ro_input[i],
                        read_mult: F::one(),
                        write_mult: F::zero(),
                        is_real: F::one(),
                    };
                    row.p_at_z_mem = MemoryPreprocessedColsNoVal {
                        addr: ext_vec_addrs.ps_at_z[i],
                        read_mult: F::one(),
                        write_mult: F::zero(),
                        is_real: F::one(),
                    };
                    row.p_at_x_mem = MemoryPreprocessedColsNoVal {
                        addr: ext_vec_addrs.mat_opening[i],
                        read_mult: F::one(),
                        write_mult: F::zero(),
                        is_real: F::one(),
                    };

                    // Write the memory for the output vectors.
                    row.alpha_pow_output_mem = MemoryPreprocessedColsNoVal {
                        addr: ext_vec_addrs.alpha_pow_output[i],
                        read_mult: F::zero(),
                        write_mult: alpha_pow_mults[i],
                        is_real: F::one(),
                    };
                    row.ro_output_mem = MemoryPreprocessedColsNoVal {
                        addr: ext_vec_addrs.ro_output[i],
                        read_mult: F::zero(),
                        write_mult: ro_mults[i],
                        is_real: F::one(),
                    };

                    row.is_real = F::one();
                });
                rows.extend(row_add);
            });

        // Pad the trace to a power of two.
        if self.pad {
            pad_rows_fixed(
                &mut rows,
                || [F::zero(); NUM_FRI_FOLD_PREPROCESSED_COLS],
                self.fixed_log2_rows,
            );
        }

        let trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect(),
            NUM_FRI_FOLD_PREPROCESSED_COLS,
        );
        Some(trace)
    }
    #[instrument(name = "generate fri fold trace", level = "debug", skip_all, fields(rows = input.fri_fold_events.len()))]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut rows = input
            .fri_fold_events
            .iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_FRI_FOLD_COLS];

                let cols: &mut FriFoldCols<F> = row.as_mut_slice().borrow_mut();

                cols.x = event.base_single.x;
                cols.z = event.ext_single.z;
                cols.alpha = event.ext_single.alpha;

                cols.p_at_z = event.ext_vec.ps_at_z;
                cols.p_at_x = event.ext_vec.mat_opening;
                cols.alpha_pow_input = event.ext_vec.alpha_pow_input;
                cols.ro_input = event.ext_vec.ro_input;

                cols.alpha_pow_output = event.ext_vec.alpha_pow_output;
                cols.ro_output = event.ext_vec.ro_output;

                row
            })
            .collect_vec();

        // Pad the trace to a power of two.
        if self.pad {
            pad_rows_fixed(
                &mut rows,
                || [F::zero(); NUM_FRI_FOLD_COLS],
                self.fixed_log2_rows,
            );
        }

        // Convert the trace to a row major matrix.
        let trace = RowMajorMatrix::new(rows.into_iter().flatten().collect(), NUM_FRI_FOLD_COLS);

        #[cfg(debug_assertions)]
        println!(
            "fri fold trace dims is width: {:?}, height: {:?}",
            trace.width(),
            trace.height()
        );

        trace
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<const DEGREE: usize> FriFoldChip<DEGREE> {
    pub fn eval_fri_fold<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        local: &FriFoldCols<AB::Var>,
        next: &FriFoldCols<AB::Var>,
        local_prepr: &FriFoldPreprocessedCols<AB::Var>,
        receive_table: AB::Var,
        memory_access: AB::Var,
    ) {
        builder.receive_single(local_prepr.x_mem.addr, local.x, local_prepr.x_mem.read_mult);

        builder.receive_block(local_prepr.z_mem.addr, local.z, local_prepr.z_mem.read_mult);

        builder.receive_block(
            local_prepr.alpha_mem.addr,
            local.alpha,
            local_prepr.alpha_mem.read_mult,
        );

        builder.receive_block(
            local_prepr.alpha_pow_input_mem.addr,
            local.alpha_pow_input,
            local_prepr.alpha_pow_input_mem.read_mult,
        );

        builder.receive_block(
            local_prepr.ro_input_mem.addr,
            local.ro_input,
            local_prepr.ro_input_mem.read_mult,
        );

        builder.receive_block(
            local_prepr.p_at_z_mem.addr,
            local.p_at_z,
            local_prepr.p_at_z_mem.read_mult,
        );

        builder.receive_block(
            local_prepr.p_at_x_mem.addr,
            local.p_at_x,
            local_prepr.p_at_x_mem.read_mult,
        );

        builder.send_block(
            local_prepr.alpha_pow_output_mem.addr,
            local.alpha_pow_output,
            local_prepr.alpha_pow_output_mem.write_mult,
        );

        builder.send_block(
            local_prepr.ro_output_mem.addr,
            local.ro_output,
            local_prepr.ro_output_mem.write_mult,
        );

        // // Constraint that the operands are sent from the CPU table.
        // let first_iteration_clk = local.clk.into() - local.m.into();
        // let total_num_iterations = local.m.into() + AB::Expr::one();
        // let operands = [
        //     first_iteration_clk,
        //     total_num_iterations,
        //     local.input_ptr.into(),
        //     AB::Expr::zero(),
        // ];
        // builder.receive_table(
        //     Opcode::FRIFold.as_field::<AB::F>(),
        //     &operands,
        //     receive_table,
        // );

        // builder.assert_bool(local.is_last_iteration);
        // builder.assert_bool(local.is_real);

        // builder
        //     .when_transition()
        //     .when_not(local.is_last_iteration)
        //     .assert_eq(local.is_real, next.is_real);

        // builder
        //     .when(local.is_last_iteration)
        //     .assert_one(local.is_real);

        // builder
        //     .when_transition()
        //     .when_not(local.is_real)
        //     .assert_zero(next.is_real);

        // builder
        //     .when_last_row()
        //     .when_not(local.is_last_iteration)
        //     .assert_zero(local.is_real);

        // // Ensure that all first iteration rows has a m value of 0.
        // builder.when_first_row().assert_zero(local.m);
        // builder
        //     .when(local.is_last_iteration)
        //     .when_transition()
        //     .when(next.is_real)
        //     .assert_zero(next.m);

        // // Ensure that all rows for a FRI FOLD invocation have the same input_ptr and sequential clk and m values.
        // builder
        //     .when_transition()
        //     .when_not(local.is_last_iteration)
        //     .when(next.is_real)
        //     .assert_eq(next.m, local.m + AB::Expr::one());
        // builder
        //     .when_transition()
        //     .when_not(local.is_last_iteration)
        //     .when(next.is_real)
        //     .assert_eq(local.input_ptr, next.input_ptr);
        // builder
        //     .when_transition()
        //     .when_not(local.is_last_iteration)
        //     .when(next.is_real)
        //     .assert_eq(local.clk + AB::Expr::one(), next.clk);

        // // Constrain read for `z` at `input_ptr`
        // builder.recursion_eval_memory_access(
        //     local.clk,
        //     local.input_ptr + AB::Expr::zero(),
        //     &local.z,
        //     memory_access,
        // );

        // // Constrain read for `alpha`
        // builder.recursion_eval_memory_access(
        //     local.clk,
        //     local.input_ptr + AB::Expr::one(),
        //     &local.alpha,
        //     memory_access,
        // );

        // // Constrain read for `x`
        // builder.recursion_eval_memory_access_single(
        //     local.clk,
        //     local.input_ptr + AB::Expr::from_canonical_u32(2),
        //     &local.x,
        //     memory_access,
        // );

        // // Constrain read for `log_height`
        // builder.recursion_eval_memory_access_single(
        //     local.clk,
        //     local.input_ptr + AB::Expr::from_canonical_u32(3),
        //     &local.log_height,
        //     memory_access,
        // );

        // // Constrain read for `mat_opening_ptr`
        // builder.recursion_eval_memory_access_single(
        //     local.clk,
        //     local.input_ptr + AB::Expr::from_canonical_u32(4),
        //     &local.mat_opening_ptr,
        //     memory_access,
        // );

        // // Constrain read for `ps_at_z_ptr`
        // builder.recursion_eval_memory_access_single(
        //     local.clk,
        //     local.input_ptr + AB::Expr::from_canonical_u32(6),
        //     &local.ps_at_z_ptr,
        //     memory_access,
        // );

        // // Constrain read for `alpha_pow_ptr`
        // builder.recursion_eval_memory_access_single(
        //     local.clk,
        //     local.input_ptr + AB::Expr::from_canonical_u32(8),
        //     &local.alpha_pow_ptr,
        //     memory_access,
        // );

        // // Constrain read for `ro_ptr`
        // builder.recursion_eval_memory_access_single(
        //     local.clk,
        //     local.input_ptr + AB::Expr::from_canonical_u32(10),
        //     &local.ro_ptr,
        //     memory_access,
        // );

        // // Constrain read for `p_at_x`
        // builder.recursion_eval_memory_access(
        //     local.clk,
        //     local.mat_opening_ptr.access.value.into() + local.m.into(),
        //     &local.p_at_x,
        //     memory_access,
        // );

        // // Constrain read for `p_at_z`
        // builder.recursion_eval_memory_access(
        //     local.clk,
        //     local.ps_at_z_ptr.access.value.into() + local.m.into(),
        //     &local.p_at_z,
        //     memory_access,
        // );

        // // Update alpha_pow_at_log_height.
        // // 1. Constrain old and new value against memory
        // builder.recursion_eval_memory_access(
        //     local.clk,
        //     local.alpha_pow_ptr.access.value.into() + local.log_height.access.value.into(),
        //     &local.alpha_pow_at_log_height,
        //     memory_access,
        // );

        // // 2. Constrain new_value = old_value * alpha.
        // let alpha = local.alpha.access.value.as_extension::<AB>();
        // let alpha_pow_at_log_height = local
        //     .alpha_pow_at_log_height
        //     .prev_value
        //     .as_extension::<AB>();
        // let new_alpha_pow_at_log_height = local
        //     .alpha_pow_at_log_height
        //     .access
        //     .value
        //     .as_extension::<AB>();

        // builder.assert_ext_eq(
        //     alpha_pow_at_log_height.clone() * alpha,
        //     new_alpha_pow_at_log_height,
        // );

        // // Update ro_at_log_height.
        // // 1. Constrain old and new value against memory.
        // builder.recursion_eval_memory_access(
        //     local.clk,
        //     local.ro_ptr.access.value.into() + local.log_height.access.value.into(),
        //     &local.ro_at_log_height,
        //     memory_access,
        // );

        // // 2. Constrain new_value = old_alpha_pow_at_log_height * quotient + old_value,
        // // where quotient = (p_at_x - p_at_z) / (x - z)
        // // <=> (new_value - old_value) * (z - x) = old_alpha_pow_at_log_height * (p_at_x - p_at_z)
        // let p_at_z = local.p_at_z.access.value.as_extension::<AB>();
        // let p_at_x = local.p_at_x.access.value.as_extension::<AB>();
        // let z = local.z.access.value.as_extension::<AB>();
        // let x = local.x.access.value.into();

        // let ro_at_log_height = local.ro_at_log_height.prev_value.as_extension::<AB>();
        // let new_ro_at_log_height = local.ro_at_log_height.access.value.as_extension::<AB>();
        // builder.assert_ext_eq(
        //     (new_ro_at_log_height - ro_at_log_height) * (BinomialExtension::from_base(x) - z),
        //     (p_at_x - p_at_z) * alpha_pow_at_log_height,
        // );
    }

    pub const fn do_receive_table<T: Copy>(local: &FriFoldPreprocessedCols<T>) -> T {
        local.is_last_iteration
    }

    pub const fn do_memory_access<T: Copy>(local: &FriFoldPreprocessedCols<T>) -> T {
        local.is_real
    }
}

impl<AB, const DEGREE: usize> Air<AB> for FriFoldChip<DEGREE>
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &FriFoldCols<AB::Var> = (*local).borrow();
        let next: &FriFoldCols<AB::Var> = (*next).borrow();
        let prepr = builder.preprocessed();
        let prepr_local = prepr.row_slice(0);
        let prepr_local: &FriFoldPreprocessedCols<AB::Var> = (*prepr_local).borrow();

        // Dummy constraints to normalize to DEGREE.
        let lhs = (0..DEGREE)
            .map(|_| prepr_local.is_real.into())
            .product::<AB::Expr>();
        let rhs = (0..DEGREE)
            .map(|_| prepr_local.is_real.into())
            .product::<AB::Expr>();
        builder.assert_eq(lhs, rhs);

        self.eval_fri_fold::<AB>(
            builder,
            local,
            next,
            prepr_local,
            Self::do_receive_table::<AB::Var>(prepr_local),
            Self::do_memory_access::<AB::Var>(prepr_local),
        );
    }
}
#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use p3_field::AbstractExtensionField;
    use p3_field::ExtensionField;
    use p3_util::reverse_bits_len;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use sp1_core::utils::run_test_machine;
    use sp1_core::utils::setup_logger;
    use sp1_core::utils::BabyBearPoseidon2;
    use sp1_recursion_core::air::Block;
    use sp1_recursion_core::stark::config::BabyBearPoseidon2Outer;
    use std::iter::once;
    use std::mem::size_of;

    use p3_baby_bear::BabyBear;
    use p3_baby_bear::DiffusionMatrixBabyBear;
    use p3_field::{AbstractField, PrimeField32};
    use p3_matrix::dense::RowMajorMatrix;
    use sp1_core::air::MachineAir;
    use sp1_core::stark::StarkGenericConfig;

    use crate::exp_reverse_bits::ExpReverseBitsLenChip;
    use crate::fri_fold::FriFoldChip;
    use crate::machine::RecursionAir;
    use crate::runtime::instruction as instr;
    use crate::runtime::ExecutionRecord;
    use crate::Address;
    use crate::ExpReverseBitsEvent;
    use crate::FriFoldBaseIo;
    use crate::FriFoldEvent;
    use crate::FriFoldExtSingleIo;
    use crate::FriFoldExtVecIo;
    use crate::Instruction;
    use crate::MemAccessKind;
    use crate::RecursionProgram;
    use crate::Runtime;

    #[test]
    fn prove_babybear_circuit_fri_fold() {
        setup_logger();
        type SC = BabyBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;
        type A = RecursionAir<F, 3>;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut random_felt = move || -> F { F::from_canonical_u32(rng.gen_range(0..1 << 16)) };
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut random_block =
            move || Block::from([F::from_canonical_u32(rng.gen_range(0..1 << 16)); 4]);
        let mut addr = 0;

        let num_ext_vecs: u32 = size_of::<FriFoldExtVecIo<u8>>() as u32;
        let num_singles: u32 =
            size_of::<FriFoldBaseIo<u8>>() as u32 + size_of::<FriFoldExtSingleIo<u8>>() as u32;

        let instructions = (2..3)
            .flat_map(|i: u32| {
                println!("i: {:?}", i);
                let alloc_size = i * (num_ext_vecs + 2) + num_singles;
                let mat_opening_a = (0..i).map(|x| x + addr).collect::<Vec<_>>();
                println!("mat_opening_a: {:?}", mat_opening_a);
                let ps_at_z_a = (0..i).map(|x| x + i + addr).collect::<Vec<_>>();
                println!("ps_at_z_a: {:?}", ps_at_z_a);

                let alpha_pow_input_a = (0..i).map(|x: u32| x + addr + 2 * i).collect::<Vec<_>>();
                println!("alpha_pow_input_a: {:?}", alpha_pow_input_a);
                let ro_input_a = (0..i).map(|x: u32| x + addr + 3 * i).collect::<Vec<_>>();
                println!("ro_input_a: {:?}", ro_input_a);

                let alpha_pow_output_a = (0..i).map(|x: u32| x + addr + 4 * i).collect::<Vec<_>>();
                println!("alpha_pow_output_a: {:?}", alpha_pow_output_a);
                let ro_output_a = (0..i).map(|x: u32| x + addr + 5 * i).collect::<Vec<_>>();
                println!("ro_output_a: {:?}", ro_output_a);

                let x_a = addr + 6 * i;
                println!("x_a: {:?}", x_a);
                let z_a = addr + 6 * i + 1;
                println!("z_a: {:?}", z_a);
                let alpha_a = addr + 6 * i + 2;
                println!("alpha_a: {:?}", alpha_a);

                addr += alloc_size;

                let x = random_felt();
                let z = random_block();
                let alpha = random_block();

                let alpha_pow_input = (0..i).map(|_| random_block()).collect::<Vec<_>>();
                let ro_input = (0..i).map(|_| random_block()).collect::<Vec<_>>();

                let ps_at_z = (0..i).map(|_| random_block()).collect::<Vec<_>>();
                let mat_opening = (0..i).map(|_| random_block()).collect::<Vec<_>>();

                let alpha_pow_output = (0..i)
                    .map(|i| alpha_pow_input[i as usize].ext::<EF>() * alpha.ext::<EF>())
                    .collect::<Vec<EF>>();
                let ro_output = (0..i)
                    .map(|i| {
                        let i = i as usize;
                        ro_input[i].ext::<EF>()
                            + alpha_pow_input[i].ext::<EF>()
                                * (-ps_at_z[i].ext::<EF>() + mat_opening[i].ext::<EF>())
                                / (-z.ext::<EF>() + x)
                    })
                    .collect::<Vec<EF>>();

                let mut instructions = vec![instr::mem_single(MemAccessKind::Write, 1, x_a, x)];

                instructions.push(instr::mem_block(MemAccessKind::Write, 1, z_a, z));

                instructions.push(instr::mem_block(MemAccessKind::Write, 1, alpha_a, alpha));

                (0..i).for_each(|j_32| {
                    let j = j_32 as usize;
                    instructions.push(instr::mem_block(
                        MemAccessKind::Write,
                        1,
                        mat_opening_a[j],
                        mat_opening[j],
                    ));
                    instructions.push(instr::mem_block(
                        MemAccessKind::Write,
                        1,
                        ps_at_z_a[j],
                        ps_at_z[j],
                    ));

                    instructions.push(instr::mem_block(
                        MemAccessKind::Write,
                        1,
                        alpha_pow_input_a[j],
                        alpha_pow_input[j],
                    ));
                    instructions.push(instr::mem_block(
                        MemAccessKind::Write,
                        1,
                        ro_input_a[j],
                        ro_input[j],
                    ));
                });

                instructions.push(instr::fri_fold(
                    z_a,
                    alpha_a,
                    x_a,
                    mat_opening_a.clone(),
                    ps_at_z_a.clone(),
                    alpha_pow_input_a.clone(),
                    ro_input_a.clone(),
                    alpha_pow_output_a.clone(),
                    ro_output_a.clone(),
                    vec![1; i as usize],
                    vec![1; i as usize],
                ));

                (0..i).for_each(|j| {
                    let j = j as usize;
                    instructions.push(instr::mem_block(
                        MemAccessKind::Read,
                        1,
                        alpha_pow_output_a[j],
                        Block::from(alpha_pow_output[j].as_base_slice()),
                    ));
                    instructions.push(instr::mem_block(
                        MemAccessKind::Read,
                        1,
                        ro_output_a[j],
                        Block::from(ro_output[j].as_base_slice()),
                    ));
                });

                instructions
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

    #[test]
    fn generate_fri_fold_circuit_trace() {
        type F = BabyBear;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut rng2 = StdRng::seed_from_u64(0xDEADBEEF);
        let mut random_felt = move || -> F { F::from_canonical_u32(rng.gen_range(0..1 << 16)) };
        let mut random_block = move || Block::from([random_felt(); 4]);

        let shard = ExecutionRecord {
            fri_fold_events: (0..17)
                .map(|_| FriFoldEvent {
                    base_single: FriFoldBaseIo {
                        x: F::from_canonical_u32(rng2.gen_range(0..1 << 16)),
                    },
                    ext_single: FriFoldExtSingleIo {
                        z: random_block(),
                        alpha: random_block(),
                    },
                    ext_vec: crate::FriFoldExtVecIo {
                        mat_opening: random_block(),
                        ps_at_z: random_block(),
                        alpha_pow_input: random_block(),
                        ro_input: random_block(),
                        alpha_pow_output: random_block(),
                        ro_output: random_block(),
                    },
                })
                .collect(),
            ..Default::default()
        };
        let chip = FriFoldChip::<3>::default();
        let trace: RowMajorMatrix<F> = chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }
}
