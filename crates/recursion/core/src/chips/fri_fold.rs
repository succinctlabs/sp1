#![allow(clippy::needless_range_loop)]

use core::borrow::Borrow;
use itertools::Itertools;
use sp1_core_machine::utils::pad_rows_fixed;
use sp1_stark::air::{BinomialExtension, MachineAir};
use std::borrow::BorrowMut;
use tracing::instrument;

use p3_air::{Air, AirBuilder, BaseAir, PairBuilder};
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_stark::air::{BaseAirBuilder, ExtensionAirBuilder};

use sp1_derive::AlignedBorrow;

use crate::{
    air::Block,
    builder::SP1RecursionAirBuilder,
    runtime::{Instruction, RecursionProgram},
    ExecutionRecord, FriFoldInstr,
};

use super::mem::MemoryAccessCols;

pub const NUM_FRI_FOLD_COLS: usize = core::mem::size_of::<FriFoldCols<u8>>();
pub const NUM_FRI_FOLD_PREPROCESSED_COLS: usize =
    core::mem::size_of::<FriFoldPreprocessedCols<u8>>();

pub struct FriFoldChip<const DEGREE: usize> {
    pub fixed_log2_rows: Option<usize>,
    pub pad: bool,
}

impl<const DEGREE: usize> Default for FriFoldChip<DEGREE> {
    fn default() -> Self {
        Self { fixed_log2_rows: None, pad: true }
    }
}

/// The preprocessed columns for a FRI fold invocation.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct FriFoldPreprocessedCols<T: Copy> {
    pub is_first: T,

    // Memory accesses for the single fields.
    pub z_mem: MemoryAccessCols<T>,
    pub alpha_mem: MemoryAccessCols<T>,
    pub x_mem: MemoryAccessCols<T>,

    // Memory accesses for the vector field inputs.
    pub alpha_pow_input_mem: MemoryAccessCols<T>,
    pub ro_input_mem: MemoryAccessCols<T>,
    pub p_at_x_mem: MemoryAccessCols<T>,
    pub p_at_z_mem: MemoryAccessCols<T>,

    // Memory accesses for the vector field outputs.
    pub ro_output_mem: MemoryAccessCols<T>,
    pub alpha_pow_output_mem: MemoryAccessCols<T>,

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
                } = instruction.as_ref();
                let mut row_add =
                    vec![[F::zero(); NUM_FRI_FOLD_PREPROCESSED_COLS]; ext_vec_addrs.ps_at_z.len()];

                row_add.iter_mut().enumerate().for_each(|(i, row)| {
                    let row: &mut FriFoldPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                    row.is_first = F::from_bool(i == 0);

                    // Only need to read z, x, and alpha on the first iteration, hence the
                    // multiplicities are i==0.
                    row.z_mem =
                        MemoryAccessCols { addr: ext_single_addrs.z, mult: -F::from_bool(i == 0) };
                    row.x_mem =
                        MemoryAccessCols { addr: base_single_addrs.x, mult: -F::from_bool(i == 0) };
                    row.alpha_mem = MemoryAccessCols {
                        addr: ext_single_addrs.alpha,
                        mult: -F::from_bool(i == 0),
                    };

                    // Read the memory for the input vectors.
                    row.alpha_pow_input_mem = MemoryAccessCols {
                        addr: ext_vec_addrs.alpha_pow_input[i],
                        mult: F::neg_one(),
                    };
                    row.ro_input_mem =
                        MemoryAccessCols { addr: ext_vec_addrs.ro_input[i], mult: F::neg_one() };
                    row.p_at_z_mem =
                        MemoryAccessCols { addr: ext_vec_addrs.ps_at_z[i], mult: F::neg_one() };
                    row.p_at_x_mem =
                        MemoryAccessCols { addr: ext_vec_addrs.mat_opening[i], mult: F::neg_one() };

                    // Write the memory for the output vectors.
                    row.alpha_pow_output_mem = MemoryAccessCols {
                        addr: ext_vec_addrs.alpha_pow_output[i],
                        mult: alpha_pow_mults[i],
                    };
                    row.ro_output_mem =
                        MemoryAccessCols { addr: ext_vec_addrs.ro_output[i], mult: ro_mults[i] };

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
            pad_rows_fixed(&mut rows, || [F::zero(); NUM_FRI_FOLD_COLS], self.fixed_log2_rows);
        }

        // Convert the trace to a row major matrix.
        let trace = RowMajorMatrix::new(rows.into_iter().flatten().collect(), NUM_FRI_FOLD_COLS);

        #[cfg(debug_assertions)]
        println!("fri fold trace dims is width: {:?}, height: {:?}", trace.width(), trace.height());

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
        next_prepr: &FriFoldPreprocessedCols<AB::Var>,
    ) {
        // Constrain mem read for x.  Read at the first fri fold row.
        builder.send_single(local_prepr.x_mem.addr, local.x, local_prepr.x_mem.mult);

        // Ensure that the x value is the same for all rows within a fri fold invocation.
        builder
            .when_transition()
            .when(next_prepr.is_real)
            .when_not(next_prepr.is_first)
            .assert_eq(local.x, next.x);

        // Constrain mem read for z.  Read at the first fri fold row.
        builder.send_block(local_prepr.z_mem.addr, local.z, local_prepr.z_mem.mult);

        // Ensure that the z value is the same for all rows within a fri fold invocation.
        builder
            .when_transition()
            .when(next_prepr.is_real)
            .when_not(next_prepr.is_first)
            .assert_ext_eq(local.z.as_extension::<AB>(), next.z.as_extension::<AB>());

        // Constrain mem read for alpha.  Read at the first fri fold row.
        builder.send_block(local_prepr.alpha_mem.addr, local.alpha, local_prepr.alpha_mem.mult);

        // Ensure that the alpha value is the same for all rows within a fri fold invocation.
        builder
            .when_transition()
            .when(next_prepr.is_real)
            .when_not(next_prepr.is_first)
            .assert_ext_eq(local.alpha.as_extension::<AB>(), next.alpha.as_extension::<AB>());

        // Constrain read for alpha_pow_input.
        builder.send_block(
            local_prepr.alpha_pow_input_mem.addr,
            local.alpha_pow_input,
            local_prepr.alpha_pow_input_mem.mult,
        );

        // Constrain read for ro_input.
        builder.send_block(
            local_prepr.ro_input_mem.addr,
            local.ro_input,
            local_prepr.ro_input_mem.mult,
        );

        // Constrain read for p_at_z.
        builder.send_block(local_prepr.p_at_z_mem.addr, local.p_at_z, local_prepr.p_at_z_mem.mult);

        // Constrain read for p_at_x.
        builder.send_block(local_prepr.p_at_x_mem.addr, local.p_at_x, local_prepr.p_at_x_mem.mult);

        // Constrain write for alpha_pow_output.
        builder.send_block(
            local_prepr.alpha_pow_output_mem.addr,
            local.alpha_pow_output,
            local_prepr.alpha_pow_output_mem.mult,
        );

        // Constrain write for ro_output.
        builder.send_block(
            local_prepr.ro_output_mem.addr,
            local.ro_output,
            local_prepr.ro_output_mem.mult,
        );

        // 1. Constrain new_value = old_value * alpha.
        let alpha = local.alpha.as_extension::<AB>();
        let old_alpha_pow = local.alpha_pow_input.as_extension::<AB>();
        let new_alpha_pow = local.alpha_pow_output.as_extension::<AB>();
        builder.assert_ext_eq(old_alpha_pow.clone() * alpha, new_alpha_pow.clone());

        // 2. Constrain new_value = old_alpha_pow * quotient + old_ro,
        // where quotient = (p_at_x - p_at_z) / (x - z)
        // <=> (new_ro - old_ro) * (z - x) = old_alpha_pow * (p_at_x - p_at_z)
        let p_at_z = local.p_at_z.as_extension::<AB>();
        let p_at_x = local.p_at_x.as_extension::<AB>();
        let z = local.z.as_extension::<AB>();
        let x = local.x.into();
        let old_ro = local.ro_input.as_extension::<AB>();
        let new_ro = local.ro_output.as_extension::<AB>();
        builder.assert_ext_eq(
            (new_ro.clone() - old_ro) * (BinomialExtension::from_base(x) - z),
            (p_at_x - p_at_z) * old_alpha_pow,
        );
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
        let (prepr_local, prepr_next) = (prepr.row_slice(0), prepr.row_slice(1));
        let prepr_local: &FriFoldPreprocessedCols<AB::Var> = (*prepr_local).borrow();
        let prepr_next: &FriFoldPreprocessedCols<AB::Var> = (*prepr_next).borrow();

        // Dummy constraints to normalize to DEGREE.
        let lhs = (0..DEGREE).map(|_| prepr_local.is_real.into()).product::<AB::Expr>();
        let rhs = (0..DEGREE).map(|_| prepr_local.is_real.into()).product::<AB::Expr>();
        builder.assert_eq(lhs, rhs);

        self.eval_fri_fold::<AB>(builder, local, next, prepr_local, prepr_next);
    }
}

#[cfg(test)]
mod tests {
    use p3_field::AbstractExtensionField;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sp1_core_machine::utils::setup_logger;
    use sp1_stark::{air::MachineAir, StarkGenericConfig};
    use std::mem::size_of;

    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;

    use crate::{
        air::Block,
        chips::fri_fold::FriFoldChip,
        machine::tests::run_recursion_test_machines,
        runtime::{instruction as instr, ExecutionRecord},
        stark::BabyBearPoseidon2Outer,
        FriFoldBaseIo, FriFoldEvent, FriFoldExtSingleIo, FriFoldExtVecIo, Instruction,
        MemAccessKind, RecursionProgram,
    };

    #[test]
    fn prove_babybear_circuit_fri_fold() {
        setup_logger();
        type SC = BabyBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut random_felt = move || -> F { F::from_canonical_u32(rng.gen_range(0..1 << 16)) };
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut random_block =
            move || Block::from([F::from_canonical_u32(rng.gen_range(0..1 << 16)); 4]);
        let mut addr = 0;

        let num_ext_vecs: u32 = size_of::<FriFoldExtVecIo<u8>>() as u32;
        let num_singles: u32 =
            size_of::<FriFoldBaseIo<u8>>() as u32 + size_of::<FriFoldExtSingleIo<u8>>() as u32;

        let instructions = (2..17)
            .flat_map(|i: u32| {
                let alloc_size = i * (num_ext_vecs + 2) + num_singles;

                // Allocate the memory for a FRI fold instruction. Here, i is the lengths
                // of the vectors for the vector fields of the instruction.
                let mat_opening_a = (0..i).map(|x| x + addr).collect::<Vec<_>>();
                let ps_at_z_a = (0..i).map(|x| x + i + addr).collect::<Vec<_>>();

                let alpha_pow_input_a = (0..i).map(|x: u32| x + addr + 2 * i).collect::<Vec<_>>();
                let ro_input_a = (0..i).map(|x: u32| x + addr + 3 * i).collect::<Vec<_>>();

                let alpha_pow_output_a = (0..i).map(|x: u32| x + addr + 4 * i).collect::<Vec<_>>();
                let ro_output_a = (0..i).map(|x: u32| x + addr + 5 * i).collect::<Vec<_>>();

                let x_a = addr + 6 * i;
                let z_a = addr + 6 * i + 1;
                let alpha_a = addr + 6 * i + 2;

                addr += alloc_size;

                // Generate random values for the inputs.
                let x = random_felt();
                let z = random_block();
                let alpha = random_block();

                let alpha_pow_input = (0..i).map(|_| random_block()).collect::<Vec<_>>();
                let ro_input = (0..i).map(|_| random_block()).collect::<Vec<_>>();

                let ps_at_z = (0..i).map(|_| random_block()).collect::<Vec<_>>();
                let mat_opening = (0..i).map(|_| random_block()).collect::<Vec<_>>();

                // Compute the outputs from the inputs.
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

                // Write the inputs to memory.
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

                // Generate the FRI fold instruction.
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

                // Read all the outputs.
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

        let program = RecursionProgram { instructions, ..Default::default() };

        run_recursion_test_machines(program);
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
                    ext_single: FriFoldExtSingleIo { z: random_block(), alpha: random_block() },
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
