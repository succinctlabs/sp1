use core::mem::size_of;
use p3_air::Air;
use p3_air::AirBuilder;
use p3_air::BaseAir;
use p3_field::extension::BinomiallyExtendable;
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::BinomialExtension;
use sp1_core::air::ExtensionAirBuilder;
use sp1_core::air::MachineAir;
use sp1_core::runtime::MemoryAccessPosition;
use sp1_core::utils::indices_arr;
use sp1_core::utils::pad_rows;
use std::borrow::Borrow;
use std::borrow::BorrowMut;
use std::mem::transmute;
use tracing::instrument;

use super::columns::CpuCols;
use crate::air::{BinomialExtensionUtils, BlockBuilder, SP1RecursionAirBuilder};
use crate::cpu::CpuChip;
use crate::memory::MemoryCols;
use crate::runtime::ExecutionRecord;
use crate::runtime::RecursionProgram;
use crate::runtime::D;

pub const NUM_CPU_COLS: usize = size_of::<CpuCols<u8>>();

const fn make_col_map() -> CpuCols<usize> {
    let indices_arr = indices_arr::<NUM_CPU_COLS>();
    unsafe { transmute::<[usize; NUM_CPU_COLS], CpuCols<usize>>(indices_arr) }
}

pub(crate) const CPU_COL_MAP: CpuCols<usize> = make_col_map();

impl<F: PrimeField32 + BinomiallyExtendable<D>> MachineAir<F> for CpuChip<F> {
    type Record = ExecutionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "CPU".to_string()
    }

    #[instrument(name = "generate cpu trace", level = "debug", skip_all)]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut rows = input
            .cpu_events
            .iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_CPU_COLS];
                let cols: &mut CpuCols<F> = row.as_mut_slice().borrow_mut();

                cols.clk = event.clk;
                cols.pc = event.pc;
                cols.fp = event.fp;

                cols.selectors.populate(&event.instruction);
                cols.instruction.populate(&event.instruction);

                if let Some(record) = &event.a_record {
                    cols.a.populate(record);
                }
                if let Some(record) = &event.b_record {
                    cols.b.populate(record);
                } else {
                    *cols.b.value_mut() = event.instruction.op_b;
                }
                if let Some(record) = &event.c_record {
                    cols.c.populate(record);
                } else {
                    *cols.c.value_mut() = event.instruction.op_c;
                }
                if let Some(record) = &event.memory_record {
                    cols.memory.populate(record);
                    cols.memory_addr = record.addr;
                }

                cols.is_real = F::one();
                row
            })
            .collect::<Vec<_>>();

        pad_rows(&mut rows, || {
            let mut row = [F::zero(); NUM_CPU_COLS];
            let cols: &mut CpuCols<F> = row.as_mut_slice().borrow_mut();
            cols.selectors.is_noop = F::one();
            row
        });

        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_CPU_COLS);

        for i in input.cpu_events.len()..trace.height() {
            trace.values[i * NUM_CPU_COLS + CPU_COL_MAP.clk] =
                F::from_canonical_u32(4) * F::from_canonical_usize(i);
            trace.values[i * NUM_CPU_COLS + CPU_COL_MAP.instruction.imm_b] =
                F::from_canonical_u32(1);
            trace.values[i * NUM_CPU_COLS + CPU_COL_MAP.instruction.imm_c] =
                F::from_canonical_u32(1);
        }
        trace
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }
}

impl<F: Send + Sync> BaseAir<F> for CpuChip<F> {
    fn width(&self) -> usize {
        NUM_CPU_COLS
    }
}

impl<AB> Air<AB> for CpuChip<AB::F>
where
    AB: SP1RecursionAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &CpuCols<AB::Var> = (*local).borrow();
        let next: &CpuCols<AB::Var> = (*next).borrow();

        // Increment clk by 4 every cycle.
        builder
            .when_transition()
            .when(next.is_real)
            .assert_eq(local.clk.into() + AB::F::from_canonical_u32(4), next.clk);

        // TODO: Increment pc by 1 every cycle unless it is a branch instruction that is satisfied.
        // builder
        //     .when_transition()
        //     .when(next.is_real * (AB::Expr::one() - (local.is_beq + local.is_bne)))
        //     .assert_eq(local.pc + AB::F::one(), next.pc);
        // builder
        //     .when(local.beq + local.bne)
        //     .assert_eq(next.pc, local.pc + local.c.value()[0]);

        // TODO: we also need to constraint the transition of `fp`.

        self.eval_alu(builder, local);

        // Constraint all the memory access.

        // Constraint the case of immediates for the b and c operands.
        builder
            .when(local.instruction.imm_b)
            .assert_block_eq::<AB::Var, AB::Var>(*local.b.value(), local.instruction.op_b);
        builder
            .when(local.instruction.imm_c)
            .assert_block_eq::<AB::Var, AB::Var>(*local.c.value(), local.instruction.op_c);

        // Constraint the memory accesses.
        builder.recursion_eval_memory_access(
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::A as u32),
            local.fp.into() + local.instruction.op_a.into(),
            &local.a,
            local.is_real.into(),
        );

        builder.recursion_eval_memory_access(
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::B as u32),
            local.fp.into() + local.instruction.op_b[0].into(),
            &local.b,
            AB::Expr::one() - local.instruction.imm_b.into(),
        );

        builder.recursion_eval_memory_access(
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::C as u32),
            local.fp.into() + local.instruction.op_c[0].into(),
            &local.c,
            AB::Expr::one() - local.instruction.imm_c.into(),
        );

        // Evaluate the memory column.
        let load_memory = local.selectors.is_load + local.selectors.is_store;
        let index = local.c.value()[0];
        let ptr = local.b.value()[0];
        let _memory_addr = ptr + index * local.instruction.size_imm + local.instruction.offset_imm;
        // TODO: comment this back in to constraint the memory_addr column.
        // When load_memory is true, then we check that the local.memory_addr column equals the computed
        // memory_addr column from the other columns. Otherwise it is 0.
        // builder.assert_eq(memory_addr * load_memory.clone(), local.memory_addr);

        builder.recursion_eval_memory_access(
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::Memory as u32),
            local.memory_addr,
            &local.memory,
            load_memory,
        );

        // Constraints on the memory column depending on load or store.
        // We read from memory when it is a load.
        // builder
        //     .when(local.selectors.is_load)
        //     .assert_block_eq(local.memory.prev_value, *local.memory.value());
        // // When there is a store, we ensure that we are writing the value of the a operand to the memory.
        // builder
        //     .when(local.selectors.is_store)
        //     .assert_block_eq(local.a.value, local.memory.value);

        // Constraint the program.
        builder.send_program(
            local.pc,
            local.instruction.clone(),
            local.selectors.clone(),
            local.is_real,
        );

        // Constraint the syscalls.
        let send_syscall = local.selectors.is_poseidon + local.selectors.is_fri_fold;
        let operands = [
            local.clk.into(),
            local.a.value()[0].into(),
            local.b.value()[0].into(),
            local.c.value()[0] + local.instruction.offset_imm,
        ];
        builder.send_table(local.instruction.opcode, &operands, send_syscall);
    }
}

impl<F> CpuChip<F> {
    /// Eval all the ALU operations.
    fn eval_alu<AB>(&self, builder: &mut AB, local: &CpuCols<AB::Var>)
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        // Convert register values from Block<Var> to BinomialExtension<Expr>.
        let a_ext: BinomialExtension<AB::Expr> =
            BinomialExtensionUtils::from_block(local.a.value().map(|x| x.into()));
        let b_ext: BinomialExtension<AB::Expr> =
            BinomialExtensionUtils::from_block(local.b.value().map(|x| x.into()));
        let c_ext: BinomialExtension<AB::Expr> =
            BinomialExtensionUtils::from_block(local.c.value().map(|x| x.into()));

        // Flag to check if the instruction is a field operation
        let is_field_op = local.selectors.is_add
            + local.selectors.is_sub
            + local.selectors.is_mul
            + local.selectors.is_div;

        // Verify that the b and c registers are base elements for field operations.
        builder
            .when(is_field_op.clone())
            .assert_is_base_element(b_ext.clone());
        builder
            .when(is_field_op)
            .assert_is_base_element(c_ext.clone());

        // Verify the actual operation.
        builder
            .when(local.selectors.is_add + local.selectors.is_eadd)
            .assert_ext_eq(a_ext.clone(), b_ext.clone() + c_ext.clone());
        builder
            .when(local.selectors.is_sub + local.selectors.is_esub)
            .assert_ext_eq(a_ext.clone(), b_ext.clone() - c_ext.clone());
        builder
            .when(local.selectors.is_mul + local.selectors.is_emul)
            .assert_ext_eq(a_ext.clone(), b_ext.clone() * c_ext.clone());
        // For div operation, we assert that b == a * c (equivalent to a == b / c).
        builder
            .when(local.selectors.is_div + local.selectors.is_ediv)
            .assert_ext_eq(b_ext, a_ext * c_ext);
    }
}
