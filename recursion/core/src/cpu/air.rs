use core::mem::size_of;
use p3_air::Air;
use p3_air::AirBuilder;
use p3_air::BaseAir;
use p3_field::extension::BinomiallyExtendable;
use p3_field::AbstractField;
use p3_field::Field;
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
use crate::air::BinomialExtensionUtils;
use crate::air::BlockBuilder;
use crate::air::IsExtZeroOperation;
use crate::air::SP1RecursionAirBuilder;
use crate::cpu::CpuChip;
use crate::memory::MemoryCols;
use crate::runtime::ExecutionRecord;
use crate::runtime::Opcode;
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

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // There are no dependencies, since we do it all in the runtime. This is just a placeholder.
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

                // Populate the instruction related columns.
                cols.selectors.populate(&event.instruction);
                cols.instruction.populate(&event.instruction);

                // Populate the register columns.
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

                // Populate the branch columns.
                if matches!(
                    event.instruction.opcode,
                    Opcode::BEQ | Opcode::BNE | Opcode::BNEINC
                ) {
                    let branch_cols = cols.opcode_specific.branch_mut();
                    let a_ext: BinomialExtension<F> =
                        BinomialExtensionUtils::from_block(*cols.a.prev_value());
                    let b_ext: BinomialExtension<F> =
                        BinomialExtensionUtils::from_block(*cols.b.prev_value());

                    let (comparison_diff, do_branch) = match event.instruction.opcode {
                        Opcode::BEQ => (a_ext - b_ext, a_ext == b_ext),
                        Opcode::BNE => (a_ext - b_ext, a_ext != b_ext),
                        Opcode::BNEINC => {
                            let base_element_one = BinomialExtension::<F>::from_base(F::one());
                            (
                                a_ext + base_element_one - b_ext,
                                a_ext + base_element_one != b_ext,
                            )
                        }
                        _ => unreachable!(),
                    };

                    branch_cols
                        .comparison_diff
                        .populate((comparison_diff).as_block());
                    branch_cols.comparison_diff_val = comparison_diff;
                    branch_cols.do_branch = F::from_bool(do_branch);
                    branch_cols.next_pc = if do_branch {
                        event.pc + event.instruction.op_c[0]
                    } else {
                        event.pc + F::one()
                    };
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
        let _next: &CpuCols<AB::Var> = (*next).borrow();
        let zero = AB::Expr::zero();
        let one = AB::Expr::one();

        self.eval_operands(builder, local);

        self.eval_memory(builder, local);

        self.eval_alu(builder, local);

        // Expression for the expected next_pc.
        let mut next_pc = zero;

        self.eval_branch(builder, local, &mut next_pc);

        // builder.when_first_row().assert_zero(next_pc.clone());

        // TODO: in eval_jump, we need to constraint the transition of `fp`.
        // self.eval_jump(builder, local, &mut next_pc);

        // If the instruction is not a jump or branch instruction, then next pc = pc + 1.
        let not_branch_or_jump = one.clone()
            - self.is_branch_instruction::<AB>(local)
            - self.is_jump_instruction::<AB>(local);
        next_pc += not_branch_or_jump.clone() * (local.pc + one);

        // Verify next row's pc is correct.
        // TODO: Uncomment once eval_jump is implemented.
        // builder
        //     .when_transition()
        //     .when(next.is_real)
        //     .assert_eq(next_pc, next.pc);

        // // Increment clk by 4 every cycle.
        // builder
        //     .when_transition()
        //     .when(next.is_real)
        //     .assert_eq(local.clk.into() + AB::F::from_canonical_u32(4), next.clk);

        // Constraint the program.
        if std::env::var("MAX_RECURSION_PROGRAM_SIZE").is_err() {
            builder.send_program(local.pc, local.instruction, local.selectors, local.is_real);
        }

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

impl<F: Field> CpuChip<F> {
    /// Eval the operands.
    fn eval_operands<AB>(&self, builder: &mut AB, local: &CpuCols<AB::Var>)
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        // Constraint the case of immediates for the b and c operands.
        builder
            .when(local.instruction.imm_b)
            .assert_block_eq::<AB::Var, AB::Var>(*local.b.value(), local.instruction.op_b);
        builder
            .when(local.instruction.imm_c)
            .assert_block_eq::<AB::Var, AB::Var>(*local.c.value(), local.instruction.op_c);

        // Constraint the operand accesses.
        let a_addr = local.fp.into() + local.instruction.op_a.into();
        builder.recursion_eval_memory_access(
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::A as u32),
            a_addr,
            &local.a,
            local.is_real.into(),
        );
        // If the instruction only reads from operand A, then verify that previous and current values are equal.
        let is_op_a_read_only = self.is_op_a_read_only_instruction::<AB>(local);
        builder
            .when(is_op_a_read_only)
            .assert_block_eq(*local.a.prev_value(), *local.a.value());

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
    }

    // Eval the memory instructions.
    fn eval_memory<AB>(&self, builder: &mut AB, local: &CpuCols<AB::Var>)
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        // Constraint all the memory access.

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
    }

    /// Eval the ALU operations.
    fn eval_alu<AB>(&self, builder: &mut AB, local: &CpuCols<AB::Var>)
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        // Convert operand values from Block<Var> to BinomialExtension<Expr>.
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
        // TODO:  Figure out why this fails in the groth16 proof.
        // builder
        //     .when(local.selectors.is_mul + local.selectors.is_emul)
        //     .assert_ext_eq(a_ext.clone(), b_ext.clone() * c_ext.clone());
        // // For div operation, we assert that b == a * c (equivalent to a == b / c).
        builder
            .when(local.selectors.is_div + local.selectors.is_ediv)
            .assert_ext_eq(b_ext, a_ext * c_ext);
    }

    /// Eval the branch operations.
    fn eval_branch<AB>(&self, builder: &mut AB, local: &CpuCols<AB::Var>, next_pc: &mut AB::Expr)
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        let branch_cols = local.opcode_specific.branch();
        let is_branch_instruction = self.is_branch_instruction::<AB>(local);
        let one = AB::Expr::one();
        let base_element_one = BinomialExtension::<AB::Expr>::from_base(one.clone());

        // If the instruction is a BNEINC, verify that the a value is incremented by one.
        builder
            .when(local.is_real)
            .when(local.selectors.is_bneinc)
            .assert_eq(local.a.value()[0], local.a.prev_value()[0] + one.clone());

        // Convert operand values from Block<Var> to BinomialExtension<Expr>.  Note that it gets the
        // previous value of the `a` and `b` operands, since BNENIC will modify `a`.
        let a_ext: BinomialExtension<AB::Expr> =
            BinomialExtensionUtils::from_block(local.a.prev_value().map(|x| x.into()));
        let b_ext: BinomialExtension<AB::Expr> =
            BinomialExtensionUtils::from_block(local.b.prev_value().map(|x| x.into()));

        let mut comparison_diff = a_ext - b_ext;

        // For the BNEINC operation, add one to the comparison_diff.
        comparison_diff = builder.if_else_ext(
            local.selectors.is_bneinc,
            comparison_diff.clone() + base_element_one,
            comparison_diff.clone(),
        );

        builder.when(is_branch_instruction.clone()).assert_ext_eq(
            BinomialExtension::from(branch_cols.comparison_diff_val),
            comparison_diff,
        );

        // Verify the comparison_diff flag value.
        IsExtZeroOperation::<AB::F>::eval(
            builder,
            BinomialExtension::from(branch_cols.comparison_diff_val),
            branch_cols.comparison_diff,
            is_branch_instruction.clone(),
        );

        // Verify branch_col.do_branch col.
        let mut do_branch = local.selectors.is_beq.clone() * branch_cols.comparison_diff.result;
        do_branch +=
            local.selectors.is_bne.clone() * (one.clone() - branch_cols.comparison_diff.result);
        do_branch +=
            local.selectors.is_bneinc.clone() * (one.clone() - branch_cols.comparison_diff.result);
        builder
            .when(is_branch_instruction.clone())
            .assert_eq(branch_cols.do_branch, do_branch);

        // Verify branch_col.next_pc col.
        let pc_offset = local.c.value().0[0];
        let expected_next_pc =
            builder.if_else(branch_cols.do_branch, local.pc + pc_offset, local.pc + one);
        builder
            .when(is_branch_instruction.clone())
            .assert_eq(branch_cols.next_pc, expected_next_pc);

        *next_pc = is_branch_instruction * branch_cols.next_pc;
    }

    fn is_branch_instruction<AB>(&self, local: &CpuCols<AB::Var>) -> AB::Expr
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        local.selectors.is_beq + local.selectors.is_bne + local.selectors.is_bneinc
    }

    fn is_jump_instruction<AB>(&self, local: &CpuCols<AB::Var>) -> AB::Expr
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        local.selectors.is_jal + local.selectors.is_jalr
    }

    fn is_op_a_read_only_instruction<AB>(&self, local: &CpuCols<AB::Var>) -> AB::Expr
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        local.selectors.is_beq
            + local.selectors.is_bne
            + local.selectors.is_fri_fold
            + local.selectors.is_poseidon
            + local.selectors.is_store
    }
}
