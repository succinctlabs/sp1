use crate::air::Word;
use crate::cpu::CpuChip;
use crate::runtime::Opcode;
use core::mem::size_of;
use p3_air::Air;
use p3_air::AirBuilder;
use p3_air::BaseAir;
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_matrix::MatrixRowSlices;
use sp1_core::air::AirInteraction;
use sp1_core::air::Extension;
use sp1_core::lookup::InteractionKind;
use sp1_core::operations::IsZeroOperation;
use sp1_core::stark::SP1AirBuilder;
use sp1_core::utils::indices_arr;
use sp1_core::{air::MachineAir, utils::pad_to_power_of_two};
use std::borrow::Borrow;
use std::borrow::BorrowMut;
use std::mem::transmute;

use super::columns::CpuCols;
use crate::runtime::ExecutionRecord;

pub const NUM_CPU_COLS: usize = size_of::<CpuCols<u8>>();

const fn make_col_map() -> CpuCols<usize> {
    let indices_arr = indices_arr::<NUM_CPU_COLS>();
    unsafe { transmute::<[usize; NUM_CPU_COLS], CpuCols<usize>>(indices_arr) }
}

pub(crate) const CPU_COL_MAP: CpuCols<usize> = make_col_map();

impl<F: PrimeField32> MachineAir<F> for CpuChip<F> {
    type Record = ExecutionRecord<F>;

    fn name(&self) -> String {
        "CPU".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let rows = input
            .cpu_events
            .iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_CPU_COLS];
                let cols: &mut CpuCols<F> = row.as_mut_slice().borrow_mut();
                cols.clk = event.clk;
                cols.pc = event.pc;
                cols.fp = event.fp;

                cols.instruction.opcode = F::from_canonical_u32(event.instruction.opcode as u32);
                cols.instruction.op_a = event.instruction.op_a;
                cols.instruction.op_b = event.instruction.op_b;
                cols.instruction.op_c = event.instruction.op_c;
                cols.instruction.imm_b = F::from_canonical_u32(event.instruction.imm_b as u32);
                cols.instruction.imm_c = F::from_canonical_u32(event.instruction.imm_c as u32);
                match event.instruction.opcode {
                    Opcode::ADD => {
                        cols.is_add = F::one();
                    }
                    Opcode::SUB => {
                        cols.is_sub = F::one();
                    }
                    Opcode::MUL => {
                        cols.is_mul = F::one();
                    }
                    _ => {}
                };

                if let Some(record) = &event.a_record {
                    cols.a.populate(record);
                }
                if let Some(record) = &event.b_record {
                    cols.b.populate(record);
                } else {
                    cols.b.value = Word::from(event.instruction.op_b);
                }
                if let Some(record) = &event.c_record {
                    cols.c.populate(record);
                } else {
                    cols.c.value = Word::from(event.instruction.op_c);
                }

                cols.add_scratch = cols.b.value.0[0] + cols.c.value.0[0];
                cols.sub_scratch = cols.b.value.0[0] - cols.c.value.0[0];
                cols.mul_scratch = cols.b.value.0[0] * cols.c.value.0[0];
                cols.add_ext_scratch =
                    Word((Extension(cols.b.value.0) + Extension(cols.c.value.0)).0);
                cols.sub_ext_scratch =
                    Word((Extension(cols.b.value.0) - Extension(cols.c.value.0)).0);
                cols.mul_ext_scratch =
                    Word((Extension(cols.b.value.0) * Extension(cols.c.value.0)).0);

                cols.a_eq_b
                    .populate((cols.a.value.0[0] - cols.b.value.0[0]).as_canonical_u32());

                cols.is_real = F::one();
                row
            })
            .collect::<Vec<_>>();

        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_CPU_COLS);

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_CPU_COLS, F>(&mut trace.values);

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
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &CpuCols<AB::Var> = main.row_slice(0).borrow();
        let next: &CpuCols<AB::Var> = main.row_slice(1).borrow();

        // Increment clk by 4 every cycle..
        builder
            .when_transition()
            .when(local.is_real)
            .assert_eq(local.clk + AB::F::from_canonical_u32(4), next.clk);

        // Compute ALU.
        builder.assert_eq(local.b.value.0[0] + local.c.value.0[0], local.add_scratch);
        builder.assert_eq(local.b.value.0[0] - local.c.value.0[0], local.sub_scratch);
        builder.assert_eq(local.b.value.0[0] * local.c.value.0[0], local.mul_scratch);

        // Compute extension ALU.
        builder.assert_ext_eq(
            local.b.value.extension::<AB>() + local.c.value.extension::<AB>(),
            local.add_ext_scratch.extension::<AB>(),
        );
        builder.assert_ext_eq(
            local.b.value.extension::<AB>() - local.c.value.extension::<AB>(),
            local.sub_ext_scratch.extension::<AB>(),
        );
        builder.assert_ext_eq(
            local.b.value.extension::<AB>() * local.c.value.extension::<AB>(),
            local.mul_ext_scratch.extension::<AB>(),
        );

        // Connect ALU to CPU.
        builder
            .when(local.is_add)
            .assert_eq(local.a.value.0[0], local.add_scratch);
        builder
            .when(local.is_add)
            .assert_eq(local.a.value.0[1], AB::F::zero());
        builder
            .when(local.is_add)
            .assert_eq(local.a.value.0[2], AB::F::zero());
        builder
            .when(local.is_add)
            .assert_eq(local.a.value.0[3], AB::F::zero());

        builder
            .when(local.is_sub)
            .assert_eq(local.a.value.0[0], local.sub_scratch);
        builder
            .when(local.is_sub)
            .assert_eq(local.a.value.0[1], AB::F::zero());
        builder
            .when(local.is_sub)
            .assert_eq(local.a.value.0[2], AB::F::zero());
        builder
            .when(local.is_sub)
            .assert_eq(local.a.value.0[3], AB::F::zero());

        builder
            .when(local.is_mul)
            .assert_eq(local.a.value.0[0], local.mul_scratch);
        builder
            .when(local.is_mul)
            .assert_eq(local.a.value.0[1], AB::F::zero());
        builder
            .when(local.is_mul)
            .assert_eq(local.a.value.0[2], AB::F::zero());
        builder
            .when(local.is_mul)
            .assert_eq(local.a.value.0[3], AB::F::zero());

        // Compute if a == b.
        IsZeroOperation::<AB::F>::eval::<AB>(
            builder,
            local.a.value.0[0] - local.b.value.0[0],
            local.a_eq_b,
            local.is_real.into(),
        );

        // Receive C.
        builder.receive(AirInteraction::new(
            vec![
                local.c.addr.into(),
                local.c.prev_timestamp.into(),
                local.c.prev_value.0[0].into(),
                local.c.prev_value.0[1].into(),
                local.c.prev_value.0[2].into(),
                local.c.prev_value.0[3].into(),
            ],
            AB::Expr::one() - local.instruction.imm_c.into(),
            InteractionKind::Memory,
        ));
        builder.send(AirInteraction::new(
            vec![
                local.c.addr.into(),
                local.c.timestamp.into(),
                local.c.value.0[0].into(),
                local.c.value.0[1].into(),
                local.c.value.0[2].into(),
                local.c.value.0[3].into(),
            ],
            AB::Expr::one() - local.instruction.imm_c.into(),
            InteractionKind::Memory,
        ));

        // Receive B.
        builder.receive(AirInteraction::new(
            vec![
                local.b.addr.into(),
                local.b.prev_timestamp.into(),
                local.b.prev_value.0[0].into(),
                local.b.prev_value.0[1].into(),
                local.b.prev_value.0[2].into(),
                local.b.prev_value.0[3].into(),
            ],
            AB::Expr::one() - local.instruction.imm_b.into(),
            InteractionKind::Memory,
        ));
        builder.send(AirInteraction::new(
            vec![
                local.b.addr.into(),
                local.b.timestamp.into(),
                local.b.value.0[0].into(),
                local.b.value.0[1].into(),
                local.b.value.0[2].into(),
                local.b.value.0[3].into(),
            ],
            AB::Expr::one() - local.instruction.imm_b.into(),
            InteractionKind::Memory,
        ));

        // Receive A.
        builder.receive(AirInteraction::new(
            vec![
                local.a.addr.into(),
                local.a.prev_timestamp.into(),
                local.a.prev_value.0[0].into(),
                local.a.prev_value.0[1].into(),
                local.a.prev_value.0[2].into(),
                local.a.prev_value.0[3].into(),
            ],
            local.is_real.into(),
            InteractionKind::Memory,
        ));
        builder.send(AirInteraction::new(
            vec![
                local.a.addr.into(),
                local.a.timestamp.into(),
                local.a.value.0[0].into(),
                local.a.value.0[1].into(),
                local.a.value.0[2].into(),
                local.a.value.0[3].into(),
            ],
            local.is_real.into(),
            InteractionKind::Memory,
        ));

        builder.send(AirInteraction::new(
            vec![
                local.instruction.opcode.into(),
                local.instruction.op_a.into(),
                local.instruction.op_b.into(),
                local.instruction.op_c.into(),
                local.instruction.imm_b.into(),
                local.instruction.imm_c.into(),
            ],
            local.is_real.into(),
            InteractionKind::Program,
        ));
    }
}
