use std::borrow::BorrowMut;

use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use rayon::iter::{ParallelBridge, ParallelIterator};
use sp1_core_executor::{events::BranchEvent, ExecutionRecord, Opcode, Program};
use sp1_stark::air::MachineAir;

use crate::utils::{next_power_of_two, zeroed_f_vec};

use super::{BranchChip, BranchColumns, NUM_BRANCH_COLS};

impl<F: PrimeField32> MachineAir<F> for BranchChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Branch".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let chunk_size = std::cmp::max((input.branch_events.len()) / num_cpus::get(), 1);
        let nb_rows = input.branch_events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_BRANCH_COLS);

        values.chunks_mut(chunk_size * NUM_BRANCH_COLS).enumerate().par_bridge().for_each(
            |(i, rows)| {
                rows.chunks_mut(NUM_BRANCH_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut BranchColumns<F> = row.borrow_mut();

                    if idx < input.branch_events.len() {
                        let event = &input.branch_events[idx];
                        self.event_to_row(event, cols, &input.nonce_lookup);
                    }
                });
            },
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_BRANCH_COLS)
    }

    /// Generate dependencies is a no-op for branch instructions.
    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {}

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.branch_events.is_empty()
        }
    }
}

impl BranchChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &BranchEvent,
        cols: &mut BranchColumns<F>,
        nonce_lookup: &[u32],
    ) {
        cols.is_beq = F::from_bool(matches!(event.opcode, Opcode::BEQ));
        cols.is_bne = F::from_bool(matches!(event.opcode, Opcode::BNE));
        cols.is_blt = F::from_bool(matches!(event.opcode, Opcode::BLT));
        cols.is_bge = F::from_bool(matches!(event.opcode, Opcode::BGE));
        cols.is_bltu = F::from_bool(matches!(event.opcode, Opcode::BLTU));
        cols.is_bgeu = F::from_bool(matches!(event.opcode, Opcode::BGEU));

        cols.op_a_value = event.a.into();
        cols.op_b_value = event.b.into();
        cols.op_c_value = event.c.into();

        let a_eq_b = event.a == event.b;

        let use_signed_comparison = matches!(event.opcode, Opcode::BLT | Opcode::BGE);

        let a_lt_b = if use_signed_comparison {
            (event.a as i32) < (event.b as i32)
        } else {
            event.a < event.b
        };
        let a_gt_b = if use_signed_comparison {
            (event.a as i32) > (event.b as i32)
        } else {
            event.a > event.b
        };

        cols.a_lt_b_nonce = F::from_canonical_u32(
            nonce_lookup.get(event.branch_lt_lookup_id.0 as usize).copied().unwrap_or_default(),
        );

        cols.a_gt_b_nonce = F::from_canonical_u32(
            nonce_lookup.get(event.branch_gt_lookup_id.0 as usize).copied().unwrap_or_default(),
        );

        cols.a_eq_b = F::from_bool(a_eq_b);
        cols.a_lt_b = F::from_bool(a_lt_b);
        cols.a_gt_b = F::from_bool(a_gt_b);

        let branching = match event.opcode {
            Opcode::BEQ => a_eq_b,
            Opcode::BNE => !a_eq_b,
            Opcode::BLT | Opcode::BLTU => a_lt_b,
            Opcode::BGE | Opcode::BGEU => a_eq_b || a_gt_b,
            _ => unreachable!(),
        };

        cols.pc = event.pc.into();
        cols.next_pc = event.next_pc.into();
        cols.pc_range_checker.populate(event.pc);
        cols.next_pc_range_checker.populate(event.next_pc);

        if branching {
            cols.is_branching = F::one();
            cols.next_pc_nonce = F::from_canonical_u32(
                nonce_lookup
                    .get(event.branch_add_lookup_id.0 as usize)
                    .copied()
                    .unwrap_or_default(),
            );
        } else {
            cols.not_branching = F::one();
        }
    }
}
