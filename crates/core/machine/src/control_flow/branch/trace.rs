use std::{borrow::BorrowMut, mem::MaybeUninit};

use hashbrown::HashMap;
use itertools::Itertools;
use rayon::iter::{ParallelBridge, ParallelIterator};
use slop_air::BaseAir;
use slop_algebra::PrimeField32;
use sp1_core_executor::{
    events::{BranchEvent, ByteLookupEvent, ByteRecord},
    ExecutionRecord, Opcode, Program,
};
use sp1_hypercube::air::MachineAir;

use crate::{utils::next_multiple_of_32, TrustMode, UserMode};

use super::{BranchChip, BranchColumns};

impl<F: PrimeField32, M: TrustMode> MachineAir<F> for BranchChip<M> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        if M::IS_TRUSTED {
            "Branch"
        } else {
            "BranchUser"
        }
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return Some(0);
        }
        let nb_rows =
            next_multiple_of_32(input.branch_events.len(), input.fixed_log2_rows::<F, _>(self));
        Some(nb_rows)
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return;
        }

        let chunk_size = std::cmp::max((input.branch_events.len()) / num_cpus::get(), 1);
        let width = <BranchChip<M> as BaseAir<F>>::width(self);

        let blu_batches = input
            .branch_events
            .chunks(chunk_size)
            .par_bridge()
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = vec![F::zero(); width];
                    let cols: &mut BranchColumns<F, M> = row.as_mut_slice().borrow_mut();

                    self.event_to_row(&event.0, cols, &mut blu);
                    cols.state.populate(&mut blu, event.0.clk, event.0.pc);
                    cols.adapter.populate(&mut blu, event.1);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return;
        }

        // Generate the rows for the trace.
        let chunk_size = std::cmp::max(input.branch_events.len() / num_cpus::get(), 1);
        let padded_nb_rows = <BranchChip<M> as MachineAir<F>>::num_rows(self, input).unwrap();
        let width = <BranchChip<M> as BaseAir<F>>::width(self);

        let num_event_rows = input.branch_events.len();

        unsafe {
            let padding_start = num_event_rows * width;
            let padding_size = (padded_nb_rows - num_event_rows) * width;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * width) };

        values.chunks_mut(chunk_size * width).enumerate().par_bridge().for_each(|(i, rows)| {
            let mut blu = Vec::new();
            rows.chunks_mut(width).enumerate().for_each(|(j, row)| {
                let idx = i * chunk_size + j;
                let cols: &mut BranchColumns<F, M> = row.borrow_mut();

                if idx < input.branch_events.len() {
                    let event = input.branch_events[idx];
                    self.event_to_row(&event.0, cols, &mut blu);
                    cols.state.populate(&mut blu, event.0.clk, event.0.pc);
                    cols.adapter.populate(&mut blu, event.1);
                    if !M::IS_TRUSTED {
                        let cols: &mut BranchColumns<F, UserMode> = row.borrow_mut();
                        cols.adapter_cols.is_trusted = F::from_bool(!event.1.is_untrusted);
                    }
                }
            });
        });
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.branch_events.is_empty()
                && (M::IS_TRUSTED != shard.program.enable_untrusted_programs)
        }
    }
}

impl<M: TrustMode> BranchChip<M> {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &BranchEvent,
        cols: &mut BranchColumns<F, M>,
        blu: &mut impl ByteRecord,
    ) {
        cols.is_beq = F::from_bool(matches!(event.opcode, Opcode::BEQ));
        cols.is_bne = F::from_bool(matches!(event.opcode, Opcode::BNE));
        cols.is_blt = F::from_bool(matches!(event.opcode, Opcode::BLT));
        cols.is_bge = F::from_bool(matches!(event.opcode, Opcode::BGE));
        cols.is_bltu = F::from_bool(matches!(event.opcode, Opcode::BLTU));
        cols.is_bgeu = F::from_bool(matches!(event.opcode, Opcode::BGEU));

        let a_eq_b = event.a == event.b;

        let use_signed_comparison = matches!(event.opcode, Opcode::BLT | Opcode::BGE);

        let a_lt_b = if use_signed_comparison {
            (event.a as i64) < (event.b as i64)
        } else {
            event.a < event.b
        };

        let branching = match event.opcode {
            Opcode::BEQ => a_eq_b,
            Opcode::BNE => !a_eq_b,
            Opcode::BLT | Opcode::BLTU => a_lt_b,
            Opcode::BGE | Opcode::BGEU => !a_lt_b,
            _ => unreachable!(),
        };

        cols.compare_operation.populate_signed(
            blu,
            a_lt_b as u64,
            event.a,
            event.b,
            use_signed_comparison,
        );

        cols.next_pc = [
            F::from_canonical_u16((event.next_pc & 0xFFFF) as u16),
            F::from_canonical_u16(((event.next_pc >> 16) & 0xFFFF) as u16),
            F::from_canonical_u16(((event.next_pc >> 32) & 0xFFFF) as u16),
        ];
        blu.add_bit_range_check((event.next_pc & 0xFFFF) as u16 / 4, 14);
        blu.add_u16_range_checks_field(&cols.next_pc[1..3]);

        if branching {
            cols.is_branching = F::one();
        } else {
            cols.is_branching = F::zero();
        }
    }
}
