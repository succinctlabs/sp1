use hashbrown::HashMap;
use itertools::Itertools;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, CpuEvent, MemoryRecordEnum},
    syscalls::SyscallCode,
    ByteOpcode::{self, U16Range},
    ExecutionRecord, Instruction, Opcode, Program,
};
use sp1_stark::{air::MachineAir, Word};
use std::borrow::BorrowMut;

use p3_field::{PrimeField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator, ParallelSlice};
use tracing::instrument;

use super::{columns::NUM_CPU_COLS, CpuChip};
use crate::{cpu::columns::CpuCols, memory::MemoryCols, utils::zeroed_f_vec};

impl<F: PrimeField32> MachineAir<F> for CpuChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "CPU".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let n_real_rows = input.cpu_events.len();
        let padded_nb_rows = if let Some(shape) = &input.shape {
            1 << shape.inner[&MachineAir::<F>::name(self)]
        } else if n_real_rows < 16 {
            16
        } else {
            n_real_rows.next_power_of_two()
        };
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_CPU_COLS);

        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);
        values.chunks_mut(chunk_size * NUM_CPU_COLS).enumerate().par_bridge().for_each(
            |(i, rows)| {
                rows.chunks_mut(NUM_CPU_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut CpuCols<F> = row.borrow_mut();

                    if idx >= input.cpu_events.len() {
                        cols.selectors.imm_b = F::one();
                        cols.selectors.imm_c = F::one();
                    } else {
                        let mut byte_lookup_events = Vec::new();
                        let event = &input.cpu_events[idx];
                        let instruction = &input.program.fetch(event.pc);
                        self.event_to_row(
                            event,
                            &input.nonce_lookup,
                            cols,
                            &mut byte_lookup_events,
                            input.public_values.execution_shard,
                            instruction,
                        );
                    }
                });
            },
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_CPU_COLS)
    }

    #[instrument(name = "generate cpu dependencies", level = "debug", skip_all)]
    fn generate_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        // Generate the trace rows for each event.
        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);

        let blu_events: Vec<_> = input
            .cpu_events
            .par_chunks(chunk_size)
            .map(|ops: &[CpuEvent]| {
                // The blu map stores shard -> map(byte lookup event -> multiplicity).
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                ops.iter().for_each(|op| {
                    let mut row = [F::zero(); NUM_CPU_COLS];
                    let cols: &mut CpuCols<F> = row.as_mut_slice().borrow_mut();
                    let instruction = &input.program.fetch(op.pc);
                    self.event_to_row::<F>(
                        op,
                        &input.nonce_lookup,
                        cols,
                        &mut blu,
                        input.public_values.execution_shard,
                        instruction,
                    );
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_events.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            shard.contains_cpu()
        }
    }
}

impl CpuChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &CpuEvent,
        nonce_lookup: &[u32],
        cols: &mut CpuCols<F>,
        blu_events: &mut impl ByteRecord,
        shard: u32,
        instruction: &Instruction,
    ) {
        // Populate shard and clk columns.
        self.populate_shard_clk(cols, event, blu_events, shard);

        // Populate the nonce.
        cols.nonce = F::from_canonical_u32(
            nonce_lookup.get(event.alu_lookup_id.0 as usize).copied().unwrap_or_default(),
        );

        // Populate basic fields.
        cols.pc = F::from_canonical_u32(event.pc);
        cols.next_pc = F::from_canonical_u32(event.next_pc);
        cols.instruction.populate(instruction);
        cols.is_mem_store =
            F::from_bool(matches!(instruction.opcode, Opcode::SB | Opcode::SH | Opcode::SW));
        cols.selectors.populate(instruction);
        *cols.op_a_access.value_mut() = event.a.into();
        *cols.op_b_access.value_mut() = event.b.into();
        *cols.op_c_access.value_mut() = event.c.into();

        // Populate memory accesses for a, b, and c.
        if let Some(record) = event.a_record {
            cols.op_a_access.populate(record, blu_events);
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.b_record {
            cols.op_b_access.populate(record, blu_events);
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.c_record {
            cols.op_c_access.populate(record, blu_events);
        }

        // Populate range checks for a.
        let a_bytes = cols
            .op_a_access
            .access
            .value
            .0
            .iter()
            .map(|x| x.as_canonical_u32())
            .collect::<Vec<_>>();
        blu_events.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: a_bytes[0] as u8,
            c: a_bytes[1] as u8,
        });
        blu_events.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: a_bytes[2] as u8,
            c: a_bytes[3] as u8,
        });

        // Populate branch, jump, and auipc specific fields.
        self.populate_branch(cols, event, nonce_lookup, instruction);
        self.populate_jump(cols, event, nonce_lookup, instruction);
        self.populate_auipc(cols, event, nonce_lookup, instruction);
        let is_halt = self.populate_ecall(cols, event, nonce_lookup);

        cols.is_sequential_instr = F::from_bool(
            !instruction.is_branch_instruction()
                && !instruction.is_jump_instruction()
                && !is_halt
                && !instruction.is_alu_instruction(),
        );

        // Assert that the instruction is not a no-op.
        cols.is_real = F::one();
    }

    /// Populates the shard and clk related rows.
    fn populate_shard_clk<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        blu_events: &mut impl ByteRecord,
        shard: u32,
    ) {
        cols.shard = F::from_canonical_u32(shard);
        cols.clk = F::from_canonical_u32(event.clk);

        let clk_16bit_limb = (event.clk & 0xffff) as u16;
        let clk_8bit_limb = ((event.clk >> 16) & 0xff) as u8;
        cols.clk_16bit_limb = F::from_canonical_u16(clk_16bit_limb);
        cols.clk_8bit_limb = F::from_canonical_u8(clk_8bit_limb);

        blu_events.add_byte_lookup_event(ByteLookupEvent::new(U16Range, shard as u16, 0, 0, 0));
        blu_events.add_byte_lookup_event(ByteLookupEvent::new(U16Range, clk_16bit_limb, 0, 0, 0));
        blu_events.add_byte_lookup_event(ByteLookupEvent::new(
            ByteOpcode::U8Range,
            0,
            0,
            0,
            clk_8bit_limb as u8,
        ));
    }

    /// Populates columns related to branching.
    fn populate_branch<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        nonce_lookup: &[u32],
        instruction: &Instruction,
    ) {
        if instruction.is_branch_instruction() {
            let branch_columns = cols.opcode_specific_columns.branch_mut();

            let a_eq_b = event.a == event.b;

            let use_signed_comparison = matches!(instruction.opcode, Opcode::BLT | Opcode::BGE);

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

            branch_columns.a_lt_b_nonce = F::from_canonical_u32(
                nonce_lookup.get(event.branch_lt_lookup_id.0 as usize).copied().unwrap_or_default(),
            );

            branch_columns.a_gt_b_nonce = F::from_canonical_u32(
                nonce_lookup.get(event.branch_gt_lookup_id.0 as usize).copied().unwrap_or_default(),
            );

            branch_columns.a_eq_b = F::from_bool(a_eq_b);
            branch_columns.a_lt_b = F::from_bool(a_lt_b);
            branch_columns.a_gt_b = F::from_bool(a_gt_b);

            let branching = match instruction.opcode {
                Opcode::BEQ => a_eq_b,
                Opcode::BNE => !a_eq_b,
                Opcode::BLT | Opcode::BLTU => a_lt_b,
                Opcode::BGE | Opcode::BGEU => a_eq_b || a_gt_b,
                _ => unreachable!(),
            };

            let next_pc = event.pc.wrapping_add(event.c);
            branch_columns.pc = Word::from(event.pc);
            branch_columns.next_pc = Word::from(next_pc);
            branch_columns.pc_range_checker.populate(event.pc);
            branch_columns.next_pc_range_checker.populate(next_pc);

            if branching {
                cols.branching = F::one();
                branch_columns.next_pc_nonce = F::from_canonical_u32(
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

    /// Populate columns related to jumping.
    fn populate_jump<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        nonce_lookup: &[u32],
        instruction: &Instruction,
    ) {
        if instruction.is_jump_instruction() {
            let jump_columns = cols.opcode_specific_columns.jump_mut();

            match instruction.opcode {
                Opcode::JAL => {
                    let next_pc = event.pc.wrapping_add(event.b);
                    jump_columns.op_a_range_checker.populate(event.a);
                    jump_columns.pc = Word::from(event.pc);
                    jump_columns.pc_range_checker.populate(event.pc);
                    jump_columns.next_pc = Word::from(next_pc);
                    jump_columns.next_pc_range_checker.populate(next_pc);
                    jump_columns.jal_nonce = F::from_canonical_u32(
                        nonce_lookup
                            .get(event.jump_jal_lookup_id.0 as usize)
                            .copied()
                            .unwrap_or_default(),
                    );
                }
                Opcode::JALR => {
                    let next_pc = event.b.wrapping_add(event.c);
                    jump_columns.op_a_range_checker.populate(event.a);
                    jump_columns.next_pc = Word::from(next_pc);
                    jump_columns.next_pc_range_checker.populate(next_pc);
                    jump_columns.jalr_nonce = F::from_canonical_u32(
                        nonce_lookup
                            .get(event.jump_jalr_lookup_id.0 as usize)
                            .copied()
                            .unwrap_or_default(),
                    );
                }
                _ => unreachable!(),
            }
        }
    }

    /// Populate columns related to AUIPC.
    fn populate_auipc<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        nonce_lookup: &[u32],
        instruction: &Instruction,
    ) {
        if matches!(instruction.opcode, Opcode::AUIPC) {
            let auipc_columns = cols.opcode_specific_columns.auipc_mut();

            auipc_columns.pc = Word::from(event.pc);
            auipc_columns.pc_range_checker.populate(event.pc);
            auipc_columns.auipc_nonce = F::from_canonical_u32(
                nonce_lookup.get(event.auipc_lookup_id.0 as usize).copied().unwrap_or_default(),
            );
        }
    }

    /// Populate columns related to ECALL.
    fn populate_ecall<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        nonce_lookup: &[u32],
    ) -> bool {
        let mut is_halt = false;

        if cols.selectors.is_ecall == F::one() {
            // The send_to_table column is the 1st entry of the op_a_access column prev_value field.
            // Look at `ecall_eval` in cpu/air/mod.rs for the corresponding constraint and
            // explanation.
            let ecall_cols = cols.opcode_specific_columns.ecall_mut();

            cols.ecall_mul_send_to_table = cols.selectors.is_ecall * cols.op_a_access.prev_value[1];

            let syscall_id = cols.op_a_access.prev_value[0];
            // let send_to_table = cols.op_a_access.prev_value[1];
            // let num_cycles = cols.op_a_access.prev_value[2];

            // Populate `is_enter_unconstrained`.
            ecall_cols.is_enter_unconstrained.populate_from_field_element(
                syscall_id - F::from_canonical_u32(SyscallCode::ENTER_UNCONSTRAINED.syscall_id()),
            );

            // Populate `is_hint_len`.
            ecall_cols.is_hint_len.populate_from_field_element(
                syscall_id - F::from_canonical_u32(SyscallCode::HINT_LEN.syscall_id()),
            );

            // Populate `is_halt`.
            ecall_cols.is_halt.populate_from_field_element(
                syscall_id - F::from_canonical_u32(SyscallCode::HALT.syscall_id()),
            );

            // Populate `is_commit`.
            ecall_cols.is_commit.populate_from_field_element(
                syscall_id - F::from_canonical_u32(SyscallCode::COMMIT.syscall_id()),
            );

            // Populate `is_commit_deferred_proofs`.
            ecall_cols.is_commit_deferred_proofs.populate_from_field_element(
                syscall_id
                    - F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id()),
            );

            // If the syscall is `COMMIT` or `COMMIT_DEFERRED_PROOFS`, set the index bitmap and
            // digest word.
            if syscall_id == F::from_canonical_u32(SyscallCode::COMMIT.syscall_id())
                || syscall_id
                    == F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id())
            {
                let digest_idx = cols.op_b_access.value().to_u32() as usize;
                ecall_cols.index_bitmap[digest_idx] = F::one();
            }

            // Write the syscall nonce.
            ecall_cols.syscall_nonce =
                F::from_canonical_u32(nonce_lookup[event.syscall_lookup_id.0 as usize]);

            is_halt = syscall_id == F::from_canonical_u32(SyscallCode::HALT.syscall_id());

            // For halt and commit deferred proofs syscalls, we need to baby bear range check one of
            // it's operands.
            if is_halt {
                ecall_cols.operand_to_check = event.b.into();
                ecall_cols.operand_range_check_cols.populate(event.b);
                cols.ecall_range_check_operand = F::one();
            }

            if syscall_id == F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id())
            {
                ecall_cols.operand_to_check = event.c.into();
                ecall_cols.operand_range_check_cols.populate(event.c);
                cols.ecall_range_check_operand = F::one();
            }
        }

        is_halt
    }
}
