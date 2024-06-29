use hashbrown::HashMap;
use num::traits::ToBytes;
use p3_maybe_rayon::prelude::ParallelBridge;
use std::array;
use std::borrow::BorrowMut;

use p3_field::{PrimeField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::IntoParallelRefMutIterator;
use p3_maybe_rayon::prelude::ParallelIterator;
use p3_maybe_rayon::prelude::ParallelSlice;
use p3_maybe_rayon::prelude::ParallelSliceMut;
use tracing::instrument;

use super::columns::{CPU_COL_MAP, NUM_CPU_COLS};
use super::{CpuChip, CpuEvent};
use crate::air::MachineAir;
use crate::air::Word;
use crate::alu::create_alu_lookups;
use crate::alu::AluEvent;
use crate::bytes::event::ByteRecord;
use crate::bytes::{ByteLookupEvent, ByteOpcode};
use crate::cpu::columns::CpuCols;
use crate::cpu::trace::ByteOpcode::{U16Range, U8Range};
use crate::disassembler::WORD_SIZE;
use crate::lookup::{AluInteraction, InteractionEvent};
use crate::memory::MemoryCols;
use crate::runtime::MemoryReadRecord;
use crate::runtime::{ExecutionRecord, Opcode, Program, Runtime};
use crate::runtime::{MemoryRecordEnum, SyscallCode};

impl<F: PrimeField32> MachineAir<F> for CpuChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "CPU".to_string()
    }

    fn generate_interaction_events(&self, input: &Self::Record) -> Vec<InteractionEvent> {
        input
            .cpu_events
            .iter()
            .map(|event| CpuChip::event_to_interaction_events(*event))
            .flatten()
            .collect()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut values = vec![F::zero(); input.cpu_events.len() * NUM_CPU_COLS];

        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);
        values
            .chunks_mut(chunk_size * NUM_CPU_COLS)
            .enumerate()
            .par_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_CPU_COLS)
                    .enumerate()
                    .for_each(|(j, row)| {
                        let idx = i * chunk_size + j;
                        let cols: &mut CpuCols<F> = row.borrow_mut();
                        self.event_to_row(&input.cpu_events[idx], &input.nonce_lookup, cols);
                    });
            });

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(values, NUM_CPU_COLS);

        // Pad the trace to a power of two.
        Self::pad_to_power_of_two::<F>(&mut trace.values);

        trace
    }

    #[instrument(name = "generate cpu dependencies", level = "debug", skip_all)]
    fn generate_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        // TODO: separate this late
        // Generate the trace rows for each event.
        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);
        let blu_events: Vec<_> = input
            .cpu_events
            .par_chunks(chunk_size)
            .map(|ops: &[CpuEvent]| {
                let mut blu: Vec<_> = Vec::with_capacity(ops.len() * 8);
                ops.iter().for_each(|op| {
                    let mut row = [F::zero(); NUM_CPU_COLS];
                    let cols: &mut CpuCols<F> = row.as_mut_slice().borrow_mut();
                    let blu_events = self.event_to_row::<F>(op, &HashMap::new(), cols);
                    blu.extend(blu_events);
                });
                blu
            })
            .collect();

        let mut blu_events = blu_events.into_iter().flatten().collect::<Vec<_>>();
        blu_events.par_sort_unstable_by_key(|event| (event.shard, event.opcode));

        for blu_event in blu_events.into_iter() {
            output.add_byte_lookup_event(blu_event);
        }
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }
}

impl CpuChip {
    pub fn event_to_interaction_events(event: CpuEvent) -> Vec<InteractionEvent> {
        let mut interaction_events = Vec::new();

        // This is the "ECALL" interaction event.
        if event.instruction.opcode == Opcode::ECALL {
            let a_record = event.a_record.expect("ECALL should have an a record");
            let prev_value = a_record.prev_value();
            let syscall_id = prev_value.to_le_bytes()[0] as u32;
            interaction_events.push(InteractionEvent::from_syscall(
                true,
                event.shard,
                event.clk,
                syscall_id,
                event.b,
                event.c,
            ));
        }

        // All interactions due to memory are here.
        if let Some(record) = event.a_record {
            interaction_events.push(InteractionEvent::from_memory_record(&record));
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.b_record {
            interaction_events.push(InteractionEvent::from_memory_record(&record.into()));
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.c_record {
            interaction_events.push(InteractionEvent::from_memory_record(&record.into()));
        }
        // Populate memory accesses for reading from memory.
        assert_eq!(event.memory_record.is_some(), event.memory.is_some());
        if let Some(record) = event.memory_record {
            interaction_events.push(InteractionEvent::from_memory_record(&record));
        }

        // Interactions due to send_alu are here (at the top-level due to opcode)
        if event.instruction.is_alu_instruction() {
            let interaction = InteractionEvent::Alu(AluInteraction {
                is_send: true,
                shard: event.shard,
                clk: event.clk,
                opcode: event.instruction.opcode,
                a: event.a,
                b: event.b,
                c: event.c,
            });
            interaction_events.push(interaction);
        }

        // TODO: refactor below so its a less jank...
        let mut mock_record = ExecutionRecord::default();
        let alu_events = CpuChip::event_to_alu_events(&mut mock_record, event);
        for alu_event in alu_events {
            interaction_events.push(InteractionEvent::from_alu_event(true, &alu_event));
        }
        interaction_events
    }

    /// Given an CpuEvent, emit all ALU events that are derived from it.
    pub fn event_to_alu_events(record: &mut ExecutionRecord, event: CpuEvent) -> Vec<AluEvent> {
        let mut all_alu_events = vec![];
        if matches!(
            event.instruction.opcode,
            Opcode::LB
                | Opcode::LH
                | Opcode::LW
                | Opcode::LBU
                | Opcode::LHU
                | Opcode::SB
                | Opcode::SH
                | Opcode::SW
        ) {
            let memory_addr = event.b.wrapping_add(event.c);
            // Add event to ALU check to check that addr == b + c
            let add_event = AluEvent {
                lookup_id: event.memory_add_lookup_id,
                shard: event.shard,
                channel: event.channel,
                clk: event.clk,
                opcode: Opcode::ADD,
                a: memory_addr,
                b: event.b,
                c: event.c,
                sub_lookups: create_alu_lookups(),
            };
            all_alu_events.push(add_event);
            record.add_events.push(add_event);
            let addr_offset = (memory_addr % 4 as u32) as u8;
            let mem_value = event.memory_record.unwrap().value();

            if matches!(event.instruction.opcode, Opcode::LB | Opcode::LH) {
                let (unsigned_mem_val, most_sig_mem_value_byte, sign_value) =
                    match event.instruction.opcode {
                        Opcode::LB => {
                            let most_sig_mem_value_byte =
                                mem_value.to_le_bytes()[addr_offset as usize];
                            let sign_value = 256;
                            (
                                most_sig_mem_value_byte as u32,
                                most_sig_mem_value_byte,
                                sign_value,
                            )
                        }
                        Opcode::LH => {
                            let sign_value = 65536;
                            let unsigned_mem_val = match (addr_offset >> 1) % 2 {
                                0 => mem_value & 0x0000FFFF,
                                1 => (mem_value & 0xFFFF0000) >> 16,
                                _ => unreachable!(),
                            };
                            let most_sig_mem_value_byte = unsigned_mem_val.to_le_bytes()[1];
                            (unsigned_mem_val, most_sig_mem_value_byte, sign_value)
                        }
                        _ => unreachable!(),
                    };

                if most_sig_mem_value_byte >> 7 & 0x01 == 1 {
                    let sub_event = AluEvent {
                        lookup_id: event.memory_sub_lookup_id,
                        channel: event.channel,
                        shard: event.shard,
                        clk: event.clk,
                        opcode: Opcode::SUB,
                        a: event.a,
                        b: unsigned_mem_val,
                        c: sign_value,
                        sub_lookups: create_alu_lookups(),
                    };
                    record.add_events.push(sub_event);
                    all_alu_events.push(sub_event);
                }
            }
        }

        if event.instruction.is_branch_instruction() {
            let a_eq_b = event.a == event.b;
            let use_signed_comparison =
                matches!(event.instruction.opcode, Opcode::BLT | Opcode::BGE);
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

            let alu_op_code = if use_signed_comparison {
                Opcode::SLT
            } else {
                Opcode::SLTU
            };
            // Add the ALU events for the comparisons
            let lt_comp_event = AluEvent {
                lookup_id: event.branch_lt_lookup_id,
                shard: event.shard,
                channel: event.channel,
                clk: event.clk,
                opcode: alu_op_code,
                a: a_lt_b as u32,
                b: event.a,
                c: event.b,
                sub_lookups: create_alu_lookups(),
            };
            let gt_comp_event = AluEvent {
                lookup_id: event.branch_gt_lookup_id,
                shard: event.shard,
                channel: event.channel,
                clk: event.clk,
                opcode: alu_op_code,
                a: a_gt_b as u32,
                b: event.b,
                c: event.a,
                sub_lookups: create_alu_lookups(),
            };
            record.lt_events.push(lt_comp_event);
            record.lt_events.push(gt_comp_event);
            all_alu_events.push(lt_comp_event);
            all_alu_events.push(gt_comp_event);
            let branching = match event.instruction.opcode {
                Opcode::BEQ => a_eq_b,
                Opcode::BNE => !a_eq_b,
                Opcode::BLT | Opcode::BLTU => a_lt_b,
                Opcode::BGE | Opcode::BGEU => a_eq_b || a_gt_b,
                _ => unreachable!(),
            };
            if branching {
                let next_pc = event.pc.wrapping_add(event.c);
                let add_event = AluEvent {
                    lookup_id: event.branch_add_lookup_id,
                    shard: event.shard,
                    channel: event.channel,
                    clk: event.clk,
                    opcode: Opcode::ADD,
                    a: next_pc,
                    b: event.pc,
                    c: event.c,
                    sub_lookups: create_alu_lookups(),
                };
                record.add_events.push(add_event);
                all_alu_events.push(add_event);
            }
        }

        if event.instruction.is_jump_instruction() {
            match event.instruction.opcode {
                Opcode::JAL => {
                    let next_pc = event.pc.wrapping_add(event.b);
                    let add_event = AluEvent {
                        lookup_id: event.jump_jal_lookup_id,
                        shard: event.shard,
                        channel: event.channel,
                        clk: event.clk,
                        opcode: Opcode::ADD,
                        a: next_pc,
                        b: event.pc,
                        c: event.b,
                        sub_lookups: create_alu_lookups(),
                    };
                    record.add_events.push(add_event);
                    all_alu_events.push(add_event);
                }
                Opcode::JALR => {
                    let next_pc = event.b.wrapping_add(event.c);
                    let add_event = AluEvent {
                        lookup_id: event.jump_jalr_lookup_id,
                        shard: event.shard,
                        channel: event.channel,
                        clk: event.clk,
                        opcode: Opcode::ADD,
                        a: next_pc,
                        b: event.b,
                        c: event.c,
                        sub_lookups: create_alu_lookups(),
                    };
                    record.add_events.push(add_event);
                    all_alu_events.push(add_event);
                }
                _ => unreachable!(),
            }
        }

        if matches!(event.instruction.opcode, Opcode::AUIPC) {
            let add_event = AluEvent {
                lookup_id: event.auipc_lookup_id,
                shard: event.shard,
                channel: event.channel,
                clk: event.clk,
                opcode: Opcode::ADD,
                a: event.a,
                b: event.pc,
                c: event.b,
                sub_lookups: create_alu_lookups(),
            };
            record.add_events.push(add_event);
            all_alu_events.push(add_event);
        }

        all_alu_events
    }

    /// Create a row from an event.
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &CpuEvent,
        nonce_lookup: &HashMap<usize, u32>,
        cols: &mut CpuCols<F>,
    ) -> Vec<ByteLookupEvent> {
        let mut new_blu_events = Vec::new();

        // Populate shard and clk columns.
        self.populate_shard_clk(cols, event, &mut new_blu_events);

        // Populate the nonce.
        cols.nonce = F::from_canonical_u32(
            nonce_lookup
                .get(&event.alu_lookup_id)
                .copied()
                .unwrap_or_default(),
        );

        // Populate basic fields.
        cols.pc = F::from_canonical_u32(event.pc);
        cols.next_pc = F::from_canonical_u32(event.next_pc);
        cols.instruction.populate(event.instruction);
        cols.selectors.populate(event.instruction);
        *cols.op_a_access.value_mut() = event.a.into();
        *cols.op_b_access.value_mut() = event.b.into();
        *cols.op_c_access.value_mut() = event.c.into();

        // Populate memory accesses for a, b, and c.
        if let Some(record) = event.a_record {
            cols.op_a_access
                .populate(event.channel, record, &mut new_blu_events);
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.b_record {
            cols.op_b_access
                .populate(event.channel, record, &mut new_blu_events);
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.c_record {
            cols.op_c_access
                .populate(event.channel, record, &mut new_blu_events);
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
        new_blu_events.push(ByteLookupEvent {
            shard: event.shard,
            channel: event.channel,
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: a_bytes[0],
            c: a_bytes[1],
        });
        new_blu_events.push(ByteLookupEvent {
            shard: event.shard,
            channel: event.channel,
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: a_bytes[2],
            c: a_bytes[3],
        });

        // Populate memory accesses for reading from memory.
        assert_eq!(event.memory_record.is_some(), event.memory.is_some());
        let memory_columns = cols.opcode_specific_columns.memory_mut();
        if let Some(record) = event.memory_record {
            memory_columns
                .memory_access
                .populate(event.channel, record, &mut new_blu_events);
        }

        // Populate memory, branch, jump, and auipc specific fields.
        self.populate_memory(cols, event, &mut new_blu_events, nonce_lookup);
        self.populate_branch(cols, event, nonce_lookup);
        self.populate_jump(cols, event, nonce_lookup);
        self.populate_auipc(cols, event, nonce_lookup);
        let is_halt = self.populate_ecall(cols, event, nonce_lookup);

        cols.is_sequential_instr = F::from_bool(
            !event.instruction.is_branch_instruction()
                && !event.instruction.is_jump_instruction()
                && !is_halt,
        );

        // Assert that the instruction is not a no-op.
        cols.is_real = F::one();

        new_blu_events
    }

    /// Populates the shard, channel, and clk related rows.
    fn populate_shard_clk<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        new_blu_events: &mut Vec<ByteLookupEvent>,
    ) {
        cols.shard = F::from_canonical_u32(event.shard);
        cols.channel = F::from_canonical_u32(event.channel);
        cols.clk = F::from_canonical_u32(event.clk);

        let clk_16bit_limb = event.clk & 0xffff;
        let clk_8bit_limb = (event.clk >> 16) & 0xff;
        cols.clk_16bit_limb = F::from_canonical_u32(clk_16bit_limb);
        cols.clk_8bit_limb = F::from_canonical_u32(clk_8bit_limb);

        cols.channel_selectors.populate(event.channel);

        new_blu_events.push(ByteLookupEvent::new(
            event.shard,
            event.channel,
            U16Range,
            event.shard,
            0,
            0,
            0,
        ));
        new_blu_events.push(ByteLookupEvent::new(
            event.shard,
            event.channel,
            U16Range,
            clk_16bit_limb,
            0,
            0,
            0,
        ));
        new_blu_events.push(ByteLookupEvent::new(
            event.shard,
            event.channel,
            U8Range,
            0,
            0,
            0,
            clk_8bit_limb,
        ));
    }

    /// Populates columns related to memory.
    fn populate_memory<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        new_blu_events: &mut Vec<ByteLookupEvent>,
        nonce_lookup: &HashMap<usize, u32>,
    ) {
        if !matches!(
            event.instruction.opcode,
            Opcode::LB
                | Opcode::LH
                | Opcode::LW
                | Opcode::LBU
                | Opcode::LHU
                | Opcode::SB
                | Opcode::SH
                | Opcode::SW
        ) {
            return;
        }

        // Populate addr_word and addr_aligned columns.
        let memory_columns = cols.opcode_specific_columns.memory_mut();
        let memory_addr = event.b.wrapping_add(event.c);
        let aligned_addr = memory_addr - memory_addr % WORD_SIZE as u32;
        memory_columns.addr_word = memory_addr.into();
        memory_columns.addr_word_range_checker.populate(memory_addr);
        memory_columns.addr_aligned = F::from_canonical_u32(aligned_addr);

        // Populate the aa_least_sig_byte_decomp columns.
        assert!(aligned_addr % 4 == 0);
        let aligned_addr_ls_byte = (aligned_addr & 0x000000FF) as u8;
        let bits: [bool; 8] = array::from_fn(|i| aligned_addr_ls_byte & (1 << i) != 0);
        memory_columns.aa_least_sig_byte_decomp = array::from_fn(|i| F::from_bool(bits[i + 2]));
        memory_columns.addr_word_nonce = F::from_canonical_u32(
            nonce_lookup
                .get(&event.memory_add_lookup_id)
                .copied()
                .unwrap_or_default(),
        );

        // Populate memory offsets.
        let addr_offset = (memory_addr % WORD_SIZE as u32) as u8;
        memory_columns.addr_offset = F::from_canonical_u8(addr_offset);
        memory_columns.offset_is_one = F::from_bool(addr_offset == 1);
        memory_columns.offset_is_two = F::from_bool(addr_offset == 2);
        memory_columns.offset_is_three = F::from_bool(addr_offset == 3);

        // If it is a load instruction, set the unsigned_mem_val column.
        let mem_value = event.memory_record.unwrap().value();
        if matches!(
            event.instruction.opcode,
            Opcode::LB | Opcode::LBU | Opcode::LH | Opcode::LHU | Opcode::LW
        ) {
            match event.instruction.opcode {
                Opcode::LB | Opcode::LBU => {
                    cols.unsigned_mem_val =
                        (mem_value.to_le_bytes()[addr_offset as usize] as u32).into();
                }
                Opcode::LH | Opcode::LHU => {
                    let value = match (addr_offset >> 1) % 2 {
                        0 => mem_value & 0x0000FFFF,
                        1 => (mem_value & 0xFFFF0000) >> 16,
                        _ => unreachable!(),
                    };
                    cols.unsigned_mem_val = value.into();
                }
                Opcode::LW => {
                    cols.unsigned_mem_val = mem_value.into();
                }
                _ => unreachable!(),
            }

            // For the signed load instructions, we need to check if the loaded value is negative.
            if matches!(event.instruction.opcode, Opcode::LB | Opcode::LH) {
                let most_sig_mem_value_byte = if matches!(event.instruction.opcode, Opcode::LB) {
                    cols.unsigned_mem_val.to_u32().to_le_bytes()[0]
                } else {
                    // LHU case
                    cols.unsigned_mem_val.to_u32().to_le_bytes()[1]
                };

                for i in (0..8).rev() {
                    memory_columns.most_sig_byte_decomp[i] =
                        F::from_canonical_u8(most_sig_mem_value_byte >> i & 0x01);
                }
                if memory_columns.most_sig_byte_decomp[7] == F::one() {
                    cols.mem_value_is_neg = F::one();
                    cols.unsigned_mem_val_nonce = F::from_canonical_u32(
                        nonce_lookup
                            .get(&event.memory_sub_lookup_id)
                            .copied()
                            .unwrap_or_default(),
                    );
                }
            }
        }

        // Add event to byte lookup for byte range checking each byte in the memory addr
        let addr_bytes = memory_addr.to_le_bytes();
        for byte_pair in addr_bytes.chunks_exact(2) {
            new_blu_events.push(ByteLookupEvent {
                shard: event.shard,
                channel: event.channel,
                opcode: ByteOpcode::U8Range,
                a1: 0,
                a2: 0,
                b: byte_pair[0] as u32,
                c: byte_pair[1] as u32,
            });
        }
    }

    /// Populates columns related to branching.
    fn populate_branch<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        nonce_lookup: &HashMap<usize, u32>,
    ) {
        if event.instruction.is_branch_instruction() {
            let branch_columns = cols.opcode_specific_columns.branch_mut();

            let a_eq_b = event.a == event.b;

            let use_signed_comparison =
                matches!(event.instruction.opcode, Opcode::BLT | Opcode::BGE);

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
                nonce_lookup
                    .get(&event.branch_lt_lookup_id)
                    .copied()
                    .unwrap_or_default(),
            );

            branch_columns.a_gt_b_nonce = F::from_canonical_u32(
                nonce_lookup
                    .get(&event.branch_gt_lookup_id)
                    .copied()
                    .unwrap_or_default(),
            );

            branch_columns.a_eq_b = F::from_bool(a_eq_b);
            branch_columns.a_lt_b = F::from_bool(a_lt_b);
            branch_columns.a_gt_b = F::from_bool(a_gt_b);

            let branching = match event.instruction.opcode {
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
                        .get(&event.branch_add_lookup_id)
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
        nonce_lookup: &HashMap<usize, u32>,
    ) {
        if event.instruction.is_jump_instruction() {
            let jump_columns = cols.opcode_specific_columns.jump_mut();

            match event.instruction.opcode {
                Opcode::JAL => {
                    let next_pc = event.pc.wrapping_add(event.b);
                    jump_columns.op_a_range_checker.populate(event.a);
                    jump_columns.pc = Word::from(event.pc);
                    jump_columns.pc_range_checker.populate(event.pc);
                    jump_columns.next_pc = Word::from(next_pc);
                    jump_columns.next_pc_range_checker.populate(next_pc);
                    jump_columns.jal_nonce = F::from_canonical_u32(
                        nonce_lookup
                            .get(&event.jump_jal_lookup_id)
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
                            .get(&event.jump_jalr_lookup_id)
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
        nonce_lookup: &HashMap<usize, u32>,
    ) {
        if matches!(event.instruction.opcode, Opcode::AUIPC) {
            let auipc_columns = cols.opcode_specific_columns.auipc_mut();

            auipc_columns.pc = Word::from(event.pc);
            auipc_columns.pc_range_checker.populate(event.pc);
            auipc_columns.auipc_nonce = F::from_canonical_u32(
                nonce_lookup
                    .get(&event.auipc_lookup_id)
                    .copied()
                    .unwrap_or_default(),
            );
        }
    }

    /// Populate columns related to ECALL.
    fn populate_ecall<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        nonce_lookup: &HashMap<usize, u32>,
    ) -> bool {
        let mut is_halt = false;

        if cols.selectors.is_ecall == F::one() {
            // The send_to_table column is the 1st entry of the op_a_access column prev_value field.
            // Look at `ecall_eval` in cpu/air/mod.rs for the corresponding constraint and explanation.
            let ecall_cols = cols.opcode_specific_columns.ecall_mut();

            cols.ecall_mul_send_to_table = cols.selectors.is_ecall * cols.op_a_access.prev_value[1];

            let syscall_id = cols.op_a_access.prev_value[0];
            // let send_to_table = cols.op_a_access.prev_value[1];
            // let num_cycles = cols.op_a_access.prev_value[2];

            // Populate `is_enter_unconstrained`.
            ecall_cols
                .is_enter_unconstrained
                .populate_from_field_element(
                    syscall_id
                        - F::from_canonical_u32(SyscallCode::ENTER_UNCONSTRAINED.syscall_id()),
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
            ecall_cols
                .is_commit_deferred_proofs
                .populate_from_field_element(
                    syscall_id
                        - F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id()),
                );

            // If the syscall is `COMMIT` or `COMMIT_DEFERRED_PROOFS`, set the index bitmap and digest word.
            if syscall_id == F::from_canonical_u32(SyscallCode::COMMIT.syscall_id())
                || syscall_id
                    == F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id())
            {
                let digest_idx = cols.op_b_access.value().to_u32() as usize;
                ecall_cols.index_bitmap[digest_idx] = F::one();
            }

            // Write the syscall nonce.
            ecall_cols.syscall_nonce = F::from_canonical_u32(
                nonce_lookup
                    .get(&event.syscall_lookup_id)
                    .copied()
                    .unwrap_or_default(),
            );

            is_halt = syscall_id == F::from_canonical_u32(SyscallCode::HALT.syscall_id());
        }

        is_halt
    }

    fn pad_to_power_of_two<F: PrimeField>(values: &mut Vec<F>) {
        let n_real_rows = values.len() / NUM_CPU_COLS;
        let padded_nb_rows = if n_real_rows < 16 {
            16
        } else {
            n_real_rows.next_power_of_two()
        };
        values.resize(padded_nb_rows * NUM_CPU_COLS, F::zero());

        // Interpret values as a slice of arrays of length `NUM_CPU_COLS`
        let rows = unsafe {
            core::slice::from_raw_parts_mut(
                values.as_mut_ptr() as *mut [F; NUM_CPU_COLS],
                values.len() / NUM_CPU_COLS,
            )
        };

        rows[n_real_rows..].par_iter_mut().for_each(|padded_row| {
            padded_row[CPU_COL_MAP.selectors.imm_b] = F::one();
            padded_row[CPU_COL_MAP.selectors.imm_c] = F::one();
        });
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;

    use std::time::Instant;

    use super::*;

    use crate::runtime::tests::ssz_withdrawals_program;
    use crate::runtime::{tests::simple_program, Runtime};
    use crate::utils::{run_test, setup_logger, SP1CoreOpts};

    // #[test]
    // fn generate_trace() {
    //     let mut shard = ExecutionRecord::default();
    //     shard.cpu_events = vec![CpuEvent {
    //         shard: 1,
    //         channel: 0,
    //         clk: 6,
    //         pc: 1,
    //         next_pc: 5,
    //         instruction: Instruction {
    //             opcode: Opcode::ADD,
    //             op_a: 0,
    //             op_b: 1,
    //             op_c: 2,
    //             imm_b: false,
    //             imm_c: false,
    //         },
    //         a: 1,
    //         a_record: None,
    //         b: 2,
    //         b_record: None,
    //         c: 3,
    //         c_record: None,
    //         memory: None,
    //         memory_record: None,
    //         exit_code: 0,
    //     }];
    //     let chip = CpuChip::default();
    //     let trace: RowMajorMatrix<BabyBear> =
    //         chip.generate_trace(&shard, &mut ExecutionRecord::default());
    //     println!("{:?}", trace.values);
    // }

    #[test]
    fn generate_trace_simple_program() {
        let program = ssz_withdrawals_program();
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        println!("runtime: {:?}", runtime.state.global_clk);
        let chip = CpuChip::default();

        let start = Instant::now();
        <CpuChip as MachineAir<BabyBear>>::generate_dependencies(
            &chip,
            &runtime.record,
            &mut ExecutionRecord::default(),
        );
        println!("generate dependencies: {:?}", start.elapsed());

        let start = Instant::now();
        let _: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&runtime.record, &mut ExecutionRecord::default());
        println!("generate trace: {:?}", start.elapsed());
    }

    #[test]
    fn prove_trace() {
        setup_logger();
        let program = simple_program();
        run_test(program).unwrap();
    }
}
