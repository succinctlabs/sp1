use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;
use std::collections::HashMap;

use super::columns::{
    AUIPCCols, BranchCols, JumpCols, CPU_COL_MAP, NUM_AUIPC_COLS, NUM_BRANCH_COLS, NUM_CPU_COLS,
    NUM_JUMP_COLS, NUM_MEMORY_COLUMNS,
};
use super::{CpuChip, CpuEvent};

use crate::alu::{self, AluEvent};
use crate::bytes::{ByteLookupEvent, ByteOpcode};
use crate::cpu::columns::{CpuCols, MemoryColumns};
use crate::cpu::MemoryRecordEnum;
use crate::disassembler::WORD_SIZE;
use crate::field::event::FieldEvent;
use crate::memory::MemoryCols;
use crate::runtime::{Opcode, Segment};
use crate::utils::Chip;

impl<F: PrimeField> Chip<F> for CpuChip {
    fn name(&self) -> String {
        "CPU".to_string()
    }

    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        let mut new_blu_events = Vec::new();
        let mut new_alu_events = HashMap::new();
        let mut new_field_events = Vec::new();

        let rows = segment
            .cpu_events
            .iter() // TODO: change this back to par_iter
            .map(|op| {
                self.event_to_row(
                    *op,
                    &mut new_alu_events,
                    &mut new_blu_events,
                    &mut new_field_events,
                )
            })
            .collect::<Vec<_>>();

        segment.add_alu_events(new_alu_events);
        segment.add_byte_lookup_events(new_blu_events);
        segment.field_events.extend(new_field_events);

        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_CPU_COLS);

        Self::pad_to_power_of_two::<F>(&mut trace.values);

        trace
    }
}

impl CpuChip {
    fn event_to_row<F: PrimeField>(
        &self,
        event: CpuEvent,
        new_alu_events: &mut HashMap<Opcode, Vec<alu::AluEvent>>,
        new_blu_events: &mut Vec<ByteLookupEvent>,
        new_field_events: &mut Vec<FieldEvent>,
    ) -> [F; NUM_CPU_COLS] {
        let mut row = [F::zero(); NUM_CPU_COLS];
        let cols: &mut CpuCols<F> = row.as_mut_slice().borrow_mut();
        cols.segment = F::from_canonical_u32(event.segment);
        cols.clk = F::from_canonical_u32(event.clk);
        cols.pc = F::from_canonical_u32(event.pc);

        cols.instruction.populate(event.instruction);
        cols.selectors.populate(event.instruction);

        *cols.op_a_access.value_mut() = event.a.into();
        *cols.op_b_access.value_mut() = event.b.into();
        *cols.op_c_access.value_mut() = event.c.into();
        if let Some(record) = event.a_record {
            cols.op_a_access.populate(record, new_field_events)
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.b_record {
            cols.op_b_access.populate(record, new_field_events)
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.c_record {
            cols.op_c_access.populate(record, new_field_events)
        }

        // If there is a memory record, then event.memory should be set and vice-versa.
        assert_eq!(event.memory_record.is_some(), event.memory.is_some());

        let memory_columns: &mut MemoryColumns<F> =
            cols.opcode_specific_columns[..NUM_MEMORY_COLUMNS].borrow_mut();
        if let Some(record) = event.memory_record {
            memory_columns
                .memory_access
                .populate(record, new_field_events)
        }

        self.populate_memory(cols, event, new_alu_events, new_blu_events);
        self.populate_branch(cols, event, new_alu_events);
        self.populate_jump(cols, event, new_alu_events);
        self.populate_auipc(cols, event, new_alu_events);
        cols.is_real = F::one();

        row
    }

    fn populate_memory<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: CpuEvent,
        new_alu_events: &mut HashMap<Opcode, Vec<alu::AluEvent>>,
        new_blu_events: &mut Vec<ByteLookupEvent>,
    ) {
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
            let memory_columns: &mut MemoryColumns<F> =
                cols.opcode_specific_columns[0..NUM_MEMORY_COLUMNS].borrow_mut();

            let memory_addr = event.b.wrapping_add(event.c);
            memory_columns.addr_word = memory_addr.into();
            memory_columns.addr_aligned =
                F::from_canonical_u32(memory_addr - memory_addr % WORD_SIZE as u32);
            // Add event to ALU check to check that addr == b + c
            let add_event = AluEvent {
                clk: event.clk,
                opcode: Opcode::ADD,
                a: memory_addr,
                b: event.b,
                c: event.c,
            };
            new_alu_events
                .entry(Opcode::ADD)
                .and_modify(|op_new_events| op_new_events.push(add_event))
                .or_insert(vec![add_event]);

            let addr_offset = (memory_addr % WORD_SIZE as u32) as u8;
            memory_columns.addr_offset = F::from_canonical_u8(addr_offset);
            memory_columns.offset_is_one = F::from_bool(addr_offset == 1);
            memory_columns.offset_is_two = F::from_bool(addr_offset == 2);
            memory_columns.offset_is_three = F::from_bool(addr_offset == 3);

            // If it is a load instruction, set the unsigned_mem_val column
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
                    let most_sig_mem_value_byte: u8;
                    let sign_value: u32;
                    if matches!(event.instruction.opcode, Opcode::LB) {
                        sign_value = 256;
                        most_sig_mem_value_byte = cols.unsigned_mem_val.to_u32().to_le_bytes()[0];
                    } else {
                        // LHU case
                        sign_value = 65536;
                        most_sig_mem_value_byte = cols.unsigned_mem_val.to_u32().to_le_bytes()[1];
                    };

                    for i in (0..8).rev() {
                        memory_columns.most_sig_byte_decomp[i] =
                            F::from_canonical_u8(most_sig_mem_value_byte >> i & 0x01);
                    }
                    if memory_columns.most_sig_byte_decomp[7] == F::one() {
                        cols.mem_value_is_neg = F::one();
                        let sub_event = AluEvent {
                            clk: event.clk,
                            opcode: Opcode::SUB,
                            a: event.a,
                            b: cols.unsigned_mem_val.to_u32(),
                            c: sign_value,
                        };

                        new_alu_events
                            .entry(Opcode::SUB)
                            .and_modify(|op_new_events| op_new_events.push(sub_event))
                            .or_insert(vec![sub_event]);
                    }
                }
            }

            // Add event to byte lookup for byte range checking each byte in the memory addr
            let addr_bytes = memory_addr.to_le_bytes();
            for byte_pair in addr_bytes.chunks_exact(2) {
                new_blu_events.push(ByteLookupEvent {
                    opcode: ByteOpcode::U8Range,
                    a1: 0,
                    a2: 0,
                    b: byte_pair[0] as u32,
                    c: byte_pair[1] as u32,
                });
            }
        }
    }

    fn populate_branch<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: CpuEvent,
        alu_events: &mut HashMap<Opcode, Vec<alu::AluEvent>>,
    ) {
        if event.instruction.is_branch_instruction() {
            let branch_columns: &mut BranchCols<F> =
                cols.opcode_specific_columns[..NUM_BRANCH_COLS].borrow_mut();

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
                clk: event.clk,
                opcode: alu_op_code,
                a: a_lt_b as u32,
                b: event.a,
                c: event.b,
            };

            alu_events
                .entry(alu_op_code)
                .and_modify(|op_new_events| op_new_events.push(lt_comp_event))
                .or_insert(vec![lt_comp_event]);

            let gt_comp_event = AluEvent {
                clk: event.clk,
                opcode: alu_op_code,
                a: a_gt_b as u32,
                b: event.b,
                c: event.a,
            };

            alu_events
                .entry(alu_op_code)
                .and_modify(|op_new_events| op_new_events.push(gt_comp_event))
                .or_insert(vec![gt_comp_event]);

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

            if branching {
                let next_pc = event.pc.wrapping_add(event.c);

                cols.branching = F::one();
                branch_columns.pc = event.pc.into();
                branch_columns.next_pc = next_pc.into();

                let add_event = AluEvent {
                    clk: event.clk,
                    opcode: Opcode::ADD,
                    a: next_pc,
                    b: event.pc,
                    c: event.c,
                };

                alu_events
                    .entry(Opcode::ADD)
                    .and_modify(|op_new_events| op_new_events.push(add_event))
                    .or_insert(vec![add_event]);
            } else {
                cols.not_branching = F::one();
            }
        }
    }

    fn populate_jump<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: CpuEvent,
        alu_events: &mut HashMap<Opcode, Vec<alu::AluEvent>>,
    ) {
        if event.instruction.is_jump_instruction() {
            let jump_columns: &mut JumpCols<F> =
                cols.opcode_specific_columns[..NUM_JUMP_COLS].borrow_mut();

            match event.instruction.opcode {
                Opcode::JAL => {
                    let next_pc = event.pc.wrapping_add(event.b);
                    jump_columns.pc = event.pc.into();
                    jump_columns.next_pc = next_pc.into();

                    let add_event = AluEvent {
                        clk: event.clk,
                        opcode: Opcode::ADD,
                        a: next_pc,
                        b: event.pc,
                        c: event.b,
                    };

                    alu_events
                        .entry(Opcode::ADD)
                        .and_modify(|op_new_events| op_new_events.push(add_event))
                        .or_insert(vec![add_event]);
                }
                Opcode::JALR => {
                    let next_pc = event.b.wrapping_add(event.c);
                    jump_columns.next_pc = next_pc.into();

                    let add_event = AluEvent {
                        clk: event.clk,
                        opcode: Opcode::ADD,
                        a: next_pc,
                        b: event.b,
                        c: event.c,
                    };

                    alu_events
                        .entry(Opcode::ADD)
                        .and_modify(|op_new_events| op_new_events.push(add_event))
                        .or_insert(vec![add_event]);
                }
                _ => unreachable!(),
            }
        }
    }

    fn populate_auipc<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: CpuEvent,
        alu_events: &mut HashMap<Opcode, Vec<alu::AluEvent>>,
    ) {
        if matches!(event.instruction.opcode, Opcode::AUIPC) {
            let auipc_columns: &mut AUIPCCols<F> =
                cols.opcode_specific_columns[..NUM_AUIPC_COLS].borrow_mut();

            auipc_columns.pc = event.pc.into();

            let add_event = AluEvent {
                clk: event.clk,
                opcode: Opcode::ADD,
                a: event.a,
                b: event.pc,
                c: event.b,
            };

            alu_events
                .entry(Opcode::ADD)
                .and_modify(|op_new_events| op_new_events.push(add_event))
                .or_insert(vec![add_event]);
        }
    }

    fn pad_to_power_of_two<F: PrimeField>(values: &mut Vec<F>) {
        let len: usize = values.len();
        let n_real_rows = values.len() / NUM_CPU_COLS;

        let last_row = &values[len - NUM_CPU_COLS..];
        let pc = last_row[CPU_COL_MAP.pc];
        let clk = last_row[CPU_COL_MAP.clk];

        values.resize(n_real_rows.next_power_of_two() * NUM_CPU_COLS, F::zero());

        // Interpret values as a slice of arrays of length `NUM_CPU_COLS`
        let rows = unsafe {
            core::slice::from_raw_parts_mut(
                values.as_mut_ptr() as *mut [F; NUM_CPU_COLS],
                values.len() / NUM_CPU_COLS,
            )
        };

        rows[n_real_rows..]
            .iter_mut() // TODO: can be replaced with par_iter_mut
            .enumerate()
            .for_each(|(n, padded_row)| {
                padded_row[CPU_COL_MAP.pc] = pc;
                padded_row[CPU_COL_MAP.clk] = clk + F::from_canonical_u32((n as u32 + 1) * 4);
                padded_row[CPU_COL_MAP.selectors.is_noop] = F::one();
                padded_row[CPU_COL_MAP.selectors.imm_b] = F::one();
                padded_row[CPU_COL_MAP.selectors.imm_c] = F::one();
                // The operands will default by 0, so this will be a no-op anyways.
            });
    }
}

#[cfg(test)]
mod tests {

    use p3_baby_bear::BabyBear;

    use crate::utils::{uni_stark_prove as prove, uni_stark_verify as verify};
    use p3_matrix::dense::RowMajorMatrix;
    use rand::thread_rng;

    use crate::{
        runtime::{tests::simple_program, Instruction, Runtime, Segment},
        utils::{BabyBearPoseidon2, Chip, StarkUtils},
    };

    use super::*;
    #[test]
    fn generate_trace() {
        let mut segment = Segment::default();
        segment.cpu_events = vec![CpuEvent {
            segment: 1,
            clk: 6,
            pc: 1,
            instruction: Instruction {
                opcode: Opcode::ADD,
                op_a: 0,
                op_b: 1,
                op_c: 2,
                imm_b: false,
                imm_c: false,
            },
            a: 1,
            a_record: None,
            b: 2,
            b_record: None,
            c: 3,
            c_record: None,
            memory: None,
            memory_record: None,
        }];
        let chip = CpuChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
        println!("{:?}", trace.values);
    }

    #[test]
    fn generate_trace_simple_program() {
        let program = simple_program();
        let mut runtime = Runtime::new(program);
        runtime.run();
        let chip = CpuChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime.segment);
        for cpu_event in runtime.segment.cpu_events {
            println!("{:?}", cpu_event);
        }
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_trace() {
        let config = BabyBearPoseidon2::new(&mut thread_rng());
        let mut challenger = config.challenger();

        let program = simple_program();
        let mut runtime = Runtime::new(program);
        runtime.run();
        let chip = CpuChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime.segment);
        trace.rows().for_each(|row| println!("{:?}", row));

        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
