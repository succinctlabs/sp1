use crate::{
    alu::{create_alu_lookups, AluEvent},
    runtime::{Opcode, Runtime},
};

use super::CpuEvent;

/// Emit the dependencies for CPU events.
pub fn emit_dependencies(runtime: &mut Runtime, event: CpuEvent) {
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
        runtime.record.add_events.push(add_event);
        let addr_offset = (memory_addr % 4 as u32) as u8;
        let mem_value = event.memory_record.unwrap().value();

        if matches!(event.instruction.opcode, Opcode::LB | Opcode::LH) {
            let (unsigned_mem_val, most_sig_mem_value_byte, sign_value) =
                match event.instruction.opcode {
                    Opcode::LB => {
                        let most_sig_mem_value_byte = mem_value.to_le_bytes()[addr_offset as usize];
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
                runtime.record.add_events.push(sub_event);
            }
        }
    }

    if event.instruction.is_branch_instruction() {
        let a_eq_b = event.a == event.b;
        let use_signed_comparison = matches!(event.instruction.opcode, Opcode::BLT | Opcode::BGE);
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
        runtime.record.lt_events.push(lt_comp_event);
        runtime.record.lt_events.push(gt_comp_event);
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
            runtime.record.add_events.push(add_event);
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
                runtime.record.add_events.push(add_event);
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
                runtime.record.add_events.push(add_event);
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
        runtime.record.add_events.push(add_event);
    }
}
