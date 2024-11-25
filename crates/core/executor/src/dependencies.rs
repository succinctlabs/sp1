use crate::{
    events::{InstrEvent, LookupId, MemoryRecord},
    utils::{get_msb, get_quotient_and_remainder, is_signed_operation},
    Executor, Opcode, UNUSED_PC,
};

/// Emits the dependencies for division and remainder operations.
#[allow(clippy::too_many_lines)]
pub fn emit_divrem_dependencies(executor: &mut Executor, event: InstrEvent) {
    let (quotient, remainder) = get_quotient_and_remainder(event.b, event.c, event.opcode);
    let c_msb = get_msb(event.c);
    let rem_msb = get_msb(remainder);
    let mut c_neg = 0;
    let mut rem_neg = 0;
    let is_signed_operation = is_signed_operation(event.opcode);
    if is_signed_operation {
        c_neg = c_msb; // same as abs_c_alu_event
        rem_neg = rem_msb; // same as abs_rem_alu_event
    }

    if c_neg == 1 {
        let ids = executor.record.create_lookup_ids();
        executor.record.add_events.push(InstrEvent {
            pc: UNUSED_PC,
            lookup_id: event.sub_lookups[4],
            opcode: Opcode::ADD,
            a: 0,
            b: event.c,
            c: (event.c as i32).unsigned_abs(),
            sub_lookups: ids,
            op_a_0: false,
            mem_access: None,
            memory_add_lookup_id: LookupId::default(),
            memory_sub_lookup_id: LookupId::default(),
        });
    }
    if rem_neg == 1 {
        let ids = executor.record.create_lookup_ids();
        executor.record.add_events.push(InstrEvent {
            pc: UNUSED_PC,
            lookup_id: event.sub_lookups[5],
            opcode: Opcode::ADD,
            a: 0,
            b: remainder,
            c: (remainder as i32).unsigned_abs(),
            sub_lookups: ids,
            op_a_0: false,
            mem_access: None,
            memory_add_lookup_id: LookupId::default(),
            memory_sub_lookup_id: LookupId::default(),
        });
    }

    let c_times_quotient = {
        if is_signed_operation {
            (((quotient as i32) as i64) * ((event.c as i32) as i64)).to_le_bytes()
        } else {
            ((quotient as u64) * (event.c as u64)).to_le_bytes()
        }
    };
    let lower_word = u32::from_le_bytes(c_times_quotient[0..4].try_into().unwrap());
    let upper_word = u32::from_le_bytes(c_times_quotient[4..8].try_into().unwrap());

    let lower_multiplication = InstrEvent {
        pc: UNUSED_PC,
        lookup_id: event.sub_lookups[0],
        opcode: Opcode::MUL,
        a: lower_word,
        c: event.c,
        b: quotient,
        sub_lookups: executor.record.create_lookup_ids(),
        op_a_0: false,
        mem_access: None,
        memory_add_lookup_id: LookupId::default(),
        memory_sub_lookup_id: LookupId::default(),
    };
    executor.record.mul_events.push(lower_multiplication);

    let upper_multiplication = InstrEvent {
        pc: UNUSED_PC,
        lookup_id: event.sub_lookups[1],
        opcode: {
            if is_signed_operation {
                Opcode::MULH
            } else {
                Opcode::MULHU
            }
        },
        a: upper_word,
        c: event.c,
        b: quotient,
        sub_lookups: executor.record.create_lookup_ids(),
        op_a_0: false,
        mem_access: None,
        memory_add_lookup_id: LookupId::default(),
        memory_sub_lookup_id: LookupId::default(),
    };
    executor.record.mul_events.push(upper_multiplication);

    let lt_event = if is_signed_operation {
        InstrEvent {
            pc: UNUSED_PC,
            lookup_id: event.sub_lookups[2],
            opcode: Opcode::SLTU,
            a: 1,
            b: (remainder as i32).unsigned_abs(),
            c: u32::max(1, (event.c as i32).unsigned_abs()),
            sub_lookups: executor.record.create_lookup_ids(),
            op_a_0: false,
            mem_access: None,
            memory_add_lookup_id: LookupId::default(),
            memory_sub_lookup_id: LookupId::default(),
        }
    } else {
        InstrEvent {
            pc: UNUSED_PC,
            lookup_id: event.sub_lookups[3],
            opcode: Opcode::SLTU,
            a: 1,
            b: remainder,
            c: u32::max(1, event.c),
            sub_lookups: executor.record.create_lookup_ids(),
            op_a_0: false,
            mem_access: None,
            memory_add_lookup_id: LookupId::default(),
            memory_sub_lookup_id: LookupId::default(),
        }
    };

    if event.c != 0 {
        executor.record.lt_events.push(lt_event);
    }
}

pub fn emit_memory_dependencies(
    executor: &mut Executor,
    event: InstrEvent,
    memory_record: MemoryRecord,
) {
    let memory_addr = event.b.wrapping_add(event.c);
    // Add event to ALU check to check that addr == b + c
    let add_event = InstrEvent {
        pc: UNUSED_PC,
        lookup_id: event.memory_add_lookup_id,
        opcode: Opcode::ADD,
        a: memory_addr,
        b: event.b,
        c: event.c,
        sub_lookups: executor.record.create_lookup_ids(),
        op_a_0: false,
        mem_access: None,
        memory_add_lookup_id: LookupId::default(),
        memory_sub_lookup_id: LookupId::default(),
    };
    executor.record.add_events.push(add_event);
    let addr_offset = (memory_addr % 4_u32) as u8;
    let mem_value = memory_record.value;

    if matches!(event.opcode, Opcode::LB | Opcode::LH) {
        let (unsigned_mem_val, most_sig_mem_value_byte, sign_value) = match event.opcode {
            Opcode::LB => {
                let most_sig_mem_value_byte = mem_value.to_le_bytes()[addr_offset as usize];
                let sign_value = 256;
                (most_sig_mem_value_byte as u32, most_sig_mem_value_byte, sign_value)
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
            let sub_event = InstrEvent {
                pc: UNUSED_PC,
                lookup_id: event.memory_sub_lookup_id,
                opcode: Opcode::SUB,
                a: event.a,
                b: unsigned_mem_val,
                c: sign_value,
                sub_lookups: executor.record.create_lookup_ids(),
                op_a_0: false,
                mem_access: None,
                memory_add_lookup_id: LookupId::default(),
                memory_sub_lookup_id: LookupId::default(),
            };
            executor.record.add_events.push(sub_event);
        }
    }
}

/// Emit the dependencies for CPU events.
#[allow(clippy::too_many_lines)]
pub fn emit_cpu_dependencies(executor: &mut Executor, index: usize) {
    let event = executor.record.cpu_events[index];
    let instruction = &executor.program.fetch(event.pc);

    if instruction.is_branch_instruction() {
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

        let alu_op_code = if use_signed_comparison { Opcode::SLT } else { Opcode::SLTU };
        // Add the ALU events for the comparisons
        let lt_comp_event = InstrEvent {
            pc: UNUSED_PC,
            lookup_id: event.branch_lt_lookup_id,
            opcode: alu_op_code,
            a: a_lt_b as u32,
            b: event.a,
            c: event.b,
            sub_lookups: executor.record.create_lookup_ids(),
            op_a_0: false,
            mem_access: None,
            memory_add_lookup_id: LookupId::default(),
            memory_sub_lookup_id: LookupId::default(),
        };
        let gt_comp_event = InstrEvent {
            pc: UNUSED_PC,
            lookup_id: event.branch_gt_lookup_id,
            opcode: alu_op_code,
            a: a_gt_b as u32,
            b: event.b,
            c: event.a,
            sub_lookups: executor.record.create_lookup_ids(),
            op_a_0: false,
            mem_access: None,
            memory_add_lookup_id: LookupId::default(),
            memory_sub_lookup_id: LookupId::default(),
        };
        executor.record.lt_events.push(lt_comp_event);
        executor.record.lt_events.push(gt_comp_event);
        let branching = match instruction.opcode {
            Opcode::BEQ => a_eq_b,
            Opcode::BNE => !a_eq_b,
            Opcode::BLT | Opcode::BLTU => a_lt_b,
            Opcode::BGE | Opcode::BGEU => a_eq_b || a_gt_b,
            _ => unreachable!(),
        };
        if branching {
            let next_pc = event.pc.wrapping_add(event.c);
            let add_event = InstrEvent {
                pc: UNUSED_PC,
                lookup_id: event.branch_add_lookup_id,
                opcode: Opcode::ADD,
                a: next_pc,
                b: event.pc,
                c: event.c,
                sub_lookups: executor.record.create_lookup_ids(),
                op_a_0: false,
                mem_access: None,
                memory_add_lookup_id: LookupId::default(),
                memory_sub_lookup_id: LookupId::default(),
            };
            executor.record.add_events.push(add_event);
        }
    }

    if instruction.is_jump_instruction() {
        match instruction.opcode {
            Opcode::JAL => {
                let next_pc = event.pc.wrapping_add(event.b);
                let add_event = InstrEvent {
                    pc: UNUSED_PC,
                    lookup_id: event.jump_jal_lookup_id,
                    opcode: Opcode::ADD,
                    a: next_pc,
                    b: event.pc,
                    c: event.b,
                    sub_lookups: executor.record.create_lookup_ids(),
                    op_a_0: false,
                    mem_access: None,
                    memory_add_lookup_id: LookupId::default(),
                    memory_sub_lookup_id: LookupId::default(),
                };
                executor.record.add_events.push(add_event);
            }
            Opcode::JALR => {
                let next_pc = event.b.wrapping_add(event.c);
                let add_event = InstrEvent {
                    pc: UNUSED_PC,
                    lookup_id: event.jump_jalr_lookup_id,
                    opcode: Opcode::ADD,
                    a: next_pc,
                    b: event.b,
                    c: event.c,
                    sub_lookups: executor.record.create_lookup_ids(),
                    op_a_0: false,
                    mem_access: None,
                    memory_add_lookup_id: LookupId::default(),
                    memory_sub_lookup_id: LookupId::default(),
                };
                executor.record.add_events.push(add_event);
            }
            _ => unreachable!(),
        }
    }

    if matches!(instruction.opcode, Opcode::AUIPC) {
        let add_event = InstrEvent {
            lookup_id: event.auipc_lookup_id,
            pc: UNUSED_PC,
            opcode: Opcode::ADD,
            a: event.a,
            b: event.pc,
            c: event.b,
            sub_lookups: executor.record.create_lookup_ids(),
            op_a_0: false,
            mem_access: None,
            memory_add_lookup_id: LookupId::default(),
            memory_sub_lookup_id: LookupId::default(),
        };
        executor.record.add_events.push(add_event);
    }
}
