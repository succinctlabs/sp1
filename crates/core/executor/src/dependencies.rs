use crate::{
    events::AluEvent,
    utils::{get_msb, get_quotient_and_remainder, is_signed_operation},
    Executor, Opcode,
};

/// Helper function to create an ALU event
fn create_alu_event(
    lookup_id: u32,
    shard: u32,
    clk: u32,
    opcode: Opcode,
    a: u32,
    b: u32,
    c: u32,
    executor: &mut Executor,
) -> AluEvent {
    AluEvent {
        lookup_id,
        shard,
        clk,
        opcode,
        a,
        b,
        c,
        sub_lookups: executor.record.create_lookup_ids(),
    }
}

/// Helper function for memory operations
fn handle_memory_operation(
    instruction: Opcode,
    mem_value: u32,
    addr_offset: u8,
    shard: u32,
    clk: u32,
    event: &AluEvent,
    executor: &mut Executor,
) {
    let (unsigned_mem_val, most_sig_mem_value_byte, sign_value) = match instruction {
        Opcode::LB => {
            let byte = mem_value.to_le_bytes()[addr_offset as usize];
            (byte as u32, byte, 256)
        }
        Opcode::LH => {
            let unsigned_mem_val = match (addr_offset >> 1) % 2 {
                0 => mem_value & 0x0000FFFF,
                1 => (mem_value & 0xFFFF0000) >> 16,
                _ => unreachable!(),
            };
            let most_sig_mem_value_byte = unsigned_mem_val.to_le_bytes()[1];
            (unsigned_mem_val, most_sig_mem_value_byte, 65536)
        }
        _ => unreachable!(),
    };

    // Trigger sub event if the most significant byte has a negative sign
    if most_sig_mem_value_byte >> 7 & 0x01 == 1 {
        let sub_event = create_alu_event(
            event.memory_sub_lookup_id,
            shard,
            clk,
            Opcode::SUB,
            event.a,
            unsigned_mem_val,
            sign_value,
            executor,
        );
        executor.record.add_events.push(sub_event);
    }
}

/// Handles dependencies for division and remainder operations
pub fn emit_divrem_dependencies(executor: &mut Executor, event: AluEvent) {
    let shard = executor.shard();
    let (quotient, remainder) = get_quotient_and_remainder(event.b, event.c, event.opcode);
    let c_msb = get_msb(event.c);
    let rem_msb = get_msb(remainder);
    let is_signed = is_signed_operation(event.opcode);

    // Flags for negative values based on sign
    let (mut c_neg, mut rem_neg) = (0, 0);
    if is_signed {
        c_neg = c_msb;
        rem_neg = rem_msb;
    }

    // Handling negative c and remainder values
    if c_neg == 1 {
        executor.record.add_events.push(create_alu_event(
            event.sub_lookups[4],
            shard,
            event.clk,
            Opcode::ADD,
            0,
            event.c,
            (event.c as i32).unsigned_abs(),
            executor,
        ));
    }

    if rem_neg == 1 {
        executor.record.add_events.push(create_alu_event(
            event.sub_lookups[5],
            shard,
            event.clk,
            Opcode::ADD,
            0,
            remainder,
            (remainder as i32).unsigned_abs(),
            executor,
        ));
    }

    // Calculate c * quotient
    let c_times_quotient = if is_signed {
        (((quotient as i32) as i64) * ((event.c as i32) as i64)).to_le_bytes()
    } else {
        ((quotient as u64) * (event.c as u64)).to_le_bytes()
    };

    let lower_word = u32::from_le_bytes(c_times_quotient[0..4].try_into().unwrap());
    let upper_word = u32::from_le_bytes(c_times_quotient[4..8].try_into().unwrap());

    // Create multiplication events
    executor.record.mul_events.push(AluEvent {
        lookup_id: event.sub_lookups[0],
        shard,
        clk: event.clk,
        opcode: Opcode::MUL,
        a: lower_word,
        b: quotient,
        c: event.c,
        sub_lookups: executor.record.create_lookup_ids(),
    });

    executor.record.mul_events.push(AluEvent {
        lookup_id: event.sub_lookups[1],
        shard,
        clk: event.clk,
        opcode: if is_signed { Opcode::MULH } else { Opcode::MULHU },
        a: upper_word,
        b: quotient,
        c: event.c,
        sub_lookups: executor.record.create_lookup_ids(),
    });

    // Create LT event for comparison
    let lt_event = create_alu_event(
        if is_signed {
            event.sub_lookups[2]
        } else {
            event.sub_lookups[3]
        },
        shard,
        event.clk,
        Opcode::SLTU,
        1,
        remainder,
        u32::max(1, event.c),
        executor,
    );

    if event.c != 0 {
        executor.record.lt_events.push(lt_event);
    }
}

/// Handles dependencies for CPU events
pub fn emit_cpu_dependencies(executor: &mut Executor, index: usize) {
    let event = executor.record.cpu_events[index];
    let shard = executor.shard();
    let instruction = &executor.program.fetch(event.pc);

    if matches!(
        instruction.opcode,
        Opcode::LB | Opcode::LH | Opcode::LW | Opcode::LBU | Opcode::LHU
        | Opcode::SB | Opcode::SH | Opcode::SW
    ) {
        let memory_addr = event.b.wrapping_add(event.c);
        
        // Create add event to validate address
        executor.record.add_events.push(create_alu_event(
            event.memory_add_lookup_id,
            shard,
            event.clk,
            Opcode::ADD,
            memory_addr,
            event.b,
            event.c,
            executor,
        ));

        // Handle memory operations
        let addr_offset = (memory_addr % 4_u32) as u8;
        if let Some(mem_value) = event.memory_record.as_ref().map(|record| record.value()) {
            handle_memory_operation(instruction.opcode, mem_value, addr_offset, shard, event.clk, &event, executor);
        }
    }

    // Branch instructions handling
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

        // Create comparison events
        executor.record.lt_events.push(create_alu_event(
            event.branch_lt_lookup_id,
            shard,
            event.clk,
            alu_op_code,
            a_lt_b as u32,
            event.a,
            event.b,
            executor,
        ));
        executor.record.lt_events.push(create_alu_event(
            event.branch_gt_lookup_id,
            shard,
            event.clk,
            alu_op_code,
            a_gt_b as u32,
            event.b,
            event.a,
            executor,
        ));

        // Evaluate branch condition
        let branching = match instruction.opcode {
            Opcode::BEQ => a_eq_b,
            Opcode::BNE => !a_eq_b,
            Opcode::BLT | Opcode::BLTU => a_lt_b,
            Opcode::BGE | Opcode::BGEU => a_eq_b || a_gt_b,
            _ => unreachable!(),
        };

        if branching {
            let next_pc = event.pc.wrapping_add(event.c);
            executor.record.add_events.push(create_alu_event(
                event.branch_add_lookup_id,
                shard,
                event.clk,
                Opcode::ADD,
                next_pc,
                event.pc,
                event.c,
                executor,
            ));
        }
    }

    // Jump instructions handling
    if instruction.is_jump_instruction() {
        match instruction.opcode {
            Opcode::JAL => {
                let next_pc = event.pc.wrapping_add(event.b);
                executor.record.add_events.push(create_alu_event(
                    event.jump_jal_lookup_id,
                    shard,
                    event.clk,
                    Opcode::ADD,
                    next_pc,
                    event.pc,
                    event.b,
                    executor,
                ));
            }
            Opcode::JALR => {
                let next_pc = event.b.wrapping_add(event.c);
                executor.record.add_events.push(create_alu_event(
                    event.jump_jalr_lookup_id,
                    shard,
                    event.clk,
                    Opcode::ADD,
                    next_pc,
                    event.pc,
                    event.c,
                    executor,
                ));
            }
            _ => unreachable!(),
        }
    }

    // AUIPC instruction handling
    if instruction.opcode == Opcode::AUIPC {
        executor.record.add_events.push(create_alu_event(
            event.auipc_lookup_id,
            shard,
            event.clk,
            Opcode::ADD,
            event.a,
            event.pc,
            event.b,
            executor,
        ));
    }
}
