use crate::{
    events::AluEvent,
    utils::{get_msb, get_quotient_and_remainder, is_signed_operation},
    Executor, Opcode,
};

/// Emits the dependencies for division and remainder operations.
/// This function handles both signed and unsigned division operations by:
/// 1. Computing quotient and remainder
/// 2. Handling sign conversions for signed operations
/// 3. Generating multiplication verification events
/// 4. Adding comparison events for remainder validation
#[allow(clippy::too_many_lines)]
pub fn emit_divrem_dependencies(executor: &mut Executor, event: AluEvent) {
    let shard = executor.shard();
    let (quotient, remainder) = get_quotient_and_remainder(event.b, event.c, event.opcode);
    let divisor_msb = get_msb(event.c);
    let remainder_msb = get_msb(remainder);
    let mut divisor_is_negative = 0;
    let mut remainder_is_negative = 0;
    let is_signed_operation = is_signed_operation(event.opcode);
    
    if is_signed_operation {
        divisor_is_negative = divisor_msb;
        remainder_is_negative = remainder_msb;
    }

    // Handle negative divisor conversion
    if divisor_is_negative == 1 {
        let ids = executor.record.create_lookup_ids();
        executor.record.add_events.push(AluEvent {
            lookup_id: event.sub_lookups[4],
            shard,
            clk: event.clk,
            opcode: Opcode::ADD,
            a: 0,
            b: event.c,
            c: (event.c as i32).unsigned_abs(),
            sub_lookups: ids,
        });
    }

    // Handle negative remainder conversion
    if remainder_is_negative == 1 {
        let ids = executor.record.create_lookup_ids();
        executor.record.add_events.push(AluEvent {
            lookup_id: event.sub_lookups[5],
            shard,
            clk: event.clk,
            opcode: Opcode::ADD,
            a: 0,
            b: remainder,
            c: (remainder as i32).unsigned_abs(),
            sub_lookups: ids,
        });
    }

    // Calculate quotient * divisor for verification
    let quotient_times_divisor = {
        if is_signed_operation {
            (((quotient as i32) as i64) * ((event.c as i32) as i64)).to_le_bytes()
        } else {
            ((quotient as u64) * (event.c as u64)).to_le_bytes()
        }
    };
    let lower_word = u32::from_le_bytes(quotient_times_divisor[0..4].try_into().unwrap());
    let upper_word = u32::from_le_bytes(quotient_times_divisor[4..8].try_into().unwrap());

    // Verify lower 32 bits of multiplication
    let lower_multiplication = AluEvent {
        lookup_id: event.sub_lookups[0],
        shard,
        clk: event.clk,
        opcode: Opcode::MUL,
        a: lower_word,
        c: event.c,
        b: quotient,
        sub_lookups: executor.record.create_lookup_ids(),
    };
    executor.record.mul_events.push(lower_multiplication);

    // Verify upper 32 bits of multiplication
    let upper_multiplication = AluEvent {
        lookup_id: event.sub_lookups[1],
        shard,
        clk: event.clk,
        opcode: if is_signed_operation { Opcode::MULH } else { Opcode::MULHU },
        a: upper_word,
        c: event.c,
        b: quotient,
        sub_lookups: executor.record.create_lookup_ids(),
    };
    executor.record.mul_events.push(upper_multiplication);

    // Verify remainder is less than divisor
    let remainder_lt_divisor = if is_signed_operation {
        AluEvent {
            lookup_id: event.sub_lookups[2],
            shard,
            opcode: Opcode::SLTU,
            a: 1,
            b: (remainder as i32).unsigned_abs(),
            c: u32::max(1, (event.c as i32).unsigned_abs()),
            clk: event.clk,
            sub_lookups: executor.record.create_lookup_ids(),
        }
    } else {
        AluEvent {
            lookup_id: event.sub_lookups[3],
            shard,
            opcode: Opcode::SLTU,
            a: 1,
            b: remainder,
            c: u32::max(1, event.c),
            clk: event.clk,
            sub_lookups: executor.record.create_lookup_ids(),
        }
    };

    if event.c != 0 {
        executor.record.lt_events.push(remainder_lt_divisor);
    }
}

/// Emit the dependencies for CPU events.
/// This function handles various CPU instruction types and their dependencies:
/// - Memory operations (load/store)
/// - Branch instructions
/// - Jump instructions
/// - AUIPC instruction
/// 
/// For each instruction type, it generates the necessary verification events
/// to ensure correct execution.
#[allow(clippy::too_many_lines)]
pub fn emit_cpu_dependencies(executor: &mut Executor, index: usize) {
    let event = executor.record.cpu_events[index];
    let shard = executor.shard();
    let instruction = &executor.program.fetch(event.pc);

    // Handle memory operations (load/store)
    if matches!(
        instruction.opcode,
        Opcode::LB
            | Opcode::LH
            | Opcode::LW
            | Opcode::LBU
            | Opcode::LHU
            | Opcode::SB
            | Opcode::SH
            | Opcode::SW
    ) {
        emit_memory_dependencies(executor, event, instruction);
    }

    // Handle branch instructions
    if instruction.is_branch_instruction() {
        emit_branch_dependencies(executor, event, instruction);
    }

    // Handle jump instructions
    if instruction.is_jump_instruction() {
        emit_jump_dependencies(executor, event, instruction);
    }

    // Handle AUIPC instruction
    if matches!(instruction.opcode, Opcode::AUIPC) {
        emit_auipc_dependencies(executor, event);
    }
}

/// Helper function to emit memory operation dependencies
fn emit_memory_dependencies(executor: &mut Executor, event: AluEvent, instruction: &Instruction) {
    let shard = executor.shard();
    let memory_addr = event.b.wrapping_add(event.c);
    
    // Verify memory address calculation
    let add_event = AluEvent {
        lookup_id: event.memory_add_lookup_id,
        shard,
        clk: event.clk,
        opcode: Opcode::ADD,
        a: memory_addr,
        b: event.b,
        c: event.c,
        sub_lookups: executor.record.create_lookup_ids(),
    };
    executor.record.add_events.push(add_event);

    let addr_offset = (memory_addr % 4_u32) as u8;
    let mem_value = event.memory_record.unwrap().value();

    // Handle sign extension for load byte/halfword
    if matches!(instruction.opcode, Opcode::LB | Opcode::LH) {
        let (unsigned_mem_val, most_sig_mem_value_byte, sign_value) = match instruction.opcode {
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
            let sub_event = AluEvent {
                lookup_id: event.memory_sub_lookup_id,
                shard,
                clk: event.clk,
                opcode: Opcode::SUB,
                a: event.a,
                b: unsigned_mem_val,
                c: sign_value,
                sub_lookups: executor.record.create_lookup_ids(),
            };
            executor.record.add_events.push(sub_event);
        }
    }
}

/// Helper function to emit branch instruction dependencies
fn emit_branch_dependencies(executor: &mut Executor, event: AluEvent, instruction: &Instruction) {
    let shard = executor.shard();
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
    
    // Add comparison events
    let lt_comp_event = AluEvent {
        lookup_id: event.branch_lt_lookup_id,
        shard,
        clk: event.clk,
        opcode: alu_op_code,
        a: a_lt_b as u32,
        b: event.a,
        c: event.b,
        sub_lookups: executor.record.create_lookup_ids(),
    };
    let gt_comp_event = AluEvent {
        lookup_id: event.branch_gt_lookup_id,
        shard,
        clk: event.clk,
        opcode: alu_op_code,
        a: a_gt_b as u32,
        b: event.b,
        c: event.a,
        sub_lookups: executor.record.create_lookup_ids(),
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
        let add_event = AluEvent {
            lookup_id: event.branch_add_lookup_id,
            shard,
            clk: event.clk,
            opcode: Opcode::ADD,
            a: next_pc,
            b: event.pc,
            c: event.c,
            sub_lookups: executor.record.create_lookup_ids(),
        };
        executor.record.add_events.push(add_event);
    }
}

/// Helper function to emit jump instruction dependencies
fn emit_jump_dependencies(executor: &mut Executor, event: AluEvent, instruction: &Instruction) {
    let shard = executor.shard();
    match instruction.opcode {
        Opcode::JAL => {
            let next_pc = event.pc.wrapping_add(event.b);
            let add_event = AluEvent {
                lookup_id: event.jump_jal_lookup_id,
                shard,
                clk: event.clk,
                opcode: Opcode::ADD,
                a: next_pc,
                b: event.pc,
                c: event.b,
                sub_lookups: executor.record.create_lookup_ids(),
            };
            executor.record.add_events.push(add_event);
        }
        Opcode::JALR => {
            let next_pc = event.b.wrapping_add(event.c);
            let add_event = AluEvent {
                lookup_id: event.jump_jalr_lookup_id,
                shard,
                clk: event.clk,
                opcode: Opcode::ADD,
                a: next_pc,
                b: event.b,
                c: event.c,
                sub_lookups: executor.record.create_lookup_ids(),
            };
            executor.record.add_events.push(add_event);
        }
        _ => unreachable!(),
    }
}

/// Helper function to emit AUIPC instruction dependencies
fn emit_auipc_dependencies(executor: &mut Executor, event: AluEvent) {
    let shard = executor.shard();
    let add_event = AluEvent {
        lookup_id: event.auipc_lookup_id,
        shard,
        clk: event.clk,
        opcode: Opcode::ADD,
        a: event.a,
        b: event.pc,
        c: event.b,
        sub_lookups: executor.record.create_lookup_ids(),
    };
    executor.record.add_events.push(add_event);
}
