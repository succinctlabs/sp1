use crate::alu::{create_alu_lookups, AluEvent};
use crate::runtime::{Opcode, Runtime};

/// Returns `true` if the given `opcode` is a signed operation.
pub fn is_signed_operation(opcode: Opcode) -> bool {
    opcode == Opcode::DIV || opcode == Opcode::REM
}

/// Calculate the correct `quotient` and `remainder` for the given `b` and `c` per RISC-V spec.
pub fn get_quotient_and_remainder(b: u32, c: u32, opcode: Opcode) -> (u32, u32) {
    if c == 0 {
        // When c is 0, the quotient is 2^32 - 1 and the remainder is b regardless of whether we
        // perform signed or unsigned division.
        (u32::MAX, b)
    } else if is_signed_operation(opcode) {
        (
            (b as i32).wrapping_div(c as i32) as u32,
            (b as i32).wrapping_rem(c as i32) as u32,
        )
    } else {
        (
            (b as u32).wrapping_div(c as u32) as u32,
            (b as u32).wrapping_rem(c as u32) as u32,
        )
    }
}

/// Calculate the most significant bit of the given 32-bit integer `a`, and returns it as a u8.
pub const fn get_msb(a: u32) -> u8 {
    ((a >> 31) & 1) as u8
}

/// Emits the dependencies for division and remainder operations.
pub fn emit_dependencies(runtime: &mut Runtime, event: AluEvent) {
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
        runtime.record.add_events.push(AluEvent {
            lookup_id: event.sub_lookups[4],
            shard: event.shard,
            channel: event.channel,
            clk: event.clk,
            opcode: Opcode::ADD,
            a: 0,
            b: event.c,
            c: (event.c as i32).abs() as u32,
            sub_lookups: create_alu_lookups(),
        });
    }
    if rem_neg == 1 {
        runtime.record.add_events.push(AluEvent {
            lookup_id: event.sub_lookups[5],
            shard: event.shard,
            channel: event.channel,
            clk: event.clk,
            opcode: Opcode::ADD,
            a: 0,
            b: remainder,
            c: (remainder as i32).abs() as u32,
            sub_lookups: create_alu_lookups(),
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

    let lower_multiplication = AluEvent {
        lookup_id: event.sub_lookups[0],
        shard: event.shard,
        channel: event.channel,
        clk: event.clk,
        opcode: Opcode::MUL,
        a: lower_word,
        c: event.c,
        b: quotient,
        sub_lookups: create_alu_lookups(),
    };
    runtime.record.mul_events.push(lower_multiplication);

    let upper_multiplication = AluEvent {
        lookup_id: event.sub_lookups[1],
        shard: event.shard,
        channel: event.channel,
        clk: event.clk,
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
        sub_lookups: create_alu_lookups(),
    };
    runtime.record.mul_events.push(upper_multiplication);

    let lt_event = if is_signed_operation {
        AluEvent {
            lookup_id: event.sub_lookups[2],
            shard: event.shard,
            channel: event.channel,
            opcode: Opcode::SLTU,
            a: 1,
            b: (remainder as i32).abs() as u32,
            c: u32::max(1, (event.c as i32).abs() as u32),
            clk: event.clk,
            sub_lookups: create_alu_lookups(),
        }
    } else {
        AluEvent {
            lookup_id: event.sub_lookups[3],
            shard: event.shard,
            channel: event.channel,
            opcode: Opcode::SLTU,
            a: 1,
            b: remainder,
            c: u32::max(1, event.c),
            clk: event.clk,
            sub_lookups: create_alu_lookups(),
        }
    };

    if event.c != 0 {
        runtime.record.lt_events.push(lt_event);
    }
}
