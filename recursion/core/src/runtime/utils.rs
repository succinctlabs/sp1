use p3_field::PrimeField32;

use crate::range_check::{RangeCheckEvent, RangeCheckOpcode};

use super::{Instruction, Opcode, HEAP_PTR, HEAP_START_ADDRESS};

pub fn canonical_i32_to_field<F: PrimeField32>(x: i32) -> F {
    let modulus = F::ORDER_U32;
    assert!(x < modulus as i32 && x >= -(modulus as i32));
    if x < 0 {
        -F::from_canonical_u32((-x) as u32)
    } else {
        F::from_canonical_u32(x as u32)
    }
}

pub fn get_heap_size_range_check_events<F: PrimeField32>(
    end_heap_address: F,
) -> (RangeCheckEvent, RangeCheckEvent) {
    let heap_size =
        (end_heap_address - F::from_canonical_usize(HEAP_START_ADDRESS)).as_canonical_u32();
    let diff_16bit_limb = heap_size & 0xffff;
    let diff_12bit_limb = (heap_size >> 16) & 0xfff;

    (
        RangeCheckEvent::new(RangeCheckOpcode::U16, diff_16bit_limb as u16),
        RangeCheckEvent::new(RangeCheckOpcode::U12, diff_12bit_limb as u16),
    )
}

pub fn instruction_is_heap_expand<F: PrimeField32>(instruction: &Instruction<F>) -> bool {
    instruction.opcode == Opcode::ADD && instruction.op_a == canonical_i32_to_field(HEAP_PTR)
}
