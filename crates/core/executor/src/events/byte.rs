use std::hash::Hash;

use hashbrown::HashMap;
use p3_field::{Field, PrimeField32};
use serde::{Deserialize, Serialize};

use crate::{ByteOpcode, Opcode};

/// The number of different byte operations.
pub const NUM_BYTE_OPS: usize = 9;

/// Byte Lookup Event.
///
/// This object encapsulates the information needed to prove a byte lookup operation. This includes
/// the shard, opcode, operands, and other relevant information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct ByteLookupEvent {
    /// The opcode.
    pub opcode: ByteOpcode,
    /// The first operand.
    pub a1: u16,
    /// The second operand.
    pub a2: u8,
    /// The third operand.
    pub b: u8,
    /// The fourth operand.
    pub c: u8,
}

/// A type that can record byte lookup events.
pub trait ByteRecord {
    /// Adds a new [`ByteLookupEvent`] to the record.
    fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent);

    /// Adds a list of [`ByteLookupEvent`] maps to the record.
    fn add_byte_lookup_events_from_maps(
        &mut self,
        new_blu_events_vec: Vec<&HashMap<ByteLookupEvent, usize>>,
    );

    /// Adds a list of `ByteLookupEvent`s to the record.
    #[inline]
    fn add_byte_lookup_events(&mut self, blu_events: Vec<ByteLookupEvent>) {
        for blu_event in blu_events {
            self.add_byte_lookup_event(blu_event);
        }
    }

    /// Adds a `ByteLookupEvent` to verify `a` and `b` are indeed bytes to the shard.
    fn add_u8_range_check(&mut self, a: u8, b: u8) {
        self.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: a,
            c: b,
        });
    }

    /// Adds a `ByteLookupEvent` to verify `a` is indeed u16.
    fn add_u16_range_check(&mut self, a: u16) {
        self.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::U16Range,
            a1: a,
            a2: 0,
            b: 0,
            c: 0,
        });
    }

    /// Adds `ByteLookupEvent`s to verify that all the bytes in the input slice are indeed bytes.
    fn add_u8_range_checks(&mut self, bytes: &[u8]) {
        let mut index = 0;
        while index + 1 < bytes.len() {
            self.add_u8_range_check(bytes[index], bytes[index + 1]);
            index += 2;
        }
        if index < bytes.len() {
            // If the input slice's length is odd, we need to add a check for the last byte.
            self.add_u8_range_check(bytes[index], 0);
        }
    }

    /// Adds `ByteLookupEvent`s to verify that all the field elements in the input slice are indeed
    /// bytes.
    fn add_u8_range_checks_field<F: PrimeField32>(&mut self, field_values: &[F]) {
        self.add_u8_range_checks(
            &field_values.iter().map(|x| x.as_canonical_u32() as u8).collect::<Vec<_>>(),
        );
    }

    /// Adds `ByteLookupEvent`s to verify that all the bytes in the input slice are indeed bytes.
    fn add_u16_range_checks(&mut self, ls: &[u16]) {
        ls.iter().for_each(|x| self.add_u16_range_check(*x));
    }

    /// Adds a `ByteLookupEvent` to compute the bitwise OR of the two input values.
    fn lookup_or(&mut self, b: u8, c: u8) {
        self.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::OR,
            a1: (b | c) as u16,
            a2: 0,
            b,
            c,
        });
    }
}

impl ByteLookupEvent {
    /// Creates a new `ByteLookupEvent`.
    #[must_use]
    pub fn new(opcode: ByteOpcode, a1: u16, a2: u8, b: u8, c: u8) -> Self {
        Self { opcode, a1, a2, b, c }
    }
}

impl ByteRecord for Vec<ByteLookupEvent> {
    fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent) {
        self.push(blu_event);
    }

    fn add_byte_lookup_events_from_maps(&mut self, _: Vec<&HashMap<ByteLookupEvent, usize>>) {
        unimplemented!()
    }
}

impl ByteRecord for HashMap<ByteLookupEvent, usize> {
    #[inline]
    fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent) {
        self.entry(blu_event).and_modify(|e| *e += 1).or_insert(1);
    }

    fn add_byte_lookup_events_from_maps(
        &mut self,
        new_events: Vec<&HashMap<ByteLookupEvent, usize>>,
    ) {
        for new_blu_map in new_events {
            for (blu_event, count) in new_blu_map.iter() {
                *self.entry(*blu_event).or_insert(0) += count;
            }
        }
    }
}

impl From<Opcode> for ByteOpcode {
    /// Convert an opcode to a byte opcode.
    fn from(value: Opcode) -> Self {
        match value {
            Opcode::AND => Self::AND,
            Opcode::OR => Self::OR,
            Opcode::XOR => Self::XOR,
            Opcode::SLL => Self::SLL,
            _ => panic!("Invalid opcode for ByteChip: {value:?}"),
        }
    }
}

impl ByteOpcode {
    /// Get all the byte opcodes.
    #[must_use]
    pub fn all() -> Vec<Self> {
        let opcodes = vec![
            ByteOpcode::AND,
            ByteOpcode::OR,
            ByteOpcode::XOR,
            ByteOpcode::SLL,
            ByteOpcode::U8Range,
            ByteOpcode::ShrCarry,
            ByteOpcode::LTU,
            ByteOpcode::MSB,
            ByteOpcode::U16Range,
        ];
        debug_assert_eq!(opcodes.len(), NUM_BYTE_OPS);
        opcodes
    }

    /// Convert the opcode to a field element.
    #[must_use]
    pub fn as_field<F: Field>(self) -> F {
        F::from_canonical_u8(self as u8)
    }
}
