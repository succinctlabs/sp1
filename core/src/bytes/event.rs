use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::ByteOpcode;

/// A byte lookup event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ByteLookupEvent {
    /// The shard number, used for byte lookup table.
    pub shard: u32,

    /// The opcode of the operation.
    pub opcode: ByteOpcode,

    /// The first output operand.
    pub a1: u32,

    /// The second output operand.
    pub a2: u32,

    /// The first input operand.
    pub b: u32,

    /// The second input operand.
    pub c: u32,
}

pub trait ByteRecord {
    fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent);

    fn add_byte_lookup_events(&mut self, blu_events: Vec<ByteLookupEvent>) {
        for blu_event in blu_events.iter() {
            self.add_byte_lookup_event(*blu_event);
        }
    }

    /// Adds a `ByteLookupEvent` to verify `a` and `b are indeed bytes to the shard.
    fn add_u8_range_check(&mut self, shard: u32, a: u8, b: u8) {
        self.add_byte_lookup_event(ByteLookupEvent {
            shard,
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: a as u32,
            c: b as u32,
        });
    }

    /// Adds a `ByteLookupEvent` to verify `a` is indeed u16.
    fn add_u16_range_check(&mut self, shard: u32, a: u32) {
        self.add_byte_lookup_event(ByteLookupEvent {
            shard,
            opcode: ByteOpcode::U16Range,
            a1: a,
            a2: 0,
            b: 0,
            c: 0,
        });
    }

    /// Adds `ByteLookupEvent`s to verify that all the bytes in the input slice are indeed bytes.
    fn add_u8_range_checks(&mut self, shard: u32, ls: &[u8]) {
        let mut index = 0;
        while index + 1 < ls.len() {
            self.add_u8_range_check(shard, ls[index], ls[index + 1]);
            index += 2;
        }
        if index < ls.len() {
            // If the input slice's length is odd, we need to add a check for the last byte.
            self.add_u8_range_check(shard, ls[index], 0);
        }
    }

    /// Adds `ByteLookupEvent`s to verify that all the bytes in the input slice are indeed bytes.
    fn add_u16_range_checks(&mut self, shard: u32, ls: &[u32]) {
        ls.iter().for_each(|x| self.add_u16_range_check(shard, *x));
    }

    /// Adds a `ByteLookupEvent` to compute the bitwise OR of the two input values.
    fn lookup_or(&mut self, shard: u32, b: u8, c: u8) {
        self.add_byte_lookup_event(ByteLookupEvent {
            shard,
            opcode: ByteOpcode::OR,
            a1: (b | c) as u32,
            a2: 0,
            b: b as u32,
            c: c as u32,
        });
    }
}

impl ByteLookupEvent {
    /// Creates a new `ByteLookupEvent`.
    pub fn new(shard: u32, opcode: ByteOpcode, a1: u32, a2: u32, b: u32, c: u32) -> Self {
        Self {
            shard,
            opcode,
            a1,
            a2,
            b,
            c,
        }
    }
}

impl ByteRecord for Vec<ByteLookupEvent> {
    fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent) {
        self.push(blu_event);
    }
}

impl ByteRecord for BTreeMap<u32, BTreeMap<ByteLookupEvent, usize>> {
    fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent) {
        *self
            .entry(blu_event.shard)
            .or_default()
            .entry(blu_event)
            .or_insert(0) += 1
    }
}
