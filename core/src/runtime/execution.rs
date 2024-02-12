use std::collections::HashMap;

use crate::{
    alu::AluEvent,
    bytes::{ByteLookupEvent, ByteOpcode},
};

use super::Opcode;

pub trait Execute<H> {
    fn execute(&self, host: &mut H);
}

pub trait Host {
    fn add_alu_events(&mut self, alu_events: HashMap<Opcode, Vec<AluEvent>>);

    fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent);

    fn add_byte_lookup_events(&mut self, blu_events: Vec<ByteLookupEvent>) {
        for blu_event in blu_events.iter() {
            self.add_byte_lookup_event(*blu_event);
        }
    }

    /// Adds a `ByteLookupEvent` to verify `a` and `b are indeed bytes to the shard.
    fn add_u8_range_check(&mut self, a: u8, b: u8) {
        self.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: a as u32,
            c: b as u32,
        });
    }

    /// Adds a `ByteLookupEvent` to verify `a` is indeed u16.
    fn add_u16_range_check(&mut self, a: u32) {
        self.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::U16Range,
            a1: a,
            a2: 0,
            b: 0,
            c: 0,
        });
    }

    /// Adds `ByteLookupEvent`s to verify that all the bytes in the input slice are indeed bytes.
    fn add_u8_range_checks(&mut self, ls: &[u8]) {
        let mut index = 0;
        while index + 1 < ls.len() {
            self.add_u8_range_check(ls[index], ls[index + 1]);
            index += 2;
        }
        if index < ls.len() {
            // If the input slice's length is odd, we need to add a check for the last byte.
            self.add_u8_range_check(ls[index], 0);
        }
    }

    /// Adds `ByteLookupEvent`s to verify that all the bytes in the input slice are indeed bytes.
    fn add_u16_range_checks(&mut self, ls: &[u32]) {
        ls.iter().for_each(|x| self.add_u16_range_check(*x));
    }

    /// Adds a `ByteLookupEvent` to compute the bitwise OR of the two input values.
    fn lookup_or(&mut self, b: u8, c: u8) {
        self.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::OR,
            a1: (b | c) as u32,
            a2: 0,
            b: b as u32,
            c: c as u32,
        });
    }
}
