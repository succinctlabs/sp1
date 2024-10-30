use std::hash::Hash;

use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::{Field, PrimeField32};
use p3_maybe_rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};
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
    /// The shard number.
    pub shard: u32,
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

    /// Adds a list of sharded [`ByteLookupEvent`]s to the record.
    fn add_sharded_byte_lookup_events(
        &mut self,
        sharded_blu_events_vec: Vec<&HashMap<u32, HashMap<ByteLookupEvent, usize>>>,
    );

    /// Adds a list of `ByteLookupEvent`s to the record.
    #[inline]
    fn add_byte_lookup_events(&mut self, blu_events: Vec<ByteLookupEvent>) {
        for blu_event in blu_events {
            self.add_byte_lookup_event(blu_event);
        }
    }

    /// Adds a `ByteLookupEvent` to verify `a` and `b` are indeed bytes to the shard.
    fn add_u8_range_check(&mut self, shard: u32, a: u8, b: u8) {
        self.add_byte_lookup_event(ByteLookupEvent {
            shard,
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: a,
            c: b,
        });
    }

    /// Adds a `ByteLookupEvent` to verify `a` is indeed u16.
    fn add_u16_range_check(&mut self, shard: u32, a: u16) {
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
    fn add_u8_range_checks(&mut self, shard: u32, bytes: &[u8]) {
        let mut index = 0;
        while index + 1 < bytes.len() {
            self.add_u8_range_check(shard, bytes[index], bytes[index + 1]);
            index += 2;
        }
        if index < bytes.len() {
            // If the input slice's length is odd, we need to add a check for the last byte.
            self.add_u8_range_check(shard, bytes[index], 0);
        }
    }

    /// Adds `ByteLookupEvent`s to verify that all the field elements in the input slice are indeed
    /// bytes.
    fn add_u8_range_checks_field<F: PrimeField32>(&mut self, shard: u32, field_values: &[F]) {
        self.add_u8_range_checks(
            shard,
            &field_values.iter().map(|x| x.as_canonical_u32() as u8).collect::<Vec<_>>(),
        );
    }

    /// Adds `ByteLookupEvent`s to verify that all the bytes in the input slice are indeed bytes.
    fn add_u16_range_checks(&mut self, shard: u32, ls: &[u16]) {
        ls.iter().for_each(|x| self.add_u16_range_check(shard, *x));
    }

    /// Adds a `ByteLookupEvent` to compute the bitwise OR of the two input values.
    fn lookup_or(&mut self, shard: u32, b: u8, c: u8) {
        self.add_byte_lookup_event(ByteLookupEvent {
            shard,
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
    pub fn new(shard: u32, opcode: ByteOpcode, a1: u16, a2: u8, b: u8, c: u8) -> Self {
        Self { shard, opcode, a1, a2, b, c }
    }
}

impl ByteRecord for Vec<ByteLookupEvent> {
    fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent) {
        self.push(blu_event);
    }

    fn add_sharded_byte_lookup_events(
        &mut self,
        _: Vec<&HashMap<u32, HashMap<ByteLookupEvent, usize>>>,
    ) {
        todo!()
    }
}

impl ByteRecord for HashMap<u32, HashMap<ByteLookupEvent, usize>> {
    #[inline]
    fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent) {
        self.entry(blu_event.shard)
            .or_default()
            .entry(blu_event)
            .and_modify(|e| *e += 1)
            .or_insert(1);
    }

    fn add_sharded_byte_lookup_events(
        &mut self,
        new_events: Vec<&HashMap<u32, HashMap<ByteLookupEvent, usize>>>,
    ) {
        add_sharded_byte_lookup_events(self, new_events);
    }
}

pub(crate) fn add_sharded_byte_lookup_events(
    sharded_blu_events: &mut HashMap<u32, HashMap<ByteLookupEvent, usize>>,
    new_events: Vec<&HashMap<u32, HashMap<ByteLookupEvent, usize>>>,
) {
    // new_sharded_blu_map is a map of shard -> Vec<map of byte lookup event -> multiplicities>.
    // We want to collect the new events in this format so that we can do parallel aggregation
    // per shard.
    let mut new_sharded_blu_map: HashMap<u32, Vec<&HashMap<ByteLookupEvent, usize>>> =
        HashMap::new();
    for new_sharded_blu_events in new_events {
        for (shard, new_blu_map) in new_sharded_blu_events {
            new_sharded_blu_map.entry(*shard).or_insert(Vec::new()).push(new_blu_map);
        }
    }

    // Collect all the shard numbers.
    let shards: Vec<u32> = new_sharded_blu_map.keys().copied().collect_vec();

    // Move ownership of self's per shard blu maps into a vec.  This is so that we
    // can do parallel aggregation per shard.
    let mut self_blu_maps: Vec<HashMap<ByteLookupEvent, usize>> = Vec::new();
    for shard in &shards {
        let blu = sharded_blu_events.remove(shard);

        match blu {
            Some(blu) => {
                self_blu_maps.push(blu);
            }
            None => {
                self_blu_maps.push(HashMap::new());
            }
        }
    }

    // Increment self's byte lookup events multiplicity.
    shards.par_iter().zip_eq(self_blu_maps.par_iter_mut()).for_each(|(shard, self_blu_map)| {
        let blu_map_vec = new_sharded_blu_map.get(shard).unwrap();
        for blu_map in blu_map_vec.iter() {
            for (blu_event, count) in blu_map.iter() {
                *self_blu_map.entry(*blu_event).or_insert(0) += count;
            }
        }
    });

    // Move ownership of the blu maps back to self.
    for (shard, blu) in shards.into_iter().zip(self_blu_maps.into_iter()) {
        sharded_blu_events.insert(shard, blu);
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
        assert_eq!(opcodes.len(), NUM_BYTE_OPS);
        opcodes
    }

    /// Convert the opcode to a field element.
    #[must_use]
    pub fn as_field<F: Field>(self) -> F {
        F::from_canonical_u8(self as u8)
    }
}
