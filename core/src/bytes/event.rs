use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_maybe_rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use serde::{Deserialize, Serialize};

use super::ByteOpcode;

/// A byte lookup event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ByteLookupEvent {
    /// The shard number, used for byte lookup table.
    pub shard: u32,

    // The channel multiplicity identifier.
    pub channel: u32,

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

/// A type that can record byte lookup events.
pub trait ByteRecord {
    /// Adds a new `ByteLookupEvent` to the record.
    fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent);

    fn add_byte_lookup_events_for_shard(
        &mut self,
        blu_event_map: &mut HashMap<u32, Vec<HashMap<ByteLookupEvent, usize>>>,
    );

    fn add_byte_lookup_events_for_shard2(
        &mut self,
        blu_event_map: &mut HashMap<u32, HashMap<ByteLookupEvent, usize>>,
    );

    /// Adds a list of `ByteLookupEvent`s to the record.
    #[inline]
    fn add_byte_lookup_events(&mut self, blu_events: Vec<ByteLookupEvent>) {
        for blu_event in blu_events.into_iter() {
            self.add_byte_lookup_event(blu_event);
        }
    }

    /// Adds a `ByteLookupEvent` to verify `a` and `b are indeed bytes to the shard.
    fn add_u8_range_check(&mut self, shard: u32, channel: u32, a: u8, b: u8) {
        self.add_byte_lookup_event(ByteLookupEvent {
            shard,
            channel,
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: a as u32,
            c: b as u32,
        });
    }

    /// Adds a `ByteLookupEvent` to verify `a` is indeed u16.
    fn add_u16_range_check(&mut self, shard: u32, channel: u32, a: u32) {
        self.add_byte_lookup_event(ByteLookupEvent {
            shard,
            channel,
            opcode: ByteOpcode::U16Range,
            a1: a,
            a2: 0,
            b: 0,
            c: 0,
        });
    }

    /// Adds `ByteLookupEvent`s to verify that all the bytes in the input slice are indeed bytes.
    fn add_u8_range_checks(&mut self, shard: u32, channel: u32, bytes: &[u8]) {
        let mut index = 0;
        while index + 1 < bytes.len() {
            self.add_u8_range_check(shard, channel, bytes[index], bytes[index + 1]);
            index += 2;
        }
        if index < bytes.len() {
            // If the input slice's length is odd, we need to add a check for the last byte.
            self.add_u8_range_check(shard, channel, bytes[index], 0);
        }
    }

    /// Adds `ByteLookupEvent`s to verify that all the field elements in the input slice are indeed
    /// bytes.
    fn add_u8_range_checks_field<F: PrimeField32>(
        &mut self,
        shard: u32,
        channel: u32,
        field_values: &[F],
    ) {
        self.add_u8_range_checks(
            shard,
            channel,
            &field_values
                .iter()
                .map(|x| x.as_canonical_u32() as u8)
                .collect::<Vec<_>>(),
        );
    }

    /// Adds `ByteLookupEvent`s to verify that all the bytes in the input slice are indeed bytes.
    fn add_u16_range_checks(&mut self, shard: u32, channel: u32, ls: &[u32]) {
        ls.iter()
            .for_each(|x| self.add_u16_range_check(shard, channel, *x));
    }

    /// Adds a `ByteLookupEvent` to compute the bitwise OR of the two input values.
    fn lookup_or(&mut self, shard: u32, channel: u32, b: u8, c: u8) {
        self.add_byte_lookup_event(ByteLookupEvent {
            shard,
            channel,
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
    #[inline(always)]
    pub fn new(
        shard: u32,
        channel: u32,
        opcode: ByteOpcode,
        a1: u32,
        a2: u32,
        b: u32,
        c: u32,
    ) -> Self {
        Self {
            shard,
            channel,
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

    fn add_byte_lookup_events_for_shard(
        &mut self,
        _: &mut HashMap<u32, Vec<HashMap<ByteLookupEvent, usize>>>,
    ) {
        todo!()
    }

    fn add_byte_lookup_events_for_shard2(
        &mut self,
        blu_event_map: &mut HashMap<u32, HashMap<ByteLookupEvent, usize>>,
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

    fn add_byte_lookup_events_for_shard(
        &mut self,
        blu_event_map: &mut HashMap<u32, Vec<HashMap<ByteLookupEvent, usize>>>,
    ) {
        let shards: Vec<u32> = blu_event_map.keys().copied().collect_vec();

        let mut self_blu_maps: Vec<HashMap<ByteLookupEvent, usize>> = Vec::new();

        for shard in shards.iter() {
            let blu = self.remove(shard);

            match blu {
                Some(blu) => {
                    self_blu_maps.push(blu);
                }
                None => {
                    self_blu_maps.push(HashMap::new());
                }
            }
        }

        println!("num_shards is {}", shards.len());

        shards
            .par_iter()
            .zip_eq(self_blu_maps.par_iter_mut())
            .for_each(|(shard, self_blu_map)| {
                let blu_map_vec = blu_event_map.get(shard).unwrap();
                for blu_map in blu_map_vec.iter() {
                    for (blu_event, count) in blu_map.iter() {
                        *self_blu_map.entry(*blu_event).or_insert(0) += count;
                    }
                }
            });

        for (shard, blu) in shards.into_iter().zip(self_blu_maps.into_iter()) {
            self.insert(shard, blu);
        }
    }

    fn add_byte_lookup_events_for_shard2(
        &mut self,
        blu_event_map: &mut HashMap<u32, HashMap<ByteLookupEvent, usize>>,
    ) {
        let shards: Vec<u32> = blu_event_map.keys().copied().collect_vec();

        let mut self_blu_maps: Vec<HashMap<ByteLookupEvent, usize>> = Vec::new();

        for shard in shards.iter() {
            let blu = self.remove(shard);

            match blu {
                Some(blu) => {
                    self_blu_maps.push(blu);
                }
                None => {
                    self_blu_maps.push(HashMap::new());
                }
            }
        }

        println!("num_shards is {}", shards.len());

        shards
            .par_iter()
            .zip_eq(self_blu_maps.par_iter_mut())
            .for_each(|(shard, self_blu_map)| {
                let blu_map = blu_event_map.get(shard).unwrap();
                for (blu_event, count) in blu_map.iter() {
                    *self_blu_map.entry(*blu_event).or_insert(0) += count;
                }
            });

        for (shard, blu) in shards.into_iter().zip(self_blu_maps.into_iter()) {
            self.insert(shard, blu);
        }
    }
}
