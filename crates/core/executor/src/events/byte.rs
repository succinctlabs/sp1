use std::hash::{Hash, Hasher};

use deepsize2::DeepSizeOf;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use slop_algebra::{Field, PrimeField32};

use crate::{ByteOpcode, Opcode};

/// The number of different byte operations.
pub const NUM_BYTE_OPS: usize = 6;

/// Byte Lookup Event.
///
/// This object encapsulates the information needed to prove a byte lookup operation. This includes
/// the shard, opcode, operands, and other relevant information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, DeepSizeOf)]
pub struct ByteLookupEvent {
    /// The opcode.
    pub opcode: ByteOpcode,
    /// The first operand.
    pub a: u16,
    /// The second operand.
    pub b: u8,
    /// The third operand.
    pub c: u8,
}

impl Hash for ByteLookupEvent {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        // All four fields fit in one machine word.
        let key = (self.opcode as u64) << 32
            | u64::from(self.a) << 16
            | u64::from(self.b) << 8
            | u64::from(self.c);
        state.write_u64(key);
    }
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
            a: 0,
            b: a,
            c: b,
        });
    }

    /// Adds a `ByteLookupEvent` to verify `a` is indeed u16.
    fn add_u16_range_check(&mut self, a: u16) {
        self.add_byte_lookup_event(ByteLookupEvent { opcode: ByteOpcode::Range, a, b: 16, c: 0 });
    }

    /// Adds a `ByteLookupEvent` to verify `a` is less than `2^b`.
    fn add_bit_range_check(&mut self, a: u16, b: u8) {
        self.add_byte_lookup_event(ByteLookupEvent { opcode: ByteOpcode::Range, a, b, c: 0 });
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
        for pair in field_values.chunks_exact(2) {
            self.add_u8_range_check(
                pair[0].as_canonical_u32() as u8,
                pair[1].as_canonical_u32() as u8,
            );
        }
        if field_values.len() % 2 != 0 {
            self.add_u8_range_check(
                field_values[field_values.len() - 1].as_canonical_u32() as u8,
                0,
            );
        }
    }

    /// Adds `ByteLookupEvent`s to verify that all the bytes in the input slice are indeed u16s.
    fn add_u16_range_checks(&mut self, ls: &[u16]) {
        for x in ls.iter() {
            self.add_u16_range_check(*x);
        }
    }

    /// Adds `ByteLookupEvent`s to verify that all the field elements in the input slice are indeed
    /// u16 values.
    fn add_u16_range_checks_field<F: PrimeField32>(&mut self, field_values: &[F]) {
        for x in field_values.iter() {
            self.add_u16_range_check(x.as_canonical_u32() as u16);
        }
    }

    /// Adds a `ByteLookupEvent` to compute the bitwise OR of the two input values.
    fn lookup_or(&mut self, b: u8, c: u8) {
        self.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::OR,
            a: (b | c) as u16,
            b,
            c,
        });
    }
}

impl ByteLookupEvent {
    /// Creates a new `ByteLookupEvent`.
    #[must_use]
    pub fn new(opcode: ByteOpcode, a: u16, b: u8, c: u8) -> Self {
        Self { opcode, a, b, c }
    }
}

/// Counts a batch of trace dependencies. Common byte operations are indexed by
/// their two inputs and range checks by their value and bit width.
#[derive(Default)]
pub struct ByteCounters<const DENSE: bool> {
    ranges: Vec<usize>,
    touched: Vec<(ByteLookupEvent, usize)>,
    other: HashMap<ByteLookupEvent, usize>,
}

thread_local! {
    static RANGE_COUNTS: std::cell::RefCell<Vec<usize>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Tracks only the touched slots for small batches.
pub type ByteLookupCounts = ByteCounters<false>;

/// Counts SHA batches directly in contiguous tables that can be merged in bulk.
pub type DenseByteLookupCounts = ByteCounters<true>;

impl<const DENSE: bool> ByteCounters<DENSE> {
    #[cold]
    fn grow(&mut self, index: usize) {
        if self.ranges.is_empty() {
            self.ranges = RANGE_COUNTS.take();
        }
        if index >= self.ranges.len() {
            self.ranges.resize((index | 0xffff) + 1, 0);
        }
    }

    #[inline(always)]
    fn increment(&mut self, event: ByteLookupEvent, index: usize) {
        if index >= self.ranges.len() {
            self.grow(index);
        }
        let count = &mut self.ranges[index];
        if !DENSE && *count == 0 {
            self.touched.push((event, index));
        }
        *count += 1;
    }

    /// Combine worker-local counts by table index before updating the shard's map.
    pub fn merge(mut self, mut other: Self) -> Self {
        if self.touched.len() < other.touched.len() {
            std::mem::swap(&mut self, &mut other);
        }
        if self.ranges.len() < other.ranges.len() {
            self.ranges.resize(other.ranges.len(), 0);
        }
        if DENSE {
            for (dst, src) in self.ranges.iter_mut().zip(&mut other.ranges) {
                *dst += std::mem::take(src);
            }
        } else {
            for (event, index) in other.touched {
                if self.ranges[index] == 0 {
                    self.touched.push((event, index));
                }
                self.ranges[index] += std::mem::take(&mut other.ranges[index]);
            }
        }
        for (event, count) in other.other {
            *self.other.entry(event).or_default() += count;
        }
        if !other.ranges.is_empty() {
            RANGE_COUNTS.set(other.ranges);
        }
        self
    }

    /// Return the nonzero counts and recycle the cleared range tables on this worker.
    pub fn finish(mut self) -> Vec<(ByteLookupEvent, usize)> {
        let mut result = Vec::with_capacity(self.other.len() + self.touched.len());
        result.extend(self.other);
        if DENSE {
            for (index, count) in self.ranges.iter_mut().enumerate() {
                if *count == 0 {
                    continue;
                }
                let value = index as u16;
                let [b, c] = value.to_be_bytes();
                let event = match index >> 16 {
                    0 => ByteLookupEvent::new(ByteOpcode::U8Range, 0, b, c),
                    1 => ByteLookupEvent::new(ByteOpcode::Range, value, 16, 0),
                    2 => {
                        let slot = u32::from(value) + 1;
                        let bits = slot.ilog2();
                        ByteLookupEvent::new(
                            ByteOpcode::Range,
                            (slot - (1 << bits)) as u16,
                            bits as u8,
                            0,
                        )
                    }
                    3 => ByteLookupEvent::new(ByteOpcode::AND, u16::from(b & c), b, c),
                    4 => ByteLookupEvent::new(ByteOpcode::OR, u16::from(b | c), b, c),
                    5 => ByteLookupEvent::new(ByteOpcode::XOR, u16::from(b ^ c), b, c),
                    _ => unreachable!(),
                };
                result.push((event, std::mem::take(count)));
            }
        } else {
            result.extend(
                self.touched
                    .into_iter()
                    .map(|(event, i)| (event, std::mem::take(&mut self.ranges[i]))),
            );
        }
        if !self.ranges.is_empty() {
            RANGE_COUNTS.set(self.ranges);
        }
        result
    }
}

impl<const DENSE: bool> ByteRecord for ByteCounters<DENSE> {
    #[inline]
    fn add_u8_range_check(&mut self, b: u8, c: u8) {
        self.increment(
            ByteLookupEvent::new(ByteOpcode::U8Range, 0, b, c),
            (usize::from(b) << 8) | usize::from(c),
        );
    }

    #[inline]
    fn add_u16_range_check(&mut self, a: u16) {
        self.increment(
            ByteLookupEvent::new(ByteOpcode::Range, a, 16, 0),
            (1 << 16) | usize::from(a),
        );
    }

    #[inline]
    fn add_bit_range_check(&mut self, a: u16, bits: u8) {
        let event = ByteLookupEvent::new(ByteOpcode::Range, a, bits, 0);
        if bits == 16 {
            self.add_u16_range_check(a);
        } else if bits < 16 && u32::from(a) < (1u32 << bits) {
            self.increment(event, (2 << 16) + (1usize << bits) - 1 + usize::from(a));
        } else {
            *self.other.entry(event).or_default() += 1;
        }
    }

    #[inline]
    fn add_byte_lookup_event(&mut self, event: ByteLookupEvent) {
        match event {
            ByteLookupEvent { opcode: ByteOpcode::U8Range, a: 0, b, c } => {
                self.add_u8_range_check(b, c)
            }
            ByteLookupEvent { opcode: ByteOpcode::Range, a, b, c: 0 } => {
                self.add_bit_range_check(a, b)
            }
            ByteLookupEvent { opcode, a, b, c }
                if match opcode {
                    ByteOpcode::AND => a == u16::from(b & c),
                    ByteOpcode::OR => a == u16::from(b | c),
                    ByteOpcode::XOR => a == u16::from(b ^ c),
                    _ => false,
                } =>
            {
                let table = 3 + opcode as usize;
                self.increment(event, (table << 16) | (usize::from(b) << 8) | usize::from(c));
            }
            _ => *self.other.entry(event).or_default() += 1,
        }
    }

    fn add_byte_lookup_events_from_maps(&mut self, maps: Vec<&HashMap<ByteLookupEvent, usize>>) {
        for map in maps {
            for (&event, &count) in map {
                *self.other.entry(event).or_default() += count;
            }
        }
    }
}

/// Trace generation can discard lookups after a separate dependency pass has counted them.
impl ByteRecord for () {
    #[inline]
    fn add_byte_lookup_event(&mut self, _: ByteLookupEvent) {}
    fn add_byte_lookup_events_from_maps(&mut self, _: Vec<&HashMap<ByteLookupEvent, usize>>) {}
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
            _ => panic!("Invalid opcode for ByteChip: {value:?}"),
        }
    }
}

impl ByteOpcode {
    /// Get all the byte table opcodes.
    #[must_use]
    pub fn byte_table() -> Vec<Self> {
        let opcodes = vec![
            ByteOpcode::AND,
            ByteOpcode::OR,
            ByteOpcode::XOR,
            ByteOpcode::U8Range,
            ByteOpcode::LTU,
            ByteOpcode::MSB,
        ];
        opcodes
    }

    /// Convert the opcode to a field element.
    #[must_use]
    pub fn as_field<F: Field>(self) -> F {
        F::from_canonical_u8(self as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_counts_match_lookup_map_across_batches() {
        fn record<R: ByteRecord>(counts: &mut R) {
            for bits in 0..=17 {
                let largest = ((1u32 << bits) - 1).min(u32::from(u16::MAX)) as u16;
                for a in [0, 1, largest, u16::MAX] {
                    counts.add_bit_range_check(a, bits);
                    counts.add_byte_lookup_event(ByteLookupEvent::new(
                        ByteOpcode::Range,
                        a,
                        bits,
                        1,
                    ));
                }
            }
            counts.add_u8_range_checks(&[1, 2, 3]);
            counts.add_u8_range_check(255, 255);
            counts.lookup_or(3, 5);
            for opcode in [ByteOpcode::AND, ByteOpcode::OR, ByteOpcode::XOR] {
                for a in [0, 1, 6, 7, 300] {
                    counts.add_byte_lookup_event(ByteLookupEvent::new(opcode, a, 3, 5));
                }
            }
            counts.add_byte_lookup_event(ByteLookupEvent::new(ByteOpcode::U8Range, 1, 2, 3));
        }

        fn check<const DENSE: bool>(expected: &HashMap<ByteLookupEvent, usize>) {
            let mut counts = ByteCounters::<DENSE>::default();
            record(&mut counts);
            counts.add_byte_lookup_events_from_maps(vec![expected]);
            let mut second = ByteCounters::<DENSE>::default();
            record(&mut second);
            let counts = counts.merge(second);
            let mut actual = HashMap::<_, usize>::new();
            for (event, count) in counts.finish() {
                *actual.entry(event).or_default() += count;
            }
            assert_eq!(actual.len(), expected.len());
            assert!(expected.iter().all(|(event, count)| actual[event] == 3 * count));
        }
        let mut expected = HashMap::new();
        record(&mut expected);
        for _ in 0..2 {
            check::<true>(&expected);
            check::<false>(&expected);
        }
    }
}
