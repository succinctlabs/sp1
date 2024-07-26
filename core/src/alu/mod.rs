pub mod add_sub;
pub mod bitwise;
pub mod divrem;
pub mod lt;
pub mod mul;
pub mod sll;
pub mod sr;

use std::array;

pub use add_sub::*;
pub use bitwise::*;
pub use divrem::*;
pub use lt::*;
pub use mul::*;
use rand::Rng;
pub use sll::*;
pub use sr::*;

use serde::{Deserialize, Serialize};

use crate::{cpu::LookupIdSampler, runtime::Opcode};

/// A standard format for describing ALU operations that need to be proven.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AluEvent {
    /// The lookup id of the event.
    pub lookup_id: u128,

    /// The shard number, used for byte lookup table.
    pub shard: u32,

    /// The channel number, used for byte lookup table.
    pub channel: u8,

    /// The clock cycle that the operation occurs on.
    pub clk: u32,

    /// The opcode of the operation.
    pub opcode: Opcode,

    /// The result of the operation.
    pub a: u32,

    /// The first input operand.
    pub b: u32,

    // The second input operand.
    pub c: u32,

    pub sub_lookups: Option<[u128; 6]>,
}

impl AluEvent {
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn new(
        lookup_id: u128,
        shard: u32,
        channel: u8,
        clk: u32,
        opcode: Opcode,
        a: u32,
        b: u32,
        c: u32,
        lookupid_sampler: &mut impl LookupIdSampler,
    ) -> Self {
        let sub_lookups = if matches!(
            opcode,
            Opcode::DIVU | Opcode::REMU | Opcode::DIV | Opcode::REM,
        ) {
            Some(new_sublookups(lookupid_sampler))
        } else {
            None
        };

        Self {
            lookup_id,
            shard,
            channel,
            clk,
            opcode,
            a,
            b,
            c,
            sub_lookups,
        }
    }
}

/// Create a set of lookup_ids for an ALU event sublookup field.
fn new_sublookups(rng_sampler: &mut impl LookupIdSampler) -> [u128; 6] {
    let lookup_ids = rng_sampler.sample(6);
    array::from_fn(|i| lookup_ids[i])
}

/// A simple lookup id sampler.  This is only used for tests.
#[derive(Default)]
pub struct SimpleLookupIdSampler {
    lookup_ids: Vec<u128>,
}

impl LookupIdSampler for SimpleLookupIdSampler {
    fn sample(&mut self, num_lookup_ids: usize) -> &[u128] {
        let mut rng = rand::thread_rng();
        self.lookup_ids = vec![rng.gen::<u128>(); num_lookup_ids];
        self.lookup_ids.as_slice()
    }
}
