use p3_baby_bear::BabyBear;
use p3_field::extension::BinomialExtensionField;

use crate::syscall::precompiles::{MemoryReadRecord, MemoryWriteRecord};

mod execute;

#[derive(Debug, Clone)]
pub struct FriFoldEvent {
    pub clk: u32,
    pub shard: u32,

    pub x: BabyBear,
    pub alpha: BinomialExtensionField<BabyBear, 4>,
    pub z: BinomialExtensionField<BabyBear, 4>,
    pub p_at_z: BinomialExtensionField<BabyBear, 4>,
    pub p_at_x: BabyBear,
    pub ro_input: BinomialExtensionField<BabyBear, 4>,
    pub alpha_pow_input: BinomialExtensionField<BabyBear, 4>,

    pub ro_output: BinomialExtensionField<BabyBear, 4>,
    pub alpha_pow_output: BinomialExtensionField<BabyBear, 4>,

    pub input_read_records: Vec<MemoryReadRecord>,
    pub input_mem_ptr: u32,

    pub output_read_records: Vec<MemoryReadRecord>,
    pub output_mem_ptr: u32,

    pub ro_read_records: Vec<MemoryReadRecord>,
    pub ro_write_records: Vec<MemoryWriteRecord>,
    pub ro_addr: u32,

    pub alpha_pow_read_records: Vec<MemoryReadRecord>,
    pub alpha_pow_write_records: Vec<MemoryWriteRecord>,
    pub alpha_pow_addr: u32,
}

pub struct FriFoldChip {}

impl FriFoldChip {
    pub fn new() -> Self {
        Self {}
    }
}
