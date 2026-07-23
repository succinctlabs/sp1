use std::fmt::Display;

use powdr_autoprecompiles::bus_map::BusType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Sp1SpecificBuses {
    Byte,
    UntrustedInstruction,
    PageProt,
}

impl Display for Sp1SpecificBuses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Sp1SpecificBuses::Byte => write!(f, "BYTE"),
            Sp1SpecificBuses::UntrustedInstruction => write!(f, "UNTRUSTED_INSTRUCTION"),
            Sp1SpecificBuses::PageProt => write!(f, "PAGE_PROT"),
        }
    }
}

pub type BusMap = powdr_autoprecompiles::bus_map::BusMap<Sp1SpecificBuses>;

pub fn sp1_bus_map() -> BusMap {
    // Mapping from: crates/stark/src/lookup/interaction.rs
    BusMap::from_id_type_pairs([
        (1, BusType::Memory),
        (2, BusType::PcLookup),
        (5, BusType::Other(Sp1SpecificBuses::Byte)),
        (7, BusType::ExecutionBridge),
        (16, BusType::Other(Sp1SpecificBuses::UntrustedInstruction)),
        (18, BusType::Other(Sp1SpecificBuses::PageProt)),
    ])
}
