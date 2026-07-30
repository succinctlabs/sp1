use std::sync::Arc;

use serde::de::Deserializer;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use sp1_core_machine::autoprecompiles::Sp1Apc;
use sp1_core_machine::riscv::RiscvAir;
use sp1_hypercube::Machine;
use sp1_primitives::SP1Field;

/// A serializable wrapper for `Machine<SP1Field, RiscvAir<SP1Field>>`.
///
/// Only the APCs are serialized; the base machine is reconstructed via
/// `RiscvAir::machine_with_apcs()` on deserialization.
#[derive(Debug, Clone)]
pub struct SerializableRiscvMachine(pub Machine<SP1Field, RiscvAir<SP1Field>>);

impl Serialize for SerializableRiscvMachine {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let apcs: Vec<_> = self
            .0
            .chips()
            .iter()
            .filter_map(|chip| match chip.air.as_ref() {
                RiscvAir::Apc(apc_chip) => Some(apc_chip.apc().clone()),
                _ => None,
            })
            .collect();

        // Serialize APCs via JSON first, then send the JSON bytes through serde.
        // Powdr's `AlgebraicExpression` uses `#[serde(untagged)]`, which requires
        // `deserialize_any` and is therefore incompatible with bincode directly.
        let json_bytes =
            serde_json::to_vec(&apcs).map_err(|e| serde::ser::Error::custom(e.to_string()))?;
        json_bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SerializableRiscvMachine {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let json_bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        let apcs: Vec<Arc<Sp1Apc<SP1Field>>> = serde_json::from_slice(&json_bytes)
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        Ok(Self(RiscvAir::machine_with_apcs(apcs)))
    }
}

impl From<Machine<SP1Field, RiscvAir<SP1Field>>> for SerializableRiscvMachine {
    fn from(machine: Machine<SP1Field, RiscvAir<SP1Field>>) -> Self {
        Self(machine)
    }
}

impl From<SerializableRiscvMachine> for Machine<SP1Field, RiscvAir<SP1Field>> {
    fn from(machine: SerializableRiscvMachine) -> Self {
        machine.0
    }
}
