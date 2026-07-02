use std::{collections::BTreeSet, sync::Arc};

use hashbrown::HashMap;
use slop_algebra::PrimeField32;
use sp1_core_executor::RiscvAirId;
use sp1_hypercube::{air::SP1_PROOF_NUM_PV_ELTS, Chip, Machine, MachineShape};
use strum::IntoEnumIterator;

use crate::{
    autoprecompiles::{chip::ApcChip, Sp1Apc},
    riscv::{air::RiscvAir, RiscvAirDiscriminants},
};
use sp1_hypercube::air::MachineAir;
use std::mem::MaybeUninit;

#[derive(sp1_derive::MachineAir, Debug)]
pub enum RiscvAirWithApcs<F: PrimeField32> {
    Riscv(RiscvAir<F>),
    Apc(ApcChip<F>),
}

impl<F: PrimeField32> RiscvAirWithApcs<F> {
    /// Returns the id of the air if it is not an apc air. Otherwise, panics.
    pub fn id(&self) -> RiscvAirId {
        match self {
            RiscvAirWithApcs::Riscv(air) => air.id(),
            _ => unreachable!(),
        }
    }

    pub fn machine() -> Machine<F, Self> {
        Self::machine_with_apcs(vec![])
    }

    pub fn machine_with_apcs(apcs: Vec<Arc<Sp1Apc<F>>>) -> Machine<F, Self> {
        #[cfg(not(feature = "apc"))]
        {
            assert!(apcs.is_empty(), "enable the `apc` feature to use apcs");
        }

        let base = RiscvAir::<F>::machine();

        let mut chips = RiscvAir::airs()
            .into_iter()
            .map(RiscvAirWithApcs::Riscv)
            .map(Chip::new)
            .collect::<Vec<_>>();

        let apc_chips = apcs
            .into_iter()
            .enumerate()
            .map(|(i, apc)| Chip::new(RiscvAirWithApcs::Apc(ApcChip::new(apc, i))))
            .collect::<Vec<_>>();
        chips.extend(apc_chips.iter().cloned());

        let chips_map = chips
            .iter()
            .filter_map(|c| match c.air.as_ref() {
                RiscvAirWithApcs::Riscv(ref d) => {
                    let id: RiscvAirDiscriminants = d.into();
                    Some((id, c))
                }
                RiscvAirWithApcs::Apc(_) => None,
            })
            .collect::<HashMap<RiscvAirDiscriminants, &Chip<F, RiscvAirWithApcs<F>>>>();
        // Check that we listed all RISC-V chips.
        assert_eq!(chips_map.len(), RiscvAirDiscriminants::iter().len());

        let chip_clusters = base
            .shape()
            .chip_clusters
            .iter()
            .map(|cluster| {
                let mut out = cluster
                    .iter()
                    .map(|chip| {
                        let id: RiscvAirDiscriminants = chip.air.as_ref().into();
                        chips_map[&id].clone()
                    })
                    .collect::<Vec<_>>();

                // A bit hacky: we detect if this cluster contains the chip for `Add`, and use that to decide whether we should add apcs
                let has_software_chips = cluster.iter().any(|chip| {
                    matches!(
                        RiscvAirDiscriminants::from(chip.air.as_ref()),
                        RiscvAirDiscriminants::Add
                    )
                });

                if has_software_chips {
                    out.extend(apc_chips.iter().cloned());
                }
                out.into_iter().collect::<BTreeSet<_>>()
            })
            .collect::<Vec<_>>();

        let shape = MachineShape::new(chip_clusters);

        // Stop borrowing `chips`.
        drop(chips_map);

        Machine::new(chips, SP1_PROOF_NUM_PV_ELTS, shape)
    }
}
