use derive_where::derive_where;
use slop_algebra::Field;
use std::collections::BTreeSet;

use crate::{air::MachineAir, Chip, MachineRecord};

/// A shape for a machine.
#[derive_where(Debug; A: MachineAir<F>)]
#[derive_where(Clone)]
pub struct MachineShape<F: Field, A> {
    /// The chip clusters.
    pub chip_clusters: Vec<BTreeSet<Chip<F, A>>>,
}

impl<F: Field, A: MachineAir<F>> MachineShape<F, A> {
    /// Create a single shape that always includes all the chips.
    #[must_use]
    pub fn all(chips: &[Chip<F, A>]) -> Self {
        let chip_clusters = vec![chips.iter().cloned().collect()];
        Self { chip_clusters }
    }

    /// Create a new shape from a list of chip clusters.
    #[must_use]
    pub const fn new(chip_clusters: Vec<BTreeSet<Chip<F, A>>>) -> Self {
        Self { chip_clusters }
    }

    /// Returns the smallest shape cluster that contains all the chips with given names.
    #[must_use]
    pub fn smallest_cluster(&self, chips: &BTreeSet<Chip<F, A>>) -> Option<&BTreeSet<Chip<F, A>>> {
        self.chip_clusters
            .iter()
            .filter(|cluster| chips.is_subset(cluster))
            .min_by_key(|cluster| cluster.len())
    }
}

/// A STARK for proving RISC-V execution.
#[derive_where(Debug; A: MachineAir<F>)]
#[derive_where(Clone)]
pub struct Machine<F: Field, A> {
    /// The chips that make up the RISC-V STARK machine, in order of their execution.
    chips: Vec<Chip<F, A>>,
    /// The number of public values elements that the machine uses
    num_pv_elts: usize,
    /// The shape of the machine.
    shape: MachineShape<F, A>,
}

impl<F, A> Machine<F, A>
where
    F: Field,
    A: MachineAir<F>,
{
    /// Creates a new [`StarkMachine`].
    #[must_use]
    pub const fn new(
        chips: Vec<Chip<F, A>>,
        num_pv_elts: usize,
        shape: MachineShape<F, A>,
    ) -> Self {
        Self { chips, num_pv_elts, shape }
    }

    /// Returns the chips in the machine.
    #[must_use]
    pub fn chips(&self) -> &[Chip<F, A>] {
        &self.chips
    }

    /// Returns the number of public values elements.
    #[must_use]
    pub const fn num_pv_elts(&self) -> usize {
        self.num_pv_elts
    }

    /// Returns the shape of the machine.
    #[must_use]
    pub const fn shape(&self) -> &MachineShape<F, A> {
        &self.shape
    }

    /// Returns the smallest shape cluster that contains all the chips with given names.
    #[must_use]
    pub fn smallest_cluster(&self, chips: &BTreeSet<Chip<F, A>>) -> Option<&BTreeSet<Chip<F, A>>> {
        self.shape.smallest_cluster(chips)
    }

    /// Generates the dependencies of the given records.
    ///
    /// Chips are processed in parallel where possible. The `Global` chip depends on
    /// `global_interaction_events` produced by other chips, so it runs after all
    /// independent chips have finished.
    pub fn generate_dependencies<'a>(
        &self,
        records: impl Iterator<Item = &'a mut A::Record>,
        chips_filter: Option<&[String]>,
    ) {
        use rayon::prelude::*;

        let chips = self
            .chips
            .iter()
            .filter(|chip| {
                if let Some(chips_filter) = chips_filter {
                    chips_filter.contains(&chip.name().to_string())
                } else {
                    true
                }
            })
            .collect::<Vec<_>>();

        // Split chips into independent (can run in parallel) and the Global chip
        // which must run after (it reads global_interaction_events produced by others).
        let mut independent_chips = Vec::new();
        let mut global_chip = None;
        for chip in &chips {
            if chip.name() == "Global" {
                global_chip = Some(*chip);
            } else {
                independent_chips.push(*chip);
            }
        }

        records.for_each(|record| {
            // Phase 1: Run all independent chips in parallel.
            // Each chip reads from the shared immutable record and writes to its own output.
            let outputs: Vec<A::Record> = independent_chips
                .par_iter()
                .map(|chip| {
                    let mut output = A::Record::default();
                    chip.generate_dependencies(record, &mut output);
                    output
                })
                .collect();

            // Merge all independent outputs into the record.
            for mut output in outputs {
                record.append(&mut output);
            }

            // Phase 2: Run GlobalChip (needs the merged global_interaction_events).
            if let Some(chip) = &global_chip {
                let mut output = A::Record::default();
                chip.generate_dependencies(record, &mut output);
                record.append(&mut output);
            }
        });
    }
}
