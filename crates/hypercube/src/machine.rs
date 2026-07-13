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
    /// Chips EXCLUDED by `chips_filter` still contribute their global-interaction
    /// dependencies (via `generate_global_dependencies`): the filter exists so a
    /// prover can move a chip's byte-lookup half to another backend (device
    /// tracegen), but septic global events are always generated on host.
    ///
    /// Every chip runs IN MACHINE CHIP ORDER regardless of the filter: each chip
    /// sees the record with all earlier chips' outputs appended, and consumers rely
    /// on it — `Global`'s dependencies read the `global_interaction_events` that
    /// `MemoryLocal`/`Syscall*`/`MemoryGlobal*` (possibly filter-excluded) emit, so
    /// running excluded chips in a separate later pass would hand `Global` an empty
    /// event list and break the global cumulative sum.
    #[allow(clippy::needless_for_each)]
    pub fn generate_dependencies<'a>(
        &self,
        records: impl Iterator<Item = &'a mut A::Record>,
        chips_filter: Option<&[String]>,
    ) {
        // The filter is stringly-typed; a typo'd or renamed chip name would silently
        // run the full host dependency pass for a chip the prover ALSO generates
        // dependencies for on-device — double-counting byte multiplicities and
        // failing verification far from the cause. Fail loudly here instead.
        if let Some(chips_filter) = chips_filter {
            for name in chips_filter {
                assert!(
                    self.chips.iter().any(|chip| *chip.name() == *name),
                    "generate_dependencies: chips_filter names unknown chip `{name}` \
                     (typo, or a chip rename that outran the filter's source?)"
                );
            }
        }

        let full_deps = |chip: &Chip<F, A>| {
            if let Some(chips_filter) = chips_filter {
                chips_filter.contains(&chip.name().to_string())
            } else {
                true
            }
        };

        records.for_each(|record| {
            self.chips.iter().for_each(|chip| {
                let mut output = A::Record::default();
                if full_deps(chip) {
                    chip.generate_dependencies(record, &mut output);
                } else {
                    chip.generate_global_dependencies(record, &mut output);
                }
                record.append(&mut output);
            });
        });
    }
}
