use std::sync::Arc;

use hashbrown::{HashMap, HashSet};
use p3_field::PrimeField;
use serde::{Deserialize, Serialize};
use sp1_stark::{air::MachineAir, ProofShape};

use crate::{ExecutionRecord, Program};

/// The shape of a core proof.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CoreShape {
    /// The shape of the proof.
    ///
    /// Keys are the chip names and values are the log-heights of the chips.
    pub inner: HashMap<String, usize>,
}

impl CoreShape {
    /// Create a dummy program with this shape.
    ///
    /// This can be used to generate a dummy preprocessed traces.
    #[must_use]
    pub fn dummy_program(&self) -> Program {
        let mut program = Program::new(vec![], 1 << 5, 1 << 5);
        program.preprocessed_shape = Some(self.clone());
        program
    }

    /// Create a dummy execution record with this shape.
    ///
    /// This can be used to generate dummy traces.
    #[must_use]
    pub fn dummy_record(&self) -> ExecutionRecord {
        let program = Arc::new(self.dummy_program());
        let mut record = ExecutionRecord::new(program);
        record.shape = Some(self.clone());
        record
    }

    /// Determines whether the execution record contains a trace for a given chip.
    pub fn included<F: PrimeField, A: MachineAir<F>>(&self, air: &A) -> bool {
        self.inner.contains_key(&air.name())
    }
}

impl Extend<CoreShape> for CoreShape {
    fn extend<T: IntoIterator<Item = CoreShape>>(&mut self, iter: T) {
        for shape in iter {
            self.inner.extend(shape.inner);
        }
    }
}

impl Extend<(String, usize)> for CoreShape {
    fn extend<T: IntoIterator<Item = (String, usize)>>(&mut self, iter: T) {
        self.inner.extend(iter);
    }
}

impl IntoIterator for CoreShape {
    type Item = (String, usize);

    type IntoIter = hashbrown::hash_map::IntoIter<String, usize>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl FromIterator<(String, usize)> for CoreShape {
    fn from_iter<T: IntoIterator<Item = (String, usize)>>(iter: T) -> Self {
        Self { inner: iter.into_iter().collect() }
    }
}

impl From<ProofShape> for CoreShape {
    fn from(value: ProofShape) -> Self {
        Self { inner: value.into_iter().collect() }
    }
}

impl From<CoreShape> for ProofShape {
    fn from(value: CoreShape) -> Self {
        value.inner.into_iter().collect()
    }
}

impl PartialOrd for CoreShape {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let set = self.inner.keys().collect::<HashSet<_>>();
        let other_set = other.inner.keys().collect::<HashSet<_>>();

        if set.is_subset(&other_set) {
            let mut less_seen = false;
            let mut greater_seen = false;
            for (name, &height) in self.inner.iter() {
                let other_height = other.inner[name];
                match height.cmp(&other_height) {
                    std::cmp::Ordering::Less => less_seen = true,
                    std::cmp::Ordering::Greater => greater_seen = true,
                    std::cmp::Ordering::Equal => {}
                }
            }
            if less_seen && greater_seen {
                return None;
            }

            if less_seen {
                return Some(std::cmp::Ordering::Less);
            }
        }

        if other_set.is_subset(&set) {
            let mut less_seen = false;
            let mut greater_seen = false;
            for (name, &height) in other.inner.iter() {
                let other_height = self.inner[name];
                match height.cmp(&other_height) {
                    std::cmp::Ordering::Less => less_seen = true,
                    std::cmp::Ordering::Greater => greater_seen = true,
                    std::cmp::Ordering::Equal => {}
                }
            }

            if less_seen && greater_seen {
                return None;
            }

            if greater_seen {
                return Some(std::cmp::Ordering::Greater);
            }
        }

        None
    }
}
