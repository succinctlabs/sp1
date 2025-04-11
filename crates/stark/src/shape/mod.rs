//! Utilities for working with shapes.

mod cluster;
mod ordered;

pub use cluster::*;
pub use ordered::*;

use itertools::Itertools;
use p3_matrix::{dense::RowMajorMatrix, Matrix};

use std::{fmt::Debug, hash::Hash, str::FromStr};

use hashbrown::{hash_map::IntoIter, HashMap, HashSet};
use p3_field::PrimeField;
use serde::{Deserialize, Serialize};

use crate::air::MachineAir;

/// A way to keep track of the log2 heights of some set of chips.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Shape<K: Clone + Eq + Hash> {
    /// The nonzero log2 heights of each chip.
    pub inner: HashMap<K, usize>,
}

// Manual `impl` to remove bound `K: Default`.
impl<K: Clone + Eq + Hash> Default for Shape<K> {
    fn default() -> Self {
        Self { inner: HashMap::default() }
    }
}

impl<K: Clone + Eq + Hash + FromStr> Shape<K> {
    /// Create a new empty shape.
    #[must_use]
    pub fn new(inner: HashMap<K, usize>) -> Self {
        Self { inner }
    }

    /// Create a shape from a list of log2 heights.
    #[must_use]
    pub fn from_log2_heights(log2_heights: &[(K, usize)]) -> Self {
        Self { inner: log2_heights.iter().map(|(k, h)| (k.clone(), *h)).collect() }
    }

    /// Create a shape from a list of traces.
    #[must_use]
    pub fn from_traces<V: Clone + Send + Sync>(traces: &[(K, RowMajorMatrix<V>)]) -> Self {
        Self {
            inner: traces
                .iter()
                .map(|(name, trace)| (name.clone(), trace.height().ilog2() as usize))
                .sorted_by_key(|(_, height)| *height)
                .collect(),
        }
    }

    /// The number of chips in the shape.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the shape is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get the height of a given key.
    pub fn height(&self, key: &K) -> Option<usize> {
        self.inner.get(key).map(|height| 1 << *height)
    }

    /// Get the log2 height of a given key.
    pub fn log2_height(&self, key: &K) -> Option<usize> {
        self.inner.get(key).copied()
    }

    /// Whether the shape includes a given key.
    pub fn contains(&self, key: &K) -> bool {
        self.inner.contains_key(key)
    }

    /// Insert a key-height pair into the shape.
    pub fn insert(&mut self, key: K, height: usize) {
        self.inner.insert(key, height);
    }

    /// Whether the shape includes a given AIR.
    ///
    /// TODO: Deprecate by adding `air.id()`.
    pub fn included<F: PrimeField, A: MachineAir<F>>(&self, air: &A) -> bool
    where
        <K as FromStr>::Err: std::fmt::Debug,
    {
        self.inner.contains_key(&K::from_str(&air.name()).unwrap())
    }

    /// Get an iterator over the shape.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &usize)> {
        self.inner.iter().sorted_by_key(|(_, v)| *v)
    }

    /// Estimate the lde size.
    ///
    /// WARNING: This is a heuristic, it may not be completely accurate. To be 100% sure that they
    /// OOM, you should run the shape through the prover.
    #[must_use]
    pub fn estimate_lde_size(&self, costs: &HashMap<K, usize>) -> usize {
        self.iter().map(|(k, h)| costs[k] * (1 << h)).sum()
    }
}

impl<K: Clone + Eq + Hash> Extend<Shape<K>> for Shape<K> {
    fn extend<T: IntoIterator<Item = Shape<K>>>(&mut self, iter: T) {
        for shape in iter {
            self.inner.extend(shape.inner);
        }
    }
}

impl<K: Clone + Eq + Hash> Extend<(K, usize)> for Shape<K> {
    fn extend<T: IntoIterator<Item = (K, usize)>>(&mut self, iter: T) {
        self.inner.extend(iter);
    }
}

impl<K: Clone + Eq + Hash + FromStr> FromIterator<(K, usize)> for Shape<K> {
    fn from_iter<T: IntoIterator<Item = (K, usize)>>(iter: T) -> Self {
        Self { inner: iter.into_iter().collect() }
    }
}

impl<K: Clone + Eq + Hash> IntoIterator for Shape<K> {
    type Item = (K, usize);
    type IntoIter = IntoIter<K, usize>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<K: Clone + Eq + Hash> PartialOrd for Shape<K> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let set = self.inner.keys().collect::<HashSet<_>>();
        let other_set = other.inner.keys().collect::<HashSet<_>>();

        if self == other {
            return Some(std::cmp::Ordering::Equal);
        }

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
            for (name, &other_height) in other.inner.iter() {
                let height = self.inner[name];
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
