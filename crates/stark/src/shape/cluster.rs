use std::{fmt::Debug, hash::Hash, str::FromStr};

use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

use super::Shape;

/// A cluster of shapes.
///
/// We represent a cluster of shapes as a cartesian product of heights per chip.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShapeCluster<K: Eq + Hash + FromStr> {
    inner: HashMap<K, Vec<Option<usize>>>,
}

impl<K: Debug + Clone + Eq + Hash + FromStr> ShapeCluster<K> {
    /// Create a new shape cluster.
    #[must_use]
    pub fn new(inner: HashMap<K, Vec<Option<usize>>>) -> Self {
        Self { inner }
    }

    /// Find the shape that is larger or equal to the given heights.
    pub fn find_shape(&self, heights: &[(K, usize)]) -> Option<Shape<K>> {
        let shape: Option<HashMap<K, Option<usize>>> = heights
            .iter()
            .map(|(air, height)| {
                for maybe_log2_height in self.inner.get(air).into_iter().flatten() {
                    let allowed_height =
                        maybe_log2_height.map(|log_height| 1 << log_height).unwrap_or_default();
                    if *height <= allowed_height {
                        return Some((air.clone(), *maybe_log2_height));
                    }
                }
                None
            })
            .collect();

        let mut inner = shape?;
        inner.retain(|_, &mut value| value.is_some());

        let shape = inner
            .into_iter()
            .map(|(air, maybe_log_height)| (air, maybe_log_height.unwrap()))
            .collect::<Shape<K>>();

        Some(shape)
    }

    /// Iterate over the inner map.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &Vec<Option<usize>>)> {
        self.inner.iter()
    }
}
