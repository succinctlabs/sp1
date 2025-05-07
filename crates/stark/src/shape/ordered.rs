use std::{cmp::Reverse, collections::BTreeSet, fmt};

use itertools::Itertools;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use serde::{Deserialize, Serialize};

/// A way to keep track of the log2 heights of some set of chips and in canonical order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct OrderedShape {
    /// The inner data.
    pub inner: Vec<(String, usize)>,
}

impl OrderedShape {
    /// Create an [`OrderedShape`] from a set of traces.
    #[must_use]
    pub fn from_traces<V: Clone + Send + Sync>(traces: &[(String, RowMajorMatrix<V>)]) -> Self {
        traces
            .iter()
            .map(|(name, trace)| (name.clone(), trace.height().ilog2() as usize))
            .sorted_by_key(|(_, height)| *height)
            .collect()
    }

    /// Create an [`OrderedShape`] from a set of log2 heights.
    #[must_use]
    pub fn from_log2_heights(traces: &[(String, usize)]) -> Self {
        traces
            .iter()
            .map(|(name, height)| (name.clone(), *height))
            .sorted_by_key(|(_, height)| *height)
            .collect()
    }
}

impl FromIterator<(String, usize)> for OrderedShape {
    fn from_iter<T: IntoIterator<Item = (String, usize)>>(iter: T) -> Self {
        let set = iter
            .into_iter()
            .map(|(name, log_degree)| (Reverse(log_degree), name))
            .collect::<BTreeSet<_>>();
        Self {
            inner: set.into_iter().map(|(Reverse(log_degree), name)| (name, log_degree)).collect(),
        }
    }
}

impl IntoIterator for OrderedShape {
    type Item = (String, usize);

    type IntoIter = <Vec<(String, usize)> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl fmt::Display for OrderedShape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "OrderedShape:")?;
        for (name, log_degree) in &self.inner {
            writeln!(f, "{name}: {log_degree}")?;
        }
        Ok(())
    }
}
