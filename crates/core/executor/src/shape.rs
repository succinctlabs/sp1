use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

/// The shape of a core proof.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoreShape {
    /// The shape of the proof.
    ///
    /// Keys are the chip names and values are the log-heights of the chips.
    pub inner: HashMap<String, usize>,
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
