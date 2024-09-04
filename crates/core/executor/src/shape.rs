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
