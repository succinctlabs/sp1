use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

/// The shape of a core proof.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoreShape {
    /// The id of the shape. Used for enumeration of the possible proof shapes.
    pub id: usize,
    /// The shape of the proof. Keys are the chip names and values are the log-heights of the chips.
    pub shape: HashMap<String, usize>,
}
