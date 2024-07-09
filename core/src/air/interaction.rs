use crate::lookup::InteractionKind;

/// An interaction is a cross-table lookup.
pub struct AirInteraction<E> {
    pub values: Vec<E>,
    pub kind: InteractionKind,
}

impl<E> AirInteraction<E> {
    /// Create a new interaction.
    pub const fn new(values: Vec<E>, kind: InteractionKind) -> Self {
        Self { values, kind }
    }
}
