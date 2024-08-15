use crate::lookup::InteractionKind;

/// An interaction is a cross-table lookup.
pub struct AirInteraction<E> {
    /// The values of the interaction.
    pub values: Vec<E>,
    /// The multiplicity of the interaction.
    pub multiplicity: E,
    /// The kind of interaction.
    pub kind: InteractionKind,
}

impl<E> AirInteraction<E> {
    /// Create a new [`AirInteraction`].
    pub const fn new(values: Vec<E>, multiplicity: E, kind: InteractionKind) -> Self {
        Self { values, multiplicity, kind }
    }
}
