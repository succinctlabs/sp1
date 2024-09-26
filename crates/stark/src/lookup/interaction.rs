use core::fmt::{Debug, Display};

use p3_air::VirtualPairCol;
use p3_field::Field;

use crate::air::InteractionScope;

/// An interaction for a lookup or a permutation argument.
#[derive(Clone)]
pub struct Interaction<F: Field> {
    /// The values of the interaction.
    pub values: Vec<VirtualPairCol<F>>,
    /// The multiplicity of the interaction.
    pub multiplicity: VirtualPairCol<F>,
    /// The kind of interaction.
    pub kind: InteractionKind,
    /// The scope of the interaction.
    pub scope: InteractionScope,
}

/// The type of interaction for a lookup argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InteractionKind {
    /// Interaction with the memory table, such as read and write.
    Memory = 1,

    /// Interaction with the program table, loading an instruction at a given pc address.
    Program = 2,

    /// Interaction with instruction oracle.
    Instruction = 3,

    /// Interaction with the ALU operations.
    Alu = 4,

    /// Interaction with the byte lookup table for byte operations.
    Byte = 5,

    /// Requesting a range check for a given value and range.
    Range = 6,

    /// Interaction with the field op table for field operations.
    Field = 7,

    /// Interaction with a syscall.
    Syscall = 8,
}

impl InteractionKind {
    /// Returns all kinds of interactions.
    #[must_use]
    pub fn all_kinds() -> Vec<InteractionKind> {
        vec![
            InteractionKind::Memory,
            InteractionKind::Program,
            InteractionKind::Instruction,
            InteractionKind::Alu,
            InteractionKind::Byte,
            InteractionKind::Range,
            InteractionKind::Field,
            InteractionKind::Syscall,
        ]
    }
}

impl<F: Field> Interaction<F> {
    /// Create a new interaction.
    pub const fn new(
        values: Vec<VirtualPairCol<F>>,
        multiplicity: VirtualPairCol<F>,
        kind: InteractionKind,
        scope: InteractionScope,
    ) -> Self {
        Self { values, multiplicity, kind, scope }
    }

    /// The index of the argument in the lookup table.
    pub const fn argument_index(&self) -> usize {
        self.kind as usize
    }
}

impl<F: Field> Debug for Interaction<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interaction")
            .field("kind", &self.kind)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl Display for InteractionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InteractionKind::Memory => write!(f, "Memory"),
            InteractionKind::Program => write!(f, "Program"),
            InteractionKind::Instruction => write!(f, "Instruction"),
            InteractionKind::Alu => write!(f, "Alu"),
            InteractionKind::Byte => write!(f, "Byte"),
            InteractionKind::Range => write!(f, "Range"),
            InteractionKind::Field => write!(f, "Field"),
            InteractionKind::Syscall => write!(f, "Syscall"),
        }
    }
}
