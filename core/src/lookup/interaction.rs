use alloc::borrow::Cow;
use core::fmt::Debug;
use core::fmt::Display;
use p3_air::VirtualPairCol;
use p3_field::Field;

/// An interaction for a lookup or a permutation argument.
#[derive(Clone)]
pub struct Interaction<'a, F: Field> {
    pub values: Cow<'a, [VirtualPairCol<'a, F>]>,
    pub multiplicity: VirtualPairCol<'a, F>,
    pub kind: InteractionKind,
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

    /// Interaction with the ALU operations
    Alu = 4,

    /// Interaction with the byte lookup table for byte operations.
    Byte = 5,

    /// Requesting a range check for a given value and range.
    Range = 6,

    /// Interaction with the field op table for field operations.
    Field = 7,
}

impl InteractionKind {
    pub fn all_kinds() -> Vec<InteractionKind> {
        vec![
            InteractionKind::Memory,
            InteractionKind::Program,
            InteractionKind::Instruction,
            InteractionKind::Alu,
            InteractionKind::Byte,
            InteractionKind::Range,
            InteractionKind::Field,
        ]
    }
}

impl<'a, F: Field> Interaction<'a, F> {
    /// Create a new interaction.
    pub fn new(
        values: Vec<VirtualPairCol<'a, F>>,
        multiplicity: VirtualPairCol<'a, F>,
        kind: InteractionKind,
    ) -> Self {
        Self {
            values: Cow::Owned(values),
            multiplicity,
            kind,
        }
    }

    /// The index of the argument in the lookup table.
    pub fn argument_index(&self) -> usize {
        self.kind as usize
    }
}

// TODO: add debug for VirtualPairCol so that we can derive Debug for Interaction.
impl<'a, F: Field> Debug for Interaction<'a, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interaction")
            .field("kind", &self.kind)
            .finish()
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
        }
    }
}
