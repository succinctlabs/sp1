use core::fmt::{Debug, Display};
use std::ops::Mul;

use serde::{Deserialize, Serialize};
use slop_air::{PairCol, VirtualPairCol};
use slop_algebra::{AbstractField, Field};
use slop_multilinear::MleEval;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum InteractionKind {
    /// Interaction with the memory table, such as read and write.
    Memory = 1,

    /// Interaction with the program table, loading an instruction at a given pc address.
    Program = 2,

    /// Interaction with the byte lookup table for byte operations.
    Byte = 3,

    /// Interaction with the current CPU state.
    State = 4,

    /// Interaction with a syscall.
    Syscall = 5,

    /// Interaction with the `ShaExtend` chip.
    ShaExtend = 6,

    /// Interaction with the `ShaCompress` chip.
    ShaCompress = 7,

    /// Interaction with the `Keccak` chip.
    Keccak = 8,

    /// Interaction with the instruction fetch table.
    InstructionFetch = 9,

    /// Interaction with the instruction decode table.
    InstructionDecode = 10,

    /// Interaction with the page prot chip.
    PageProt = 11,

    /// Interaction with the page prot chip.
    PageProtAccess = 12,

    /// Interaction for the merkle tree traversal.
    MerkleTreeTraversal = 13,

    /// Interaction for the leaf hash computation.
    LeafHash = 14,

    /// Interaction for the hint-read state machine (control chip <-> per-word chip).
    HintRead = 15,
}

impl InteractionKind {
    /// Returns all kinds of interactions.
    #[must_use]
    pub fn all_kinds() -> Vec<InteractionKind> {
        vec![
            InteractionKind::Memory,
            InteractionKind::Program,
            InteractionKind::Byte,
            InteractionKind::State,
            InteractionKind::Syscall,
            InteractionKind::ShaExtend,
            InteractionKind::ShaCompress,
            InteractionKind::Keccak,
            InteractionKind::InstructionFetch,
            InteractionKind::InstructionDecode,
            InteractionKind::PageProtAccess,
            InteractionKind::PageProt,
            InteractionKind::MerkleTreeTraversal,
            InteractionKind::LeafHash,
            InteractionKind::HintRead,
        ]
    }

    #[must_use]
    /// The number of `values` sent and received for each interaction kind.
    pub fn num_values(&self) -> usize {
        match self {
            InteractionKind::Memory => 9,
            #[cfg(feature = "mprotect")]
            InteractionKind::Syscall => 10,
            #[cfg(not(feature = "mprotect"))]
            InteractionKind::Syscall => 9,
            InteractionKind::Program => 16,
            InteractionKind::Byte => 4,
            InteractionKind::ShaCompress => 25,
            InteractionKind::Keccak => 106,
            InteractionKind::InstructionFetch => 22,
            InteractionKind::InstructionDecode => 19,
            InteractionKind::MerkleTreeTraversal => 11,
            InteractionKind::LeafHash => 11,
            // [clk_high, clk_low, ptr (3 limbs), index]
            InteractionKind::HintRead => 6,
            InteractionKind::ShaExtend
            | InteractionKind::PageProt
            | InteractionKind::PageProtAccess => 6,
            InteractionKind::State => 5,
        }
    }

    #[must_use]
    /// Whether this interaction kind gets used in `eval_public_values`.
    pub fn appears_in_eval_public_values(&self) -> bool {
        matches!(
            self,
            InteractionKind::Byte | InteractionKind::State | InteractionKind::MerkleTreeTraversal
        )
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

    /// Calculate the interactions evaluation.
    pub fn eval<Expr, Var>(
        &self,
        preprocessed: &MleEval<Var>,
        global: &MleEval<Var>,
        main: &MleEval<Var>,
        alpha: Expr,
        betas: &[Expr],
    ) -> (Expr, Expr)
    where
        F: Into<Expr>,
        Expr: AbstractField + Mul<F, Output = Expr>,
        Var: Into<Expr> + Copy,
    {
        let mut multiplicity_eval = self.multiplicity.constant.into();
        for (column, weight) in self.multiplicity.column_weights.iter() {
            let weight: Expr = (*weight).into();
            match column {
                PairCol::Preprocessed(i) => {
                    multiplicity_eval += preprocessed[*i].into() * weight;
                }
                PairCol::Global(i) => {
                    multiplicity_eval += global[*i].into() * weight;
                }
                PairCol::Main(i) => multiplicity_eval += main[*i].into() * weight,
            }
        }

        let mut betas = betas.iter().cloned();
        let mut fingerprint_eval =
            alpha + betas.next().unwrap() * Expr::from_canonical_usize(self.argument_index());
        for (element, beta) in self.values.iter().zip(betas) {
            let evaluation = element.apply::<Expr, Var>(preprocessed, global, main);
            fingerprint_eval += evaluation * beta;
        }

        (multiplicity_eval, fingerprint_eval)
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
            InteractionKind::Byte => write!(f, "Byte"),
            InteractionKind::State => write!(f, "State"),
            InteractionKind::Syscall => write!(f, "Syscall"),
            InteractionKind::ShaExtend => write!(f, "ShaExtend"),
            InteractionKind::ShaCompress => write!(f, "ShaCompress"),
            InteractionKind::Keccak => write!(f, "Keccak"),
            InteractionKind::InstructionFetch => write!(f, "InstructionFetch"),
            InteractionKind::InstructionDecode => write!(f, "InstructionDecode"),
            InteractionKind::PageProt => write!(f, "PageProt"),
            InteractionKind::PageProtAccess => write!(f, "PageProtAccess"),
            InteractionKind::MerkleTreeTraversal => write!(f, "MerkleTreeTraversal"),
            InteractionKind::LeafHash => write!(f, "LeafHash"),
            InteractionKind::HintRead => write!(f, "HintRead"),
        }
    }
}
