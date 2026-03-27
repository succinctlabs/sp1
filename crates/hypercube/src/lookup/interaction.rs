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
    Byte = 5,

    /// Interaction with the current CPU state.
    State = 7,

    /// Interaction with a syscall.
    Syscall = 8,

    /// Interaction with the global table.
    Global = 9,

    /// Interaction with the `ShaExtend` chip.
    ShaExtend = 10,

    /// Interaction with the `ShaCompress` chip.
    ShaCompress = 11,

    /// Interaction with the `Keccak` chip.
    Keccak = 12,

    /// Interaction to accumulate the global interaction digests.
    GlobalAccumulation = 13,

    /// Interaction with the `MemoryGlobalInit` chip.
    MemoryGlobalInitControl = 14,

    /// Interaction with the `MemoryGlobalFinalize` chip.
    MemoryGlobalFinalizeControl = 15,

    /// Interaction with the instruction fetch table.
    InstructionFetch = 16,

    /// Interaction with the instruction decode table.
    InstructionDecode = 17,

    /// Interaction with the page prot chip.
    PageProt = 18,

    /// Interaction with the page prot chip.
    PageProtAccess = 19,

    /// Interaction with the `PageProtGlobalInit` chip.
    PageProtGlobalInitControl = 20,

    /// Interaction with the `PageProtGlobalFinalize` chip.
    PageProtGlobalFinalizeControl = 21,

    /// Interaction with the `Blake3Compress` chip.
    Blake3Compress = 22,
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
            InteractionKind::Global,
            InteractionKind::ShaExtend,
            InteractionKind::ShaCompress,
            InteractionKind::Keccak,
            InteractionKind::GlobalAccumulation,
            InteractionKind::MemoryGlobalInitControl,
            InteractionKind::MemoryGlobalFinalizeControl,
            InteractionKind::InstructionFetch,
            InteractionKind::InstructionDecode,
            InteractionKind::PageProtAccess,
            InteractionKind::PageProtGlobalInitControl,
            InteractionKind::PageProtGlobalFinalizeControl,
            InteractionKind::PageProt,
            InteractionKind::Blake3Compress,
        ]
    }

    #[must_use]
    /// The number of `values` sent and received for each interaction kind.
    pub fn num_values(&self) -> usize {
        match self {
            InteractionKind::Memory | InteractionKind::Syscall => 9,
            InteractionKind::Program => 16,
            InteractionKind::Byte => 4,
            InteractionKind::Global => 11,

            InteractionKind::ShaCompress => 25,
            InteractionKind::Keccak => 106,
            InteractionKind::GlobalAccumulation => 15,

            InteractionKind::InstructionFetch => 22,
            InteractionKind::InstructionDecode => 19,
            InteractionKind::ShaExtend
            | InteractionKind::PageProt
            | InteractionKind::PageProtAccess => 6,

            // clk_high(1) + clk_low(1) + state_ptr(3) + msg_ptr(3) + index(1) + state[16][2](32) + msg[16][2](32) = 73
            InteractionKind::Blake3Compress => 73,
            InteractionKind::State
            | InteractionKind::PageProtGlobalInitControl
            | InteractionKind::PageProtGlobalFinalizeControl
            | InteractionKind::MemoryGlobalInitControl
            | InteractionKind::MemoryGlobalFinalizeControl => 5,
        }
    }

    #[must_use]
    /// Whether this interaction kind gets used in `eval_public_values`.
    pub fn appears_in_eval_public_values(&self) -> bool {
        matches!(
            self,
            InteractionKind::Byte
                | InteractionKind::State
                | InteractionKind::MemoryGlobalFinalizeControl
                | InteractionKind::MemoryGlobalInitControl
                | InteractionKind::PageProtGlobalFinalizeControl
                | InteractionKind::PageProtGlobalInitControl
                | InteractionKind::GlobalAccumulation
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
        preprocessed: Option<&MleEval<Var>>,
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
                    multiplicity_eval += preprocessed.as_ref().unwrap()[*i].into() * weight;
                }
                PairCol::Main(i) => multiplicity_eval += main[*i].into() * weight,
            }
        }

        let mut betas = betas.iter().cloned();
        let mut fingerprint_eval =
            alpha + betas.next().unwrap() * Expr::from_canonical_usize(self.argument_index());
        for (element, beta) in self.values.iter().zip(betas) {
            let evaluation = if let Some(preprocessed) = preprocessed {
                element.apply::<Expr, Var>(preprocessed, main)
            } else {
                element.apply::<Expr, Var>(&[], main)
            };
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
            InteractionKind::Global => write!(f, "Global"),
            InteractionKind::ShaExtend => write!(f, "ShaExtend"),
            InteractionKind::ShaCompress => write!(f, "ShaCompress"),
            InteractionKind::Keccak => write!(f, "Keccak"),
            InteractionKind::GlobalAccumulation => write!(f, "GlobalAccumulation"),
            InteractionKind::MemoryGlobalInitControl => write!(f, "MemoryGlobalInitControl"),
            InteractionKind::MemoryGlobalFinalizeControl => {
                write!(f, "MemoryGlobalFinalizeControl")
            }
            InteractionKind::InstructionFetch => write!(f, "InstructionFetch"),
            InteractionKind::InstructionDecode => write!(f, "InstructionDecode"),
            InteractionKind::PageProt => write!(f, "PageProt"),
            InteractionKind::PageProtAccess => write!(f, "PageProtAccess"),
            InteractionKind::PageProtGlobalInitControl => write!(f, "PageProtGlobalInitControl"),
            InteractionKind::PageProtGlobalFinalizeControl => {
                write!(f, "PageProtGlobalFinalizeControl")
            }
            InteractionKind::Blake3Compress => write!(f, "Blake3Compress"),
        }
    }
}
