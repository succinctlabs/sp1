use serde::{Deserialize, Serialize};
use slop_algebra::AbstractField;
use slop_challenger::VariableLengthChallenger;
use slop_challenger::{CanObserve, IopCtx};

use crate::septic_digest::SepticDigest;

#[allow(clippy::disallowed_types)]
use slop_basefold::Poseidon2KoalaBear16BasefoldConfig;

#[allow(clippy::disallowed_types)]
/// The basefold configuration (field, extension field, challenger, tensor commitment scheme)
/// for SP1.
pub type SP1BasefoldConfig = Poseidon2KoalaBear16BasefoldConfig;

#[allow(clippy::disallowed_types)]
pub use slop_koala_bear::Poseidon2KoalaBearConfig;

#[allow(clippy::disallowed_types)]
/// The Merkle tree configuration for SP1.
pub type SP1MerkleTreeConfig = Poseidon2KoalaBearConfig;

/// A specification of preprocessed polynomial batch dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ChipDimensions<T> {
    /// The height of the preprocessed polynomial.
    pub height: T,
    /// The number of polynomials in the preprocessed batch.
    pub num_polynomials: T,
}

/// A configuration regarding untrusted programs and trap handler.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UntrustedConfig<T> {
    /// Whether or not untrusted programs are enabled on the program.
    pub enable_untrusted_programs: T,
    /// Whether or not a trap handler exists.
    #[cfg(feature = "mprotect")]
    pub enable_trap_handler: T,
    /// The `address`, `address + 8`, `address + 16` values of the trap context.
    #[cfg(feature = "mprotect")]
    pub trap_context: [[T; 3]; 3],
    /// The region of memory where mprotect syscall may be called.
    #[cfg(feature = "mprotect")]
    pub untrusted_memory: [[T; 3]; 2],
}

impl<T: AbstractField> UntrustedConfig<T> {
    /// A dummy config with all zeros
    #[must_use]
    pub fn zero() -> Self {
        Self {
            enable_untrusted_programs: T::zero(),
            #[cfg(feature = "mprotect")]
            enable_trap_handler: T::zero(),
            #[cfg(feature = "mprotect")]
            trap_context: [
                [T::zero(), T::zero(), T::zero()],
                [T::zero(), T::zero(), T::zero()],
                [T::zero(), T::zero(), T::zero()],
            ],
            #[cfg(feature = "mprotect")]
            untrusted_memory: [
                [T::zero(), T::zero(), T::zero()],
                [T::zero(), T::zero(), T::zero()],
            ],
        }
    }
}

/// A verifying key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineVerifyingKey<C: IopCtx> {
    /// The start pc of the program.
    pub pc_start: [C::F; 3],
    /// The starting global digest of the program, after incorporating the initial memory.
    pub initial_global_cumulative_sum: SepticDigest<C::F>,
    /// The preprocessed commitments.
    pub preprocessed_commit: C::Digest,
    /// Metadata on configuration regarding untrusted programs.
    pub untrusted_config: UntrustedConfig<C::F>,
}

impl<C: IopCtx> PartialEq for MachineVerifyingKey<C> {
    fn eq(&self, other: &Self) -> bool {
        self.pc_start == other.pc_start
            && self.initial_global_cumulative_sum == other.initial_global_cumulative_sum
            && self.preprocessed_commit == other.preprocessed_commit
            && self.untrusted_config == other.untrusted_config
    }
}

impl<C: IopCtx> Eq for MachineVerifyingKey<C> {}

impl<C: IopCtx> MachineVerifyingKey<C> {
    /// Observes the values of the proving key into the challenger.
    pub fn observe_into(&self, challenger: &mut C::Challenger) {
        challenger.observe(self.preprocessed_commit);
        challenger.observe_constant_length_slice(&self.pc_start);
        challenger.observe_constant_length_slice(&self.initial_global_cumulative_sum.0.x.0);
        challenger.observe_constant_length_slice(&self.initial_global_cumulative_sum.0.y.0);
        challenger.observe(self.untrusted_config.enable_untrusted_programs);
        #[cfg(feature = "mprotect")]
        challenger.observe(self.untrusted_config.enable_trap_handler);
        #[cfg(feature = "mprotect")]
        challenger.observe_constant_length_slice(self.untrusted_config.trap_context.as_flattened());
        #[cfg(feature = "mprotect")]
        challenger
            .observe_constant_length_slice(self.untrusted_config.untrusted_memory.as_flattened());
        // Observe the padding.
        challenger.observe_constant_length_slice(&[C::F::zero(); 6]);
    }
}
