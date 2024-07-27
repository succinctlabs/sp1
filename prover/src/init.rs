use crate::components::SP1ProverComponents;
use p3_baby_bear::BabyBear;
pub use sp1_core::io::{SP1PublicValues, SP1Stdin};
use sp1_core::stark::MachineProver;
use sp1_core::stark::StarkProvingKey;
use sp1_core::stark::StarkVerifyingKey;
use sp1_primitives::types::RecursionProgramType;
use sp1_recursion_compiler::config::InnerConfig;
use sp1_recursion_core::runtime::RecursionProgram;
pub use sp1_recursion_gnark_ffi::plonk_bn254::PlonkBn254Proof;
pub use sp1_recursion_program::machine::ReduceProgramType;
pub use sp1_recursion_program::machine::{
    SP1CompressMemoryLayout, SP1DeferredMemoryLayout, SP1RecursionMemoryLayout, SP1RootMemoryLayout,
};
use sp1_recursion_program::machine::{
    SP1CompressVerifier, SP1DeferredVerifier, SP1RecursiveVerifier, SP1RootVerifier,
};
use tracing::debug_span;

use crate::{InnerSC, OuterSC, SP1Prover};

impl<C: SP1ProverComponents> SP1Prover<C> {
    /// The program that can recursively verify a set of proofs into a single proof.
    pub fn recursion_program(&self) -> &RecursionProgram<BabyBear> {
        self.recursion_program.get_or_init(|| {
            debug_span!("init recursion program").in_scope(|| {
                SP1RecursiveVerifier::<InnerConfig, _>::build(self.core_prover.machine())
            })
        })
    }

    /// The program that recursively verifies deferred proofs and accumulates the digests.
    pub fn deferred_program(&self) -> &RecursionProgram<BabyBear> {
        self.deferred_program.get_or_init(|| {
            debug_span!("init deferred program").in_scope(|| {
                SP1DeferredVerifier::<InnerConfig, _, _>::build(self.compress_prover.machine())
            })
        })
    }

    /// The program that reduces a set of recursive proofs into a single proof.
    pub fn compress_program(&self) -> &RecursionProgram<BabyBear> {
        self.compress_program.get_or_init(|| {
            debug_span!("init compress program").in_scope(|| {
                SP1CompressVerifier::<InnerConfig, _, _>::build(
                    self.compress_prover.machine(),
                    self.recursion_vk(),
                    self.deferred_vk(),
                )
            })
        })
    }

    /// The shrink program that compresses a proof into a succinct proof.
    pub fn shrink_program(&self) -> &RecursionProgram<BabyBear> {
        self.shrink_program.get_or_init(|| {
            debug_span!("init shrink program").in_scope(|| {
                SP1RootVerifier::<InnerConfig, _, _>::build(
                    self.compress_prover.machine(),
                    self.compress_vk(),
                    RecursionProgramType::Shrink,
                )
            })
        })
    }

    /// The wrap program that wraps a proof into a SNARK-friendly field.
    pub fn wrap_program(&self) -> &RecursionProgram<BabyBear> {
        self.wrap_program.get_or_init(|| {
            debug_span!("init wrap program").in_scope(|| {
                SP1RootVerifier::<InnerConfig, _, _>::build(
                    self.shrink_prover.machine(),
                    self.shrink_vk(),
                    RecursionProgramType::Wrap,
                )
            })
        })
    }

    /// The proving and verifying keys for the recursion step.
    pub fn recursion_keys(&self) -> &(StarkProvingKey<InnerSC>, StarkVerifyingKey<InnerSC>) {
        self.recursion_keys.get_or_init(|| {
            debug_span!("init recursion keys")
                .in_scope(|| self.compress_prover.setup(self.recursion_program()))
        })
    }

    /// The proving key for the recursion step.
    pub fn recursion_pk(&self) -> &StarkProvingKey<InnerSC> {
        &self.recursion_keys().0
    }

    /// The verifying key for the recursion step.
    pub fn recursion_vk(&self) -> &StarkVerifyingKey<InnerSC> {
        &self.recursion_keys().1
    }

    /// The proving and verifying keys for the deferred step.
    pub fn deferred_keys(&self) -> &(StarkProvingKey<InnerSC>, StarkVerifyingKey<InnerSC>) {
        self.deferred_keys.get_or_init(|| {
            debug_span!("init deferred keys")
                .in_scope(|| self.compress_prover.setup(self.deferred_program()))
        })
    }

    /// The proving key for the deferred step.
    pub fn deferred_pk(&self) -> &StarkProvingKey<InnerSC> {
        &self.deferred_keys().0
    }

    /// The verifying key for the deferred step.
    pub fn deferred_vk(&self) -> &StarkVerifyingKey<InnerSC> {
        &self.deferred_keys().1
    }

    /// The proving and verifying keys for the compress step.
    pub fn compress_keys(&self) -> &(StarkProvingKey<InnerSC>, StarkVerifyingKey<InnerSC>) {
        self.compress_keys.get_or_init(|| {
            debug_span!("init compress keys")
                .in_scope(|| self.compress_prover.setup(self.compress_program()))
        })
    }

    /// The proving key for the compress step.
    pub fn compress_pk(&self) -> &StarkProvingKey<InnerSC> {
        &self.compress_keys().0
    }

    /// The verifying key for the compress step.
    pub fn compress_vk(&self) -> &StarkVerifyingKey<InnerSC> {
        &self.compress_keys().1
    }

    /// The proving and verifying keys for the shrink step.
    pub fn shrink_keys(&self) -> &(StarkProvingKey<InnerSC>, StarkVerifyingKey<InnerSC>) {
        self.shrink_keys.get_or_init(|| {
            debug_span!("init shrink keys")
                .in_scope(|| self.shrink_prover.setup(self.shrink_program()))
        })
    }

    /// The proving key for the shrink step.
    pub fn shrink_pk(&self) -> &StarkProvingKey<InnerSC> {
        &self.shrink_keys().0
    }

    /// The verifying key for the shrink step.
    pub fn shrink_vk(&self) -> &StarkVerifyingKey<InnerSC> {
        &self.shrink_keys().1
    }

    /// The proving and verifying keys for the wrap step.
    pub fn wrap_keys(&self) -> &(StarkProvingKey<OuterSC>, StarkVerifyingKey<OuterSC>) {
        self.wrap_keys.get_or_init(|| {
            debug_span!("init wrap keys").in_scope(|| self.wrap_prover.setup(self.wrap_program()))
        })
    }

    /// The proving key for the wrap step.
    pub fn wrap_pk(&self) -> &StarkProvingKey<OuterSC> {
        &self.wrap_keys().0
    }

    /// The verifying key for the wrap step.
    pub fn wrap_vk(&self) -> &StarkVerifyingKey<OuterSC> {
        &self.wrap_keys().1
    }
}
