use std::marker::PhantomData;

use super::SP1ShapedWitnessVariable;
use crate::{
    challenger::CanObserveVariable,
    machine::{assert_complete, assert_root_public_values_valid, RootPublicValues},
    shard::RecursiveShardVerifier,
    zerocheck::RecursiveVerifierConstraintFolder,
    CircuitConfig, SP1FieldConfigVariable,
};
use slop_air::Air;
use slop_algebra::AbstractField;
use slop_challenger::IopCtx;
use sp1_hypercube::air::MachineAir;
use sp1_primitives::{SP1ExtensionField, SP1Field};
use sp1_recursion_compiler::ir::{Builder, Felt};
use std::borrow::Borrow;

/// A program to verify a single recursive proof representing a complete proof of program execution.
///
/// The root verifier is simply a `SP1CompressVerifier` with an assertion that the `is_complete`
/// flag is set to true.
#[derive(Debug, Clone, Copy)]
pub struct SP1WrapVerifier<GC, C, A> {
    _phantom: PhantomData<(GC, C, A)>,
}

impl<GC, C, A> SP1WrapVerifier<GC, C, A>
where
    GC: IopCtx<F = SP1Field, EF = SP1ExtensionField>
        + Send
        + Sync
        + SP1FieldConfigVariable<C>
        + Send
        + Sync,
    C: CircuitConfig,
    A: MachineAir<SP1Field> + for<'a> Air<RecursiveVerifierConstraintFolder<'a>>,
{
    pub fn verify(
        builder: &mut Builder<C>,
        machine: &RecursiveShardVerifier<GC, A, C>,
        input: SP1ShapedWitnessVariable<C, GC>,
    ) {
        // Assert the the proof is not malformed.
        assert!(input.vks_and_proofs.len() == 1);
        // Take the proof from the input.
        let (vk, proof) = &input.vks_and_proofs[0];

        // Assert that the program is complete.
        builder.assert_felt_eq(input.is_complete, SP1Field::one());
        let public_values: &RootPublicValues<Felt<SP1Field>> =
            proof.public_values.as_slice().borrow();
        assert_root_public_values_valid::<C, GC>(builder, public_values);

        let mut challenger = <GC as SP1FieldConfigVariable<C>>::challenger_variable(builder);
        challenger.observe(builder, vk.preprocessed_commit);
        challenger.observe_slice(builder, vk.pc_start);
        challenger.observe_slice(builder, vk.initial_global_cumulative_sum.0.x.0);
        challenger.observe_slice(builder, vk.initial_global_cumulative_sum.0.y.0);
        challenger.observe(builder, vk.untrusted_config.enable_untrusted_programs);
        #[cfg(feature = "mprotect")]
        {
            challenger.observe(builder, vk.untrusted_config.enable_trap_handler);
            for trap_context_addr in vk.untrusted_config.trap_context.into_iter() {
                challenger.observe_slice(builder, trap_context_addr);
            }
            for untrusted_memory_addr in vk.untrusted_config.untrusted_memory.into_iter() {
                challenger.observe_slice(builder, untrusted_memory_addr);
            }
        }

        // Observe the padding.
        let zero: Felt<_> = builder.eval(SP1Field::zero());
        for _ in 0..6 {
            challenger.observe(builder, zero);
        }
        machine.verify_shard(builder, vk, proof, &mut challenger);

        assert_complete(builder, &public_values.inner, input.is_complete);

        GC::commit_recursion_public_values(builder, public_values.inner);
    }
}
