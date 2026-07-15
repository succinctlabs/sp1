use std::marker::PhantomData;

use super::PublicValuesOutputDigest;
use crate::{
    machine::{SP1CompressWithVKeyWitnessVariable, SP1GlobalCompressVerifier},
    shard::RecursiveShardVerifier,
    zerocheck::RecursiveVerifierConstraintFolder,
    CircuitConfig,
};
use slop_air::Air;
use slop_algebra::AbstractField;
use sp1_hypercube::air::MachineAir;
use sp1_primitives::{SP1Field, SP1GlobalContext};
use sp1_recursion_compiler::ir::{Builder, Felt};

/// A program to verify a single recursive proof representing a complete proof of program execution.
///
/// The root verifier is simply a `SP1GlobalCompressVerifier` with an assertion that the
/// `is_complete` flag is set to true.
#[derive(Debug, Clone, Copy)]
pub struct SP1CompressRootVerifierWithVKey<C, A> {
    _phantom: PhantomData<(C, A)>,
}

impl<C, A> SP1CompressRootVerifierWithVKey<C, A>
where
    C: CircuitConfig<Bit = Felt<SP1Field>>,
    A: MachineAir<SP1Field> + for<'a> Air<RecursiveVerifierConstraintFolder<'a>>,
{
    pub fn verify(
        builder: &mut Builder<C>,
        machine: &RecursiveShardVerifier<SP1GlobalContext, A, C>,
        input: SP1CompressWithVKeyWitnessVariable<C, SP1GlobalContext>,
        value_assertions: bool,
        kind: PublicValuesOutputDigest,
    ) {
        // Assert that the program is complete.
        builder.assert_felt_eq(input.compress_var.is_complete, SP1Field::one());
        // Verify the proof, as an across-chunk compress proof.
        SP1GlobalCompressVerifier::<C, SP1GlobalContext, _>::verify(
            builder,
            machine,
            input,
            value_assertions,
            kind,
        );
    }
}
