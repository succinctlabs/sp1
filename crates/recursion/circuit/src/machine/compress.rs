use std::borrow::Borrow;

use slop_algebra::PrimeField32;
use slop_challenger::IopCtx;

use serde::{Deserialize, Serialize};
use sp1_recursion_compiler::ir::Felt;

use sp1_primitives::SP1Field;
use sp1_recursion_executor::RecursionPublicValues;

use sp1_hypercube::{air::ShardRange, MachineVerifyingKey, ShardProof};

use crate::{
    shard::{MachineVerifyingKeyVariable, ShardProofVariable},
    CircuitConfig, SP1FieldConfigVariable,
};
pub enum PublicValuesOutputDigest {
    Reduce,
    Root,
}

/// Witness layout for the compress stage verifier.
#[allow(clippy::type_complexity)]
pub struct SP1ShapedWitnessVariable<C: CircuitConfig, GC: SP1FieldConfigVariable<C>> {
    /// The shard proofs to verify.
    pub vks_and_proofs: Vec<(MachineVerifyingKeyVariable<C, GC>, ShardProofVariable<C, GC>)>,
    pub is_complete: Felt<SP1Field>,
}

pub type VkAndProof<GC, Proof> = (MachineVerifyingKey<GC>, ShardProof<GC, Proof>);

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "ShardProof<GC,Proof>: Serialize"))]
#[serde(bound(deserialize = "ShardProof<GC,Proof>: Deserialize<'de>"))]
/// An input layout for the shard proofs that have been normalized to a standard shape.
pub struct SP1ShapedWitnessValues<GC: IopCtx, Proof> {
    pub vks_and_proofs: Vec<VkAndProof<GC, Proof>>,
    pub is_complete: bool,
}

impl<GC: IopCtx, Proof> SP1ShapedWitnessValues<GC, Proof> {
    pub fn range(&self) -> ShardRange
    where
        GC::F: PrimeField32,
    {
        let start_pv: &RecursionPublicValues<GC::F> =
            self.vks_and_proofs[0].1.public_values.as_slice().borrow();
        let end_pv: &RecursionPublicValues<GC::F> =
            self.vks_and_proofs[self.vks_and_proofs.len() - 1].1.public_values.as_slice().borrow();

        let start = start_pv.range().start();
        let end = end_pv.range().end();

        (start..end).into()
    }
}
