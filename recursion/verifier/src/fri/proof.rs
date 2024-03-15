use p3_field::Field;
use sp1_recursion_compiler::ir::{Config, Felt, Vector};

use crate::symmetric::hash::Hash;

pub struct FriProof<C: Config, const DIGEST_ELEMS: usize> {
    // pub(crate) commit_phase_commits: Vector<C, Hash<C::N, DIGEST_ELEMS>>,
    pub(crate) query_proofs: Vector<C, Hash<C::N, DIGEST_ELEMS>>,
    pub(crate) final_poly: Felt<C::F>,
    pub(crate) pow_witness: Felt<C::F>,
}

pub struct QueryProof<C: Config, F: Field, const DIGEST_ELEMS: usize> {
    pub(crate) commit_phase_openings: Vector<C, CommitPhaseProofStep<C, F, DIGEST_ELEMS>>,
}

pub struct CommitPhaseProofStep<C: Config, F: Field, const DIGEST_ELEMS: usize> {
    /// The opening of the commit phase codeword at the sibling location.
    // This may change to Vec<FC::Challenge> if the library is generalized to support other FRI
    // folding arities besides 2, meaning that there can be multiple siblings.
    pub(crate) sibling_value: Felt<F>,

    pub(crate) opening_proof: Vector<C, [Felt<F>; DIGEST_ELEMS]>,
}
