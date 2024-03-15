use p3_field::Field;
use sp1_recursion_compiler::ir::Felt;

use crate::symmetric::hash::Hash;

pub struct FriProof<F: Field, const DIGEST_ELEMS: usize> {
    pub(crate) commit_phase_commits: Vec<Hash<F, DIGEST_ELEMS>>,
    pub(crate) query_proofs: Vec<Hash<F, DIGEST_ELEMS>>,
    pub(crate) final_poly: Felt<F>,
    pub(crate) pow_witness: Felt<F>,
}

pub struct QueryProof<F: Field, const DIGEST_ELEMS: usize> {
    pub(crate) commit_phase_openings: Vec<CommitPhaseProofStep<F, DIGEST_ELEMS>>,
}

pub struct CommitPhaseProofStep<F: Field, const DIGEST_ELEMS: usize> {
    /// The opening of the commit phase codeword at the sibling location.
    // This may change to Vec<FC::Challenge> if the library is generalized to support other FRI
    // folding arities besides 2, meaning that there can be multiple siblings.
    pub(crate) sibling_value: Felt<F>,

    pub(crate) opening_proof: Vec<[Felt<F>; DIGEST_ELEMS]>,
}
