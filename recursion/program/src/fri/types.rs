use sp1_recursion_compiler::prelude::*;

use crate::fri::TwoAdicMultiplicativeCosetVariable;

pub type DigestVariable<C> = Array<C, Felt<<C as Config>::F>>;

#[derive(DslVariable, Clone)]
pub struct FriConfigVariable<C: Config> {
    pub log_blowup: Var<C::N>,
    pub blowup: Var<C::N>,
    pub num_queries: Var<C::N>,
    pub proof_of_work_bits: Var<C::N>,
    pub generators: Array<C, Felt<C::F>>,
    pub subgroups: Array<C, TwoAdicMultiplicativeCosetVariable<C>>,
}

#[derive(DslVariable, Clone)]
pub struct FriProofVariable<C: Config> {
    pub commit_phase_commits: Array<C, DigestVariable<C>>,
    pub query_proofs: Array<C, FriQueryProofVariable<C>>,
    pub final_poly: Ext<C::F, C::EF>,
    pub pow_witness: Felt<C::F>,
}

#[derive(DslVariable, Clone)]
pub struct FriQueryProofVariable<C: Config> {
    pub commit_phase_openings: Array<C, FriCommitPhaseProofStepVariable<C>>,
}

#[derive(DslVariable, Clone)]
pub struct FriCommitPhaseProofStepVariable<C: Config> {
    pub sibling_value: Ext<C::F, C::EF>,
    pub opening_proof: Array<C, DigestVariable<C>>,
}

#[derive(DslVariable, Clone)]
pub struct FriChallengesVariable<C: Config> {
    pub query_indices: Array<C, Array<C, Var<C::N>>>,
    pub betas: Array<C, Ext<C::F, C::EF>>,
}

#[derive(DslVariable, Clone)]
pub struct DimensionsVariable<C: Config> {
    pub height: Var<C::N>,
}

#[derive(DslVariable, Clone)]
pub struct TwoAdicPcsProofVariable<C: Config> {
    pub fri_proof: FriProofVariable<C>,
    pub query_openings: Array<C, Array<C, BatchOpeningVariable<C>>>,
}

#[derive(DslVariable, Clone)]
pub struct BatchOpeningVariable<C: Config> {
    pub opened_values: Array<C, Array<C, Ext<C::F, C::EF>>>,
    pub opening_proof: Array<C, Array<C, Felt<C::F>>>,
}

#[derive(DslVariable, Clone)]
pub struct TwoAdicPcsRoundVariable<C: Config> {
    pub batch_commit: DigestVariable<C>,
    pub mats: Array<C, TwoAdicPcsMatsVariable<C>>,
}

#[allow(clippy::type_complexity)]
#[derive(DslVariable, Clone)]
pub struct TwoAdicPcsMatsVariable<C: Config> {
    pub domain: TwoAdicMultiplicativeCosetVariable<C>,
    pub points: Array<C, Ext<C::F, C::EF>>,
    pub values: Array<C, Array<C, Ext<C::F, C::EF>>>,
}
