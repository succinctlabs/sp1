use p3_field::AbstractField;
use p3_field::TwoAdicField;

use super::{
    challenger::DuplexChallenger,
    fri::{verify_challenges, verify_shape_and_sample_challenges},
    types::{Commitment, FriConfig, FriProof},
};
use crate::prelude::Var;
use crate::prelude::{Array, Builder, Config, Ext, Felt, SymbolicExt, SymbolicFelt, Usize};

pub struct BatchOpening<C: Config> {
    pub opened_values: Array<C, Array<C, Felt<C::F>>>,
    pub opening_proof: Array<C, Array<C, Felt<C::F>>>,
}

pub struct TwoAdicPcsProof<C: Config> {
    pub fri_proof: FriProof<C>,
    pub query_openings: Array<C, Array<C, BatchOpening<C>>>,
}

pub struct TwoAdicPcsRounds<C: Config> {
    pub batch_commit: Commitment<C>,
    pub mats: Array<C, TwoAdicPcsMats<C>>,
}

pub struct TwoAdicPcsMats<C: Config> {
    pub size: Usize<C::N>,
    pub values: Array<C, Ext<C::F, C::EF>>,
}

#[allow(unused_variables)]
pub fn verify_two_adic_pcs<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfig,
    rounds: TwoAdicPcsRounds<C>,
    proof: TwoAdicPcsProof<C>,
    challenger: &mut DuplexChallenger<C>,
) where
    C::F: TwoAdicField,
{
    let alpha = challenger.sample(builder);
    let alpha: Ext<_, _> = builder.eval(SymbolicExt::Base(SymbolicFelt::Val(alpha).into()));

    let fri_challenges =
        verify_shape_and_sample_challenges(builder, config, &proof.fri_proof, challenger);

    let commit_phase_commits_len = builder.materialize(proof.fri_proof.commit_phase_commits.len());
    let log_max_height: Var<_> =
        builder.eval(commit_phase_commits_len + C::N::from_canonical_usize(config.log_blowup));

    // TODO:
}
