use super::{
    challenger::DuplexChallenger,
    types::{Commitment, FriProof},
};
use crate::prelude::{Array, Builder, Config, Ext, Felt, Usize};

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
    rounds: TwoAdicPcsRounds<C>,
    proof: TwoAdicPcsProof<C>,
    challenger: &mut DuplexChallenger<C>,
) {
    todo!()
}
