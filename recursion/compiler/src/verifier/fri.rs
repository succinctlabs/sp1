use crate::prelude::Config;
use p3_commit::Mmcs;
use p3_field::AbstractField;
use p3_field::TwoAdicField;
use p3_fri::{FriConfig, QueryProof};

fn verify_query<C: Config, M: Mmcs<C::F>>(
    config: &FriConfig<M>,
    commit_phase_commits: &[M::Commitment],
    mut index: usize,
    proof: &QueryProof<C::F, M>,
    betas: &[C::F],
    reduced_openings: &[C::F; 32],
    log_max_height: usize,
) where
    C::F: TwoAdicField,
{
    let mut folded_eval = C::F::zero();
    let mut x = C::F::two_adic_generator(log_max_height).exp_u64(index as u64);
}
