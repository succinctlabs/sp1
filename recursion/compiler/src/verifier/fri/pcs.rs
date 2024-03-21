use p3_field::AbstractField;
use p3_field::TwoAdicField;

use super::types::{Commitment, FriConfig, FriProof};
use crate::prelude::MemVariable;
use crate::prelude::Ptr;
use crate::prelude::Var;
use crate::prelude::Variable;
use crate::prelude::{Array, Builder, Config, Ext, Felt, Usize};
use crate::prelude::{SymbolicExt, SymbolicFelt};
use crate::verifier::fri;
use crate::verifier::fri::verify_shape_and_sample_challenges;
use crate::verifier::fri::Dimensions;
use crate::verifier::fri::DuplexChallenger;

#[derive(Clone)]
pub struct BatchOpening<C: Config> {
    pub opened_values: Array<C, Array<C, Felt<C::F>>>,
    pub opening_proof: Array<C, Array<C, Felt<C::F>>>,
}

pub struct TwoAdicPcsProof<C: Config> {
    pub fri_proof: FriProof<C>,
    pub query_openings: Array<C, Array<C, BatchOpening<C>>>,
}

#[derive(Clone)]
pub struct TwoAdicPcsRound<C: Config> {
    pub batch_commit: Commitment<C>,
    pub mats: Array<C, TwoAdicPcsMats<C>>,
}

#[allow(clippy::type_complexity)]
#[derive(Clone)]
pub struct TwoAdicPcsMats<C: Config> {
    pub size: Var<C::N>,
    pub points: Array<C, Ext<C::F, C::EF>>,
    pub values: Array<C, Array<C, Ext<C::F, C::EF>>>,
}

#[allow(clippy::type_complexity)]
#[allow(unused_variables)]
pub fn verify_two_adic_pcs<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfig<C>,
    rounds: Array<C, TwoAdicPcsRound<C>>,
    proof: TwoAdicPcsProof<C>,
    challenger: &mut DuplexChallenger<C>,
) where
    C::EF: TwoAdicField,
{
    let alpha = challenger.sample(builder);
    let alpha: Ext<_, _> = builder.eval(SymbolicExt::Base(SymbolicFelt::Val(alpha).into()));

    let fri_challenges =
        verify_shape_and_sample_challenges(builder, config, &proof.fri_proof, challenger);

    let commit_phase_commits_len = builder.materialize(proof.fri_proof.commit_phase_commits.len());
    let log_blowup = config.log_blowup.materialize(builder);
    let log_max_height: Var<_> = builder.eval(commit_phase_commits_len + log_blowup);

    let mut reduced_openings: Array<C, Array<C, Ext<C::F, C::EF>>> =
        builder.array(proof.query_openings.len());
    builder
        .range(0, proof.query_openings.len())
        .for_each(|i, builder| {
            let query_opening = builder.get(&proof.query_openings, i);
            let index = builder.get(&fri_challenges.query_indices, i);
            let mut ro: Array<C, Ext<C::F, C::EF>> = builder.array(32);
            let zero: Ext<C::F, C::EF> = builder.eval(SymbolicExt::Const(C::EF::zero()));
            builder.range(0, 32).for_each(|i, builder| {
                builder.set(&mut ro, i, zero);
            });
            let mut alpha_pow: Array<C, Ext<C::F, C::EF>> = builder.array(32);
            let one: Ext<C::F, C::EF> = builder.eval(SymbolicExt::Const(C::EF::one()));
            builder.range(0, 32).for_each(|i, builder| {
                builder.set(&mut alpha_pow, i, one);
            });

            builder.range(0, rounds.len()).for_each(|j, builder| {
                let batch_opening = builder.get(&query_opening, j);
                let round = builder.get(&rounds, j);
                let batch_commit = round.batch_commit;
                let mats = round.mats;

                let mut batch_dims = builder.array(mats.len());
                builder.range(0, mats.len()).for_each(|k, builder| {
                    let mat = builder.get(&mats, k);
                    let dim = Dimensions::<C> { height: mat.size };
                    builder.set(&mut batch_dims, k, dim);
                });

                let index_bits = builder.num2bits_v(index);
                fri::verify_batch(
                    builder,
                    &batch_commit,
                    batch_dims,
                    index_bits,
                    batch_opening.opened_values.clone(),
                    &batch_opening.opening_proof,
                );

                builder
                    .range(0, batch_opening.opened_values.len())
                    .for_each(|k, builder| {
                        let mat_opening = builder.get(&batch_opening.opened_values, k);
                        let mat = builder.get(&mats, k);
                        let mat_domain = mat.size;
                        let mat_points = mat.points;
                        let mat_values = mat.values;

                        let log2_domain_size = builder.log2(mat_domain);
                        let log_height = log2_domain_size + config.log_blowup.materialize(builder);
                        let log_height: Var<C::N> = builder.eval(log_height);

                        let bits_reduced: Var<C::N> = builder.eval(log_max_height - log_height);
                        let rev_reduced_index =
                            builder.reverse_bits_len(index, Usize::Var(bits_reduced));
                        let rev_reduced_index = rev_reduced_index.materialize(builder);

                        let g = builder.generator();
                        let two_adic_generator = builder.two_adic_generator(Usize::Var(log_height));
                        let g_mul_two_adic_generator = builder.eval(g * two_adic_generator);
                        let x: SymbolicExt<C::F, C::EF> = builder
                            .exp_usize_f(g_mul_two_adic_generator, Usize::Var(rev_reduced_index))
                            .into();

                        builder.range(0, mat_points.len()).for_each(|l, builder| {
                            let z: SymbolicExt<C::F, C::EF> = builder.get(&mat_points, l).into();
                            let ps_at_z = builder.get(&mat_values, l);
                            builder.range(0, ps_at_z.len()).for_each(|m, builder| {
                                let p_at_x: SymbolicExt<C::F, C::EF> =
                                    builder.get(&mat_opening, m).into();
                                let p_at_z: SymbolicExt<C::F, C::EF> =
                                    builder.get(&ps_at_z, m).into();
                                let quotient: SymbolicExt<C::F, C::EF> =
                                    (-p_at_z + p_at_x) / (-z + x);

                                let ro_at_log_height = builder.get(&ro, log_height);
                                let alpha_pow_at_log_height = builder.get(&alpha_pow, log_height);
                                let new_ro_at_log_height: Ext<C::F, C::EF> = builder
                                    .eval(ro_at_log_height + alpha_pow_at_log_height * quotient);

                                builder.set(&mut ro, log_height, new_ro_at_log_height);
                                builder.set(
                                    &mut alpha_pow,
                                    log_height,
                                    alpha_pow_at_log_height * alpha,
                                );
                            });
                        });
                    });
            });
            builder.set(&mut reduced_openings, i, ro);
        });

    fri::verify_challenges(
        builder,
        config,
        &proof.fri_proof,
        &fri_challenges,
        &reduced_openings,
    );
}

impl<C: Config> Variable<C> for TwoAdicPcsRound<C> {
    type Expression = Self;

    fn uninit(builder: &mut Builder<C>) -> Self {
        TwoAdicPcsRound {
            batch_commit: builder.uninit(),
            mats: Array::Dyn(builder.uninit(), builder.uninit()),
        }
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<C>) {
        self.batch_commit.assign(src.batch_commit, builder);
        self.mats.assign(src.mats.clone(), builder);
    }

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();
        Array::<C, Felt<<C as Config>::F>>::assert_eq(lhs.batch_commit, rhs.batch_commit, builder);
        Array::<C, TwoAdicPcsMats<C>>::assert_eq(lhs.mats, rhs.mats, builder);
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();
        Array::<C, Felt<<C as Config>::F>>::assert_ne(lhs.batch_commit, rhs.batch_commit, builder);
        Array::<C, TwoAdicPcsMats<C>>::assert_ne(lhs.mats, rhs.mats, builder);
    }
}

impl<C: Config> MemVariable<C> for TwoAdicPcsRound<C> {
    fn size_of() -> usize {
        3
    }

    fn load(&self, ptr: Ptr<<C as Config>::N>, builder: &mut Builder<C>) {
        let address = builder.eval(ptr + Usize::Const(0));
        self.batch_commit.load(address, builder);
        let address = builder.eval(ptr + Usize::Const(1));
        self.mats.load(address, builder);
    }

    fn store(&self, ptr: Ptr<<C as Config>::N>, builder: &mut Builder<C>) {
        let address = builder.eval(ptr + Usize::Const(0));
        self.batch_commit.store(address, builder);
        let address = builder.eval(ptr + Usize::Const(1));
        self.mats.store(address, builder);
    }
}

impl<C: Config> Variable<C> for TwoAdicPcsMats<C> {
    type Expression = Self;

    fn uninit(builder: &mut Builder<C>) -> Self {
        TwoAdicPcsMats {
            size: builder.uninit(),
            points: Array::Dyn(builder.uninit(), builder.uninit()),
            values: Array::Dyn(builder.uninit(), builder.uninit()),
        }
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<C>) {
        self.size.assign(src.size.into(), builder);
        self.points.assign(src.points.clone(), builder);
    }

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();
        Usize::<C::N>::assert_eq(lhs.size, rhs.size, builder);
        Array::<C, Ext<C::F, C::EF>>::assert_eq(lhs.points, rhs.points, builder);
        Array::<C, Array<C, Ext<C::F, C::EF>>>::assert_eq(lhs.values, rhs.values, builder);
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();
        Usize::<C::N>::assert_ne(lhs.size, rhs.size, builder);
        Array::<C, Ext<C::F, C::EF>>::assert_ne(lhs.points, rhs.points, builder);
        Array::<C, Array<C, Ext<C::F, C::EF>>>::assert_ne(lhs.values, rhs.values, builder);
    }
}

impl<C: Config> MemVariable<C> for TwoAdicPcsMats<C> {
    fn size_of() -> usize {
        2
    }

    fn load(&self, ptr: Ptr<<C as Config>::N>, builder: &mut Builder<C>) {
        let address = builder.eval(ptr + Usize::Const(0));
        self.size.load(address, builder);
        let address = builder.eval(ptr + Usize::Const(1));
        self.points.load(address, builder);
    }

    fn store(&self, ptr: Ptr<<C as Config>::N>, builder: &mut Builder<C>) {
        let address = builder.eval(ptr + Usize::Const(0));
        self.size.store(address, builder);
        let address = builder.eval(ptr + Usize::Const(1));
        self.points.store(address, builder);
    }
}

impl<C: Config> Variable<C> for BatchOpening<C> {
    type Expression = Self;

    fn uninit(builder: &mut Builder<C>) -> Self {
        BatchOpening {
            opened_values: Array::Dyn(builder.uninit(), builder.uninit()),
            opening_proof: Array::Dyn(builder.uninit(), builder.uninit()),
        }
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<C>) {
        self.opened_values
            .assign(src.opened_values.clone(), builder);
        self.opening_proof
            .assign(src.opening_proof.clone(), builder);
    }

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();
        Array::<C, Array<C, Felt<C::F>>>::assert_eq(lhs.opened_values, rhs.opened_values, builder);
        Array::<C, Array<C, Felt<C::F>>>::assert_eq(lhs.opening_proof, rhs.opening_proof, builder);
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();
        Array::<C, Array<C, Felt<C::F>>>::assert_ne(lhs.opened_values, rhs.opened_values, builder);
        Array::<C, Array<C, Felt<C::F>>>::assert_ne(lhs.opening_proof, rhs.opening_proof, builder);
    }
}

impl<C: Config> MemVariable<C> for BatchOpening<C> {
    fn size_of() -> usize {
        2
    }

    fn load(&self, ptr: Ptr<<C as Config>::N>, builder: &mut Builder<C>) {
        let address = builder.eval(ptr + Usize::Const(0));
        self.opened_values.load(address, builder);
        let address = builder.eval(ptr + Usize::Const(1));
        self.opening_proof.load(address, builder);
    }

    fn store(&self, ptr: Ptr<<C as Config>::N>, builder: &mut Builder<C>) {
        let address = builder.eval(ptr + Usize::Const(0));
        self.opened_values.store(address, builder);
        let address = builder.eval(ptr + Usize::Const(1));
        self.opening_proof.store(address, builder);
    }
}
