use p3_field::AbstractField;
use p3_field::TwoAdicField;

use super::fri::verify_batch;
use super::types::Dimensions;
use super::{
    challenger::DuplexChallenger,
    fri::verify_shape_and_sample_challenges,
    types::{Commitment, FriConfig, FriProof},
};
use crate::prelude::MemVariable;
use crate::prelude::Ptr;
use crate::prelude::Var;
use crate::prelude::Variable;
use crate::prelude::{Array, Builder, Config, Ext, Felt, SymbolicExt, SymbolicFelt, Usize};

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

#[derive(Clone)]
pub struct TwoAdicPcsMats<C: Config> {
    pub size: Var<C::N>,
    pub values: Array<C, Ext<C::F, C::EF>>,
}

#[allow(unused_variables)]
pub fn verify_two_adic_pcs<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfig,
    rounds: Array<C, TwoAdicPcsRound<C>>,
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

    let start = Usize::Const(0);
    let end = Usize::Const(1); // TODO: Fix
    builder.range(start, end).for_each(|i, builder| {
        let query_opening = builder.get(&proof.query_openings, i);
        let ro: [Ext<C::F, C::EF>; 32] =
            [C::EF::zero(); 32].map(|x| builder.eval(SymbolicExt::Const(x)));
        let alpha_pow: [Ext<C::F, C::EF>; 32] =
            [C::EF::one(); 32].map(|x| builder.eval(SymbolicExt::Const(x)));
        let start = Usize::Const(0);
        let end = Usize::Const(1); // TODO: FIX
        builder.range(start, end).for_each(|j, builder| {
            let round = builder.get(&rounds, j);
            let batch_opening = builder.get(&query_opening, j);
            let batch_commit = round.batch_commit;
            let mats = builder.get(&round.mats, j);
            let dims = Dimensions::<C> {
                width: 2,
                height: mats.size,
            };
            verify_batch(
                builder,
                &batch_commit,
                &[dims],
                0,
                batch_opening.opened_values,
                &batch_opening.opening_proof,
            );
            let start = 0;
            let end = 1;
            builder.range(start, end).for_each(|k, builder| {
                // TODO:
            });
        });
    })

    // TODO: verify_challenges
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
        2
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
            values: Array::Dyn(builder.uninit(), builder.uninit()),
        }
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<C>) {
        self.size.assign(src.size.into(), builder);
        self.values.assign(src.values.clone(), builder);
    }

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();
        Usize::<C::N>::assert_eq(lhs.size, rhs.size, builder);
        Array::<C, Ext<C::F, C::EF>>::assert_eq(lhs.values, rhs.values, builder);
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();
        Usize::<C::N>::assert_ne(lhs.size, rhs.size, builder);
        Array::<C, Ext<C::F, C::EF>>::assert_ne(lhs.values, rhs.values, builder);
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
        self.values.load(address, builder);
    }

    fn store(&self, ptr: Ptr<<C as Config>::N>, builder: &mut Builder<C>) {
        let address = builder.eval(ptr + Usize::Const(0));
        self.size.store(address, builder);
        let address = builder.eval(ptr + Usize::Const(1));
        self.values.store(address, builder);
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
