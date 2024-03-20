use crate::prelude::{Array, Builder, Config, Felt, MemVariable, Ptr, Usize, Var, Variable};
use std::marker::PhantomData;

/// The width of the Poseidon2 permutation.
pub const PERMUTATION_WIDTH: usize = 16;

/// The current verifier implementation assumes that we are using a 256-bit hash with 32-bit elements.
pub const DIGEST_SIZE: usize = 8;

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/merkle-tree/src/mmcs.rs#L54
#[allow(type_alias_bounds)]
pub type Commitment<C: Config> = Array<C, Felt<C::F>>;

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/config.rs#L1
pub struct FriConfig {
    pub log_blowup: usize,
    pub num_queries: usize,
    pub proof_of_work_bits: usize,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L12
pub struct FriProof<C: Config> {
    pub commit_phase_commits: Array<C, Commitment<C>>,
    pub query_proofs: Array<C, FriQueryProof<C>>,
    pub final_poly: Felt<C::F>,
    pub pow_witness: Var<C::N>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L23
#[derive(Clone)]
pub struct FriQueryProof<C: Config> {
    pub commit_phase_openings: Array<C, FriCommitPhaseProofStep<C>>,
    pub phantom: PhantomData<C>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L32
#[derive(Clone)]
pub struct FriCommitPhaseProofStep<C: Config> {
    pub sibling_value: Felt<C::F>,
    pub opening_proof: Array<C, Commitment<C>>,
    pub phantom: PhantomData<C>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L22
pub struct FriChallenges<C: Config> {
    pub query_indices: Array<C, Var<C::N>>,
    pub betas: Array<C, Felt<C::F>>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/matrix/src/lib.rs#L38
pub struct Dimensions<C: Config> {
    pub width: usize,
    pub height: Usize<C::N>,
}

impl<C: Config> Variable<C> for FriQueryProof<C> {
    type Expression = Self;

    fn uninit(builder: &mut Builder<C>) -> Self {
        FriQueryProof {
            commit_phase_openings: Array::Dyn(builder.uninit(), builder.uninit()),
            phantom: PhantomData,
        }
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<C>) {
        self.commit_phase_openings
            .assign(src.commit_phase_openings, builder);
    }

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();
        Array::<C, FriCommitPhaseProofStep<C>>::assert_eq(
            lhs.commit_phase_openings,
            rhs.commit_phase_openings,
            builder,
        );
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();
        Array::<C, FriCommitPhaseProofStep<C>>::assert_ne(
            lhs.commit_phase_openings,
            rhs.commit_phase_openings,
            builder,
        );
    }
}

impl<C: Config> MemVariable<C> for FriQueryProof<C> {
    fn size_of() -> usize {
        1
    }

    fn load(&self, ptr: Ptr<C::N>, builder: &mut Builder<C>) {
        let address = builder.eval(ptr + Usize::Const(0));
        self.commit_phase_openings.load(address, builder);
    }

    fn store(&self, ptr: Ptr<<C as Config>::N>, builder: &mut Builder<C>) {
        let address = builder.eval(ptr + Usize::Const(0));
        self.commit_phase_openings.store(address, builder);
    }
}

impl<C: Config> Variable<C> for FriCommitPhaseProofStep<C> {
    type Expression = Self;

    fn uninit(builder: &mut Builder<C>) -> Self {
        Self {
            sibling_value: builder.uninit(),
            opening_proof: Array::Dyn(builder.uninit(), builder.uninit()),
            phantom: PhantomData,
        }
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<C>) {
        self.sibling_value.assign(src.sibling_value.into(), builder);
        self.opening_proof.assign(src.opening_proof, builder);
    }

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();
        Felt::<C::F>::assert_eq(lhs.sibling_value, rhs.sibling_value, builder);
        Array::<C, Commitment<C>>::assert_eq(lhs.opening_proof, rhs.opening_proof, builder);
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();
        Felt::<C::F>::assert_ne(lhs.sibling_value, rhs.sibling_value, builder);
        Array::<C, Commitment<C>>::assert_ne(lhs.opening_proof, rhs.opening_proof, builder);
    }
}

impl<C: Config> MemVariable<C> for FriCommitPhaseProofStep<C> {
    fn size_of() -> usize {
        let mut size = 0;
        size += <Felt<C::F> as MemVariable<C>>::size_of();
        size += Array::<C, Commitment<C>>::size_of();
        size
    }

    fn load(&self, ptr: Ptr<<C as Config>::N>, builder: &mut Builder<C>) {
        let address = builder.eval(ptr + Usize::Const(0));
        self.sibling_value.load(address, builder);
        let address = builder.eval(ptr + Usize::Const(<Felt<C::F> as MemVariable<C>>::size_of()));
        self.opening_proof.load(address, builder);
    }

    fn store(&self, ptr: Ptr<<C as Config>::N>, builder: &mut Builder<C>) {
        let address = builder.eval(ptr + Usize::Const(0));
        self.sibling_value.store(address, builder);
        let address = builder.eval(ptr + Usize::Const(<Felt<C::F> as MemVariable<C>>::size_of()));
        self.opening_proof.store(address, builder);
    }
}
