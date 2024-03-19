use crate::prelude::{Builder, Config, Felt, MemVariable, Ptr, Usize, Variable};
use std::marker::PhantomData;

/// The current verifier implementation assumes that we are using a 256-bit hash with 32-bit elements.
pub const DIGEST_SIZE: usize = 8;

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/merkle-tree/src/mmcs.rs#L54
#[allow(type_alias_bounds)]
pub type Hash<C: Config> = [Felt<C::F>; DIGEST_SIZE];

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/config.rs#L1
pub struct FriConfig {
    pub log_blowup: usize,
    pub num_queries: usize,
    pub proof_of_work_bits: usize,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L23
pub struct FmtQueryProof<C: Config> {
    pub commit_phase_openings: Vec<FmtCommitPhaseProofStep<C>>,
    pub phantom: PhantomData<C>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L32
pub struct FmtCommitPhaseProofStep<C: Config> {
    pub sibling_value: Felt<C::F>,
    pub opening_proof: Vec<Hash<C>>,
    pub phantom: PhantomData<C>,
}

impl<C: Config> Variable<C> for Hash<C> {
    type Expression = Self;

    fn uninit(builder: &mut Builder<C>) -> Self {
        [
            Felt::uninit(builder),
            Felt::uninit(builder),
            Felt::uninit(builder),
            Felt::uninit(builder),
            Felt::uninit(builder),
            Felt::uninit(builder),
            Felt::uninit(builder),
            Felt::uninit(builder),
        ]
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<C>) {
        builder.assign(self[0], src[0]);
        builder.assign(self[1], src[1]);
        builder.assign(self[2], src[2]);
        builder.assign(self[3], src[3]);
        builder.assign(self[4], src[4]);
        builder.assign(self[5], src[5]);
        builder.assign(self[6], src[6]);
        builder.assign(self[7], src[7]);
    }

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        builder.assert_felt_eq(lhs.into()[0], rhs.into()[0]);
        builder.assert_felt_eq(lhs.into()[1], rhs.into()[1]);
        builder.assert_felt_eq(lhs.into()[2], rhs.into()[2]);
        builder.assert_felt_eq(lhs.into()[3], rhs.into()[3]);
        builder.assert_felt_eq(lhs.into()[4], rhs.into()[4]);
        builder.assert_felt_eq(lhs.into()[5], rhs.into()[5]);
        builder.assert_felt_eq(lhs.into()[6], rhs.into()[6]);
        builder.assert_felt_eq(lhs.into()[7], rhs.into()[7]);
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        builder.assert_felt_ne(lhs.into()[0], rhs.into()[0]);
        builder.assert_felt_ne(lhs.into()[1], rhs.into()[1]);
        builder.assert_felt_ne(lhs.into()[2], rhs.into()[2]);
        builder.assert_felt_ne(lhs.into()[3], rhs.into()[3]);
        builder.assert_felt_ne(lhs.into()[4], rhs.into()[4]);
        builder.assert_felt_ne(lhs.into()[5], rhs.into()[5]);
        builder.assert_felt_ne(lhs.into()[6], rhs.into()[6]);
        builder.assert_felt_ne(lhs.into()[7], rhs.into()[7]);
    }
}

impl<C: Config> MemVariable<C> for Hash<C> {
    fn size_of() -> usize {
        <Felt<C::F> as MemVariable<C>>::size_of() * DIGEST_SIZE
    }

    fn load(&self, ptr: Ptr<<C as Config>::N>, builder: &mut Builder<C>) {
        let address = builder.eval(ptr + Usize::Const(0));
        self[0].load(address, builder);
        let address = builder.eval(ptr + Usize::Const(1));
        self[1].load(address, builder);
        let address = builder.eval(ptr + Usize::Const(2));
        self[2].load(address, builder);
        let address = builder.eval(ptr + Usize::Const(3));
        self[3].load(address, builder);
        let address = builder.eval(ptr + Usize::Const(4));
        self[4].load(address, builder);
        let address = builder.eval(ptr + Usize::Const(5));
        self[5].load(address, builder);
        let address = builder.eval(ptr + Usize::Const(6));
        self[6].load(address, builder);
        let address = builder.eval(ptr + Usize::Const(7));
        self[7].load(address, builder);
    }

    fn store(&self, ptr: Ptr<<C as Config>::N>, builder: &mut Builder<C>) {
        todo!()
    }
}
