use crate::prelude::{Array, Builder, Config, Felt, MemVariable, Ptr, Usize, Variable};
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
    pub commit_phase_openings: Array<C, FmtCommitPhaseProofStep<C>>,
    pub phantom: PhantomData<C>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L32
#[derive(Clone)]
pub struct FmtCommitPhaseProofStep<C: Config> {
    pub sibling_value: Felt<C::F>,
    pub opening_proof: Array<C, Hash<C>>,
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
        let lhs = lhs.into();
        let rhs = rhs.into();
        builder.assert_felt_eq(lhs[0], rhs[0]);
        builder.assert_felt_eq(lhs[1], rhs[1]);
        builder.assert_felt_eq(lhs[2], rhs[2]);
        builder.assert_felt_eq(lhs[3], rhs[3]);
        builder.assert_felt_eq(lhs[4], rhs[4]);
        builder.assert_felt_eq(lhs[5], rhs[5]);
        builder.assert_felt_eq(lhs[6], rhs[6]);
        builder.assert_felt_eq(lhs[7], rhs[7]);
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();
        builder.assert_felt_ne(lhs[0], rhs[0]);
        builder.assert_felt_ne(lhs[1], rhs[1]);
        builder.assert_felt_ne(lhs[2], rhs[2]);
        builder.assert_felt_ne(lhs[3], rhs[3]);
        builder.assert_felt_ne(lhs[4], rhs[4]);
        builder.assert_felt_ne(lhs[5], rhs[5]);
        builder.assert_felt_ne(lhs[6], rhs[6]);
        builder.assert_felt_ne(lhs[7], rhs[7]);
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
        let address = builder.eval(ptr + Usize::Const(0));
        self[0].store(address, builder);
        let address = builder.eval(ptr + Usize::Const(1));
        self[1].store(address, builder);
        let address = builder.eval(ptr + Usize::Const(2));
        self[2].store(address, builder);
        let address = builder.eval(ptr + Usize::Const(3));
        self[3].store(address, builder);
        let address = builder.eval(ptr + Usize::Const(4));
        self[4].store(address, builder);
        let address = builder.eval(ptr + Usize::Const(5));
        self[5].store(address, builder);
        let address = builder.eval(ptr + Usize::Const(6));
        self[6].store(address, builder);
        let address = builder.eval(ptr + Usize::Const(7));
        self[7].store(address, builder);
    }
}

impl<C: Config> Variable<C> for FmtCommitPhaseProofStep<C> {
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
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        todo!()
    }
}

impl<C: Config> MemVariable<C> for FmtCommitPhaseProofStep<C> {
    fn size_of() -> usize {
        todo!()
    }

    fn load(&self, ptr: Ptr<<C as Config>::N>, builder: &mut Builder<C>) {
        todo!()
    }

    fn store(&self, ptr: Ptr<<C as Config>::N>, builder: &mut Builder<C>) {
        todo!()
    }
}
