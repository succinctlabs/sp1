use itertools::Itertools;
use sp1_derive::AlignedBorrow;
use sp1_recursion_compiler::ir::{Builder, Felt};
use sp1_recursion_core::{
    air::{RecursionPublicValues, NUM_PV_ELMS_TO_HASH},
    DIGEST_SIZE,
};
use sp1_stark::{air::PV_DIGEST_NUM_WORDS, Word};

use crate::{hash::Posedion2BabyBearHasherVariable, CircuitConfig};

#[derive(Debug, Clone, Copy, Default, AlignedBorrow)]
#[repr(C)]
pub struct RootPublicValues<T> {
    pub(crate) inner: RecursionPublicValues<T>,
}

/// Verifies the digest of a recursive public values struct.
pub(crate) fn assert_recursion_public_values_valid<C, H>(
    builder: &mut Builder<C>,
    public_values: &RecursionPublicValues<Felt<C::F>>,
) where
    C: CircuitConfig,
    H: Posedion2BabyBearHasherVariable<C>,
{
    let digest = recursion_public_values_digest::<C, H>(builder, public_values);
    for (value, expected) in public_values.digest.iter().copied().zip_eq(digest) {
        builder.assert_felt_eq(value, expected);
    }
}

/// Verifies the digest of a recursive public values struct.
pub(crate) fn recursion_public_values_digest<C, H>(
    builder: &mut Builder<C>,
    public_values: &RecursionPublicValues<Felt<C::F>>,
) -> [Felt<C::F>; DIGEST_SIZE]
where
    C: CircuitConfig,
    H: Posedion2BabyBearHasherVariable<C>,
{
    let pv_slice = public_values.as_array();
    H::poseidon2_hash(builder, &pv_slice[..NUM_PV_ELMS_TO_HASH])
}

/// Assert that the digest of the root public values is correct.
pub(crate) fn assert_root_public_values_valid<C, H>(
    builder: &mut Builder<C>,
    public_values: &RootPublicValues<Felt<C::F>>,
) where
    C: CircuitConfig,
    H: Posedion2BabyBearHasherVariable<C>,
{
    let expected_digest = root_public_values_digest::<C, H>(builder, &public_values.inner);
    for (value, expected) in public_values.inner.digest.iter().copied().zip_eq(expected_digest) {
        builder.assert_felt_eq(value, expected);
    }
}

/// Compute the digest of the root public values.
pub(crate) fn root_public_values_digest<C, H>(
    builder: &mut Builder<C>,
    public_values: &RecursionPublicValues<Felt<C::F>>,
) -> [Felt<C::F>; DIGEST_SIZE]
where
    C: CircuitConfig,
    H: Posedion2BabyBearHasherVariable<C>,
{
    let input = public_values
        .sp1_vk_digest
        .into_iter()
        .chain(public_values.committed_value_digest.into_iter().flat_map(|word| word.0.into_iter()))
        .collect::<Vec<_>>();
    H::poseidon2_hash(builder, &input)
}

impl<T> RootPublicValues<T> {
    pub const fn new(inner: RecursionPublicValues<T>) -> Self {
        Self { inner }
    }

    #[inline]
    pub const fn sp1_vk_digest(&self) -> &[T; DIGEST_SIZE] {
        &self.inner.sp1_vk_digest
    }

    #[inline]
    pub const fn committed_value_digest(&self) -> &[Word<T>; PV_DIGEST_NUM_WORDS] {
        &self.inner.committed_value_digest
    }

    #[inline]
    pub const fn digest(&self) -> &[T; DIGEST_SIZE] {
        &self.inner.digest
    }
}
