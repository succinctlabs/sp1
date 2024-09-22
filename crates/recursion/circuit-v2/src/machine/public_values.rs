use itertools::Itertools;
use sp1_recursion_compiler::ir::{Builder, Felt};
use sp1_recursion_core_v2::{
    air::{RecursionPublicValues, NUM_PV_ELMS_TO_HASH},
    DIGEST_SIZE,
};

use crate::{hash::Posedion2BabyBearHasherVariable, CircuitConfig};

/// Verifies the digest of a recursive public values struct.
pub(crate) fn assert_recursion_public_values_valid<C, H>(
    builder: &mut Builder<C>,
    public_values: &RecursionPublicValues<Felt<C::F>>,
) where
    C: CircuitConfig,
    H: Posedion2BabyBearHasherVariable<C>,
{
    let digest = public_values_digest::<C, H>(builder, public_values);
    for (value, expected) in public_values.digest.iter().copied().zip_eq(digest) {
        builder.assert_felt_eq(value, expected);
    }
}

/// Verifies the digest of a recursive public values struct.
pub(crate) fn public_values_digest<C, H>(
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
