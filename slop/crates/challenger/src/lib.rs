#![allow(clippy::disallowed_types)]
mod synchronize;

use std::fmt::Debug;

use num_bigint::BigUint;
pub use p3_challenger::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use slop_algebra::{ExtensionField, Field, PrimeField32};
use slop_symmetric::{CryptographicHasher, PseudoCompressionFunction};
pub use synchronize::*;
use thiserror::Error;

pub trait FromChallenger<Challenger, A>: Sized {
    fn from_challenger(challenger: &Challenger, backend: &A) -> Self;
}

impl<Challenger: Clone, A> FromChallenger<Challenger, A> for Challenger {
    fn from_challenger(challenger: &Challenger, _backend: &A) -> Self {
        challenger.clone()
    }
}

/// A trait packaging together the types that usually appear in interactive oracle proofs in the
/// context of SP1: a field and a its cryptographically secure extension, a Fiat-Shamir challenger,
/// and a succinct commitment to data.
pub trait IopCtx:
    Clone + 'static + Send + Sync + Serialize + for<'de> Deserialize<'de> + Debug + Default
{
    type F: PrimeField32 + Ord;
    type EF: ExtensionField<Self::F>;
    type Digest: 'static
        + Copy
        + Send
        + Sync
        + Serialize
        + DeserializeOwned
        + Debug
        + PartialEq
        + Eq;
    type Challenger: VariableLengthChallenger<Self::F, Self::Digest>
        + GrindingChallenger
        + 'static
        + Send
        + Sync
        + Clone;

    type Hasher: CryptographicHasher<Self::F, Self::Digest> + Send + Sync + Clone;
    type Compressor: PseudoCompressionFunction<Self::Digest, 2> + Send + Sync + Clone;

    fn default_hasher_and_compressor() -> (Self::Hasher, Self::Compressor);

    fn default_challenger() -> Self::Challenger;
}

#[derive(Error, Debug, Clone, Copy, Eq, PartialEq)]
#[error("usize out of field bounds")]
pub struct USizeOutOfFieldBounds;

pub trait VariableLengthChallenger<F: Field, Digest: Copy>:
    FieldChallenger<F> + CanObserve<Digest>
{
    fn observe_variable_length_slice(&mut self, data: &[F]) -> Result<(), USizeOutOfFieldBounds> {
        let data_len_big_uint = BigUint::from(data.len());

        if data_len_big_uint >= F::order() {
            return Err(USizeOutOfFieldBounds);
        }
        self.observe(F::from_canonical_u32(data.len() as u32));
        self.observe_slice(data);
        Ok(())
    }
    fn observe_variable_length_extension_slice<EF: ExtensionField<F>>(
        &mut self,
        data: &[EF],
    ) -> Result<(), USizeOutOfFieldBounds> {
        let data_len_big_uint = BigUint::from(data.len());

        if data_len_big_uint >= F::order() {
            return Err(USizeOutOfFieldBounds);
        }
        self.observe(F::from_canonical_u32(data.len() as u32));
        for &item in data {
            self.observe_ext_element(item);
        }
        Ok(())
    }
    fn observe_constant_length_slice(&mut self, data: &[F]) {
        self.observe_slice(data);
    }
    fn observe_constant_length_extension_slice<EF: ExtensionField<F>>(&mut self, data: &[EF]) {
        for &item in data {
            self.observe_ext_element(item);
        }
    }
    fn observe_constant_length_digest_slice(&mut self, data: &[Digest]) {
        self.observe_slice(data);
    }
    fn observe_variable_length_digest_slice(
        &mut self,
        data: &[Digest],
    ) -> Result<(), USizeOutOfFieldBounds> {
        let data_len_big_uint = BigUint::from(data.len());

        if data_len_big_uint >= F::order() {
            return Err(USizeOutOfFieldBounds);
        }
        self.observe(F::from_canonical_u32(data.len() as u32));
        self.observe_slice(data);
        Ok(())
    }
}

impl<F: Field, Digest: Copy, C: FieldChallenger<F> + CanObserve<Digest>>
    VariableLengthChallenger<F, Digest> for C
{
}
