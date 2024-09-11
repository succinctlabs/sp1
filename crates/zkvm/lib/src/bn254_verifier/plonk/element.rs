use anyhow::{Error, Ok, Result};
use bn::Fr;
use lazy_static::lazy_static;
use num_bigint::{BigInt, Sign};
use num_traits::Num;
use std::cmp::Ordering;

#[derive(Clone, Debug)]
pub(crate) struct PlonkFr(Fr);

lazy_static! {
    static ref MODULUS: BigInt = BigInt::from_str_radix(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10
    )
    .unwrap();
}

impl PlonkFr {
    pub(crate) fn set_bytes(bytes: &[u8]) -> Result<Self> {
        let biguint_bytes = BigInt::from_bytes_be(Sign::Plus, bytes);

        let cmp = biguint_bytes.cmp(&MODULUS);
        if cmp == Ordering::Equal {
            return Ok(PlonkFr(Fr::zero()));
        } else if cmp != Ordering::Greater && bytes.cmp(&[0u8; 32][..]) != Ordering::Less {
            return Ok(PlonkFr(Fr::from_slice(bytes).map_err(Error::msg)?));
        }

        // Mod the bytes with MODULUS
        let biguint_bytes = BigInt::from_bytes_be(Sign::Plus, bytes);
        let biguint_mod = biguint_bytes % &*MODULUS;
        let (_, bytes_le) = biguint_mod.to_bytes_be();
        let e = Fr::from_slice(&bytes_le).map_err(Error::msg)?;

        Ok(PlonkFr(e))
    }

    pub(crate) fn into_fr(self) -> Result<Fr> {
        Ok(self.0)
    }
}
