pub mod blake3;
pub mod edwards;
pub mod k256;
pub mod keccak256;
pub mod sha256;
pub mod weierstrass;

use num::BigUint;
use serde::{Deserialize, Serialize};

use crate::air::SP1AirBuilder;
use crate::operations::field::params::Limbs;
use crate::runtime::SyscallContext;
use crate::utils::ec::field::FieldParameters;
use crate::utils::ec::{AffinePoint, EllipticCurve};
use crate::{runtime::MemoryReadRecord, runtime::MemoryWriteRecord};

/// Elliptic curve add event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECAddEvent {
    pub shard: u32,
    pub clk: u32,
    pub p_ptr: u32,
    pub p: [u32; 16],
    pub q_ptr: u32,
    pub q: [u32; 16],
    pub p_memory_records: [MemoryWriteRecord; 16],
    pub q_memory_records: [MemoryReadRecord; 16],
}

pub fn create_ec_add_event<E: EllipticCurve>(
    rt: &mut SyscallContext,
    arg1: u32,
    arg2: u32,
) -> ECAddEvent {
    let start_clk = rt.clk;
    let p_ptr = arg1;
    if p_ptr % 4 != 0 {
        panic!();
    }
    let q_ptr = arg2;
    if q_ptr % 4 != 0 {
        panic!();
    }

    let p: [u32; 16] = rt.slice_unsafe(p_ptr, 16).try_into().unwrap();
    let (q_memory_records_vec, q_vec) = rt.mr_slice(q_ptr, 16);
    let q_memory_records = q_memory_records_vec.try_into().unwrap();
    let q: [u32; 16] = q_vec.try_into().unwrap();
    // When we write to p, we want the clk to be incremented because p and q could be the same.
    rt.clk += 1;

    let p_affine = AffinePoint::<E>::from_words_le(&p);
    let q_affine = AffinePoint::<E>::from_words_le(&q);
    let result_affine = p_affine + q_affine;
    let result_words = result_affine.to_words_le();
    let p_memory_records = rt.mw_slice(p_ptr, &result_words).try_into().unwrap();

    ECAddEvent {
        shard: rt.current_shard(),
        clk: start_clk,
        p_ptr,
        p,
        q_ptr,
        q,
        p_memory_records,
        q_memory_records,
    }
}

/// Elliptic curve double event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECDoubleEvent {
    pub shard: u32,
    pub clk: u32,
    pub p_ptr: u32,
    pub p: [u32; 16],
    pub p_memory_records: [MemoryWriteRecord; 16],
}

pub fn create_ec_double_event<E: EllipticCurve>(
    rt: &mut SyscallContext,
    arg1: u32,
    _: u32,
) -> ECDoubleEvent {
    let start_clk = rt.clk;
    let p_ptr = arg1;
    if p_ptr % 4 != 0 {
        panic!();
    }

    let p: [u32; 16] = rt.slice_unsafe(p_ptr, 16).try_into().unwrap();
    let p_affine = AffinePoint::<E>::from_words_le(&p);
    let result_affine = E::ec_double(&p_affine);
    let result_words = result_affine.to_words_le();
    let p_memory_records = rt.mw_slice(p_ptr, &result_words).try_into().unwrap();

    ECDoubleEvent {
        shard: rt.current_shard(),
        clk: start_clk,
        p_ptr,
        p,
        p_memory_records,
    }
}

pub fn limbs_from_biguint<AB, F: FieldParameters>(value: &BigUint) -> Limbs<AB::Expr>
where
    AB: SP1AirBuilder,
{
    let a_const = F::to_limbs_field::<AB::F>(value);
    Limbs::<AB::Expr>(a_const.0.map(|x| x.into()))
}
