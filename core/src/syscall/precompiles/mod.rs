pub mod blake3;
pub mod edwards;
pub mod k256;
pub mod keccak256;
pub mod sha256;
pub mod weierstrass;
use crate::runtime::SyscallContext;
use crate::utils::ec::field::NumWords;
use core::fmt::Debug;
use serde::{Deserialize, Serialize};
use typenum::Unsigned;

use crate::utils::ec::{AffinePoint, EllipticCurve};
use crate::{runtime::MemoryReadRecord, runtime::MemoryWriteRecord};

/// Elliptic curve add event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECAddEvent {
    pub shard: u32,
    pub clk: u32,
    pub p_ptr: u32,
    pub p: Vec<u32>,
    pub q_ptr: u32,
    pub q: Vec<u32>,
    pub p_memory_records: Vec<MemoryWriteRecord>,
    pub q_memory_records: Vec<MemoryReadRecord>,
}

/// Create an elliptic curve add event. It takes two pointers to memory locations, reads the points
/// from memory, adds them together, and writes the result back to the first memory location.
/// The generic parameter `N` is the number of u32 words in the point representation. For example, for
/// the secp256k1 curve, `N` would be 16 (64 bytes) because the x and y coordinates are 32 bytes each.
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

    let num_words = <E::BaseField as NumWords>::WordsCurvePoint::USIZE;

    let p = rt.slice_unsafe(p_ptr, num_words);

    let (q_memory_records, q) = rt.mr_slice(q_ptr, num_words);

    // When we write to p, we want the clk to be incremented because p and q could be the same.
    rt.clk += 1;

    let p_affine = AffinePoint::<E>::from_words_le(&p);
    let q_affine = AffinePoint::<E>::from_words_le(&q);
    let result_affine = p_affine + q_affine;

    let result_words = result_affine.to_words_le();

    let p_memory_records = rt.mw_slice(p_ptr, &result_words);

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
    pub p: Vec<u32>,
    pub p_memory_records: Vec<MemoryWriteRecord>,
}

/// Create an elliptic curve double event. It takes a pointer to a memory location, reads the point
/// from memory, doubles it, and writes the result back to the memory location. The generic parameter
/// `N` is the number of u32 words in the point representation. For example, for the secp256k1 curve, `N`
/// would be 16 (64 bytes) because the x and y coordinates are 32 bytes each.
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

    let num_words = <E::BaseField as NumWords>::WordsCurvePoint::USIZE;

    // Read N words from memory.
    let p = rt.slice_unsafe(p_ptr, num_words);

    let p_affine = AffinePoint::<E>::from_words_le(&p);

    let result_affine = E::ec_double(&p_affine);

    let result_words = result_affine.to_words_le();

    let p_memory_records = rt.mw_slice(p_ptr, &result_words);

    ECDoubleEvent {
        shard: rt.current_shard(),
        clk: start_clk,
        p_ptr,
        p,
        p_memory_records,
    }
}
