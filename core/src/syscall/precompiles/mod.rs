pub mod edwards;
pub mod keccak256;
pub mod sha256;
pub mod uint256;
pub mod weierstrass;
use crate::operations::field::params::{NumLimbs, NumWords};
use crate::runtime::SyscallContext;
use crate::utils::ec::weierstrass::bls12_381::bls12381_decompress;
use crate::utils::ec::weierstrass::secp256k1::secp256k1_decompress;
use crate::utils::ec::CurveType;
use crate::utils::ec::{AffinePoint, EllipticCurve};
use crate::utils::{bytes_to_words_le_vec, words_to_bytes_le_vec};
use crate::{runtime::MemoryReadRecord, runtime::MemoryWriteRecord};
use typenum::Unsigned;

use core::fmt::Debug;
use serde::{Deserialize, Serialize};

/// Elliptic curve add event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECAddEvent {
    pub lookup_id: u128,
    pub shard: u32,
    pub channel: u8,
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
        lookup_id: rt.syscall_lookup_id,
        shard: rt.current_shard(),
        channel: rt.current_channel(),
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
    pub lookup_id: u128,
    pub shard: u32,
    pub channel: u8,
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

    let p = rt.slice_unsafe(p_ptr, num_words);

    let p_affine = AffinePoint::<E>::from_words_le(&p);

    let result_affine = E::ec_double(&p_affine);

    let result_words = result_affine.to_words_le();

    let p_memory_records = rt.mw_slice(p_ptr, &result_words);

    ECDoubleEvent {
        lookup_id: rt.syscall_lookup_id,
        shard: rt.current_shard(),
        channel: rt.current_channel(),
        clk: start_clk,
        p_ptr,
        p,
        p_memory_records,
    }
}

/// Elliptic curve point decompress event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECDecompressEvent {
    pub lookup_id: u128,
    pub shard: u32,
    pub channel: u8,
    pub clk: u32,
    pub ptr: u32,
    pub sign_bit: bool,
    pub x_bytes: Vec<u8>,
    pub decompressed_y_bytes: Vec<u8>,
    pub x_memory_records: Vec<MemoryReadRecord>,
    pub y_memory_records: Vec<MemoryWriteRecord>,
}

pub fn create_ec_decompress_event<E: EllipticCurve>(
    rt: &mut SyscallContext,
    slice_ptr: u32,
    sign_bit: u32,
) -> ECDecompressEvent {
    let start_clk = rt.clk;
    assert!(slice_ptr % 4 == 0, "slice_ptr must be 4-byte aligned");
    assert!(sign_bit <= 1, "is_odd must be 0 or 1");

    let num_limbs = <E::BaseField as NumLimbs>::Limbs::USIZE;
    let num_words_field_element = num_limbs / 4;

    let (x_memory_records, x_vec) =
        rt.mr_slice(slice_ptr + (num_limbs as u32), num_words_field_element);

    let x_bytes = words_to_bytes_le_vec(&x_vec);
    let mut x_bytes_be = x_bytes.clone();
    x_bytes_be.reverse();

    let decompress_fn = match E::CURVE_TYPE {
        CurveType::Secp256k1 => secp256k1_decompress::<E>,
        CurveType::Bls12381 => bls12381_decompress::<E>,
        _ => panic!("Unsupported curve"),
    };

    let computed_point: AffinePoint<E> = decompress_fn(&x_bytes_be, sign_bit);

    let mut decompressed_y_bytes = computed_point.y.to_bytes_le();
    decompressed_y_bytes.resize(num_limbs, 0u8);
    let y_words = bytes_to_words_le_vec(&decompressed_y_bytes);

    let y_memory_records = rt.mw_slice(slice_ptr, &y_words);

    ECDecompressEvent {
        lookup_id: rt.syscall_lookup_id,
        shard: rt.current_shard(),
        channel: rt.current_channel(),
        clk: start_clk,
        ptr: slice_ptr,
        sign_bit: sign_bit != 0,
        x_bytes: x_bytes.to_vec(),
        decompressed_y_bytes,
        x_memory_records,
        y_memory_records,
    }
}
