//! BLAKE2f compression function — Ethereum precompile 0x09 (EIP-152).
//!
//! Pure-software F compression function. SP1 has no BLAKE2 precompile
//! syscall, so we vendor the round function inline here. The reference
//! is EIP-152 / RFC 7693 §3.2.

use crate::precompile::types::{Blake2fMessage, Blake2fOffset, Blake2fState};
use crate::status::{ZKVM_EFAIL, ZKVM_EOK};

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

#[rustfmt::skip]
const SIGMA: [[usize; 16]; 10] = [
    [ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15],
    [14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3],
    [11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4],
    [ 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8],
    [ 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13],
    [ 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9],
    [12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11],
    [13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10],
    [ 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5],
    [10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0],
];

#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn read_u64_le(bytes: &[u8], i: usize) -> u64 {
    let off = i * 8;
    u64::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
        bytes[off + 4],
        bytes[off + 5],
        bytes[off + 6],
        bytes[off + 7],
    ])
}

fn write_u64_le(bytes: &mut [u8], i: usize, v: u64) {
    let off = i * 8;
    bytes[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// `zkvm_status zkvm_blake2f(rounds, h, m, t, f)`.
///
/// Updates `h` in place by running `rounds` iterations of the BLAKE2b
/// round function with message block `m`, offset counters `t`, and
/// final-block flag `f`. Pure software per EIP-152 / RFC 7693.
#[no_mangle]
pub unsafe extern "C" fn zkvm_blake2f(
    rounds: u32,
    h: *mut Blake2fState,
    m: *const Blake2fMessage,
    t: *const Blake2fOffset,
    f: u8,
) -> i32 {
    if h.is_null() || m.is_null() || t.is_null() {
        return ZKVM_EFAIL;
    }
    if f > 1 {
        return ZKVM_EFAIL;
    }

    let h_bytes = &mut (*h).data;
    let m_bytes = &(*m).data;
    let t_bytes = &(*t).data;

    let mut h_words = [0u64; 8];
    for (i, w) in h_words.iter_mut().enumerate() {
        *w = read_u64_le(h_bytes, i);
    }
    let mut m_words = [0u64; 16];
    for (i, w) in m_words.iter_mut().enumerate() {
        *w = read_u64_le(m_bytes, i);
    }
    let t0 = read_u64_le(t_bytes, 0);
    let t1 = read_u64_le(t_bytes, 1);

    let mut v = [0u64; 16];
    v[..8].copy_from_slice(&h_words);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t0;
    v[13] ^= t1;
    if f != 0 {
        v[14] = !v[14];
    }

    for i in 0..rounds {
        let s = &SIGMA[(i as usize) % 10];
        g(&mut v, 0, 4, 8, 12, m_words[s[0]], m_words[s[1]]);
        g(&mut v, 1, 5, 9, 13, m_words[s[2]], m_words[s[3]]);
        g(&mut v, 2, 6, 10, 14, m_words[s[4]], m_words[s[5]]);
        g(&mut v, 3, 7, 11, 15, m_words[s[6]], m_words[s[7]]);
        g(&mut v, 0, 5, 10, 15, m_words[s[8]], m_words[s[9]]);
        g(&mut v, 1, 6, 11, 12, m_words[s[10]], m_words[s[11]]);
        g(&mut v, 2, 7, 8, 13, m_words[s[12]], m_words[s[13]]);
        g(&mut v, 3, 4, 9, 14, m_words[s[14]], m_words[s[15]]);
    }

    for (i, w) in h_words.iter_mut().enumerate() {
        *w ^= v[i] ^ v[i + 8];
        write_u64_le(h_bytes, i, *w);
    }

    ZKVM_EOK
}
