use crate::{
    events::MemoryReadRecord,
    syscalls::{Syscall, SyscallCode, SyscallContext},
};

pub(crate) struct Blake2fCompressSyscall;

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

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

impl Syscall for Blake2fCompressSyscall {
    fn execute(
        &self,
        rt: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let base_ptr = arg1;
        assert!(arg2 == 0, "arg2 must be 0");
        let start_clk = rt.clk;

        // Read from memory
        let mut read_records: Vec<MemoryReadRecord> = Vec::new();

        // Layout defined in blake2f here: https://www.evm.codes/precompiled
        // rounds: 4 bytes, u32 big endian
        let (rounds_record, rounds_u32) = rt.mr(base_ptr);
        let rounds = rounds_u32.to_be();
        read_records.push(rounds_record);

        // h (state): 64 bytes, 8 * 64-bit words, i.e. 16 * 32 bits
        let (h_records, h_words) = rt.mr_slice(base_ptr + 4, 16);
        let h: [u64; 8] = words_to_u64_le::<8>(&h_words);
        read_records.extend(h_records);

        // m (message): 128 bytes, 16 * 64-bit words
        let (m_records, m_words) = rt.mr_slice(base_ptr + 68, 32);
        let m: [u64; 16] = words_to_u64_le::<16>(&m_words);
        read_records.extend(m_records);

        // t1, t2: 16 bytes, 2 * 64-bit words
        let (t_records, t_words) = rt.mr_slice(base_ptr + 196, 4);
        let [t0, t1]: [u64; 2] = words_to_u64_le::<2>(&t_words);
        read_records.extend(t_records);

        // f (final block indicator): 1 bytes
        let (f_record, f_u32) = rt.mr(base_ptr + 212);
        let f = f_u32 & 0xFF != 0;
        read_records.push(f_record);

        // Perform actual blake2f compress
        let result = compress(rounds, h, m, t0, t1, f);

        // Split back into u32 words
        let result_u32: [u32; 16] = u64_slice_to_words_le::<16>(&result);

        // Write
        rt.clk += 1;
        let write_records = rt.mw_slice(base_ptr + 213, &result_u32);

        None
    }
}

// Core compression function, see https://datatracker.ietf.org/doc/html/rfc7693#section-3.2
#[allow(clippy::many_single_char_names)]
pub fn compress(rounds: u32, h: [u64; 8], m: [u64; 16], t0: u64, t1: u64, f: bool) -> [u64; 8] {
    // Build internal state
    let mut v = [0u64; 16];

    // Take h state
    v[..8].copy_from_slice(&h);
    // Second half from IV
    v[8..].copy_from_slice(&IV);

    // XOR in offsets
    v[12] ^= t0;
    v[13] ^= t1;

    // If final round, invert word
    if f {
        v[14] = !v[14];
    }

    for i in 0..rounds as usize {
        let s = &SIGMA[i % 10];
        G(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        G(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        G(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        G(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        G(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        G(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        G(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        G(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    let mut out = [0u64; 8];
    for i in 0..8 {
        out[i] = h[i] ^ v[i] ^ v[i + 8];
    }
    out
}

#[inline(always)]
#[allow(clippy::many_single_char_names, non_snake_case)]
// G mixing function, see: https://datatracker.ietf.org/doc/html/rfc7693#section-3.1
fn G(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// Convert `2 * len` u32s into a `[u64; len]` assuming little-endian encoding.
fn words_to_u64_le<const N: usize>(words: &[u32]) -> [u64; N] {
    assert_eq!(words.len(), 2 * N, "Expected {} u32s for {} u64s", 2 * N, N);

    let mut result = [0u64; N];
    for i in 0..N {
        let lo = words[2 * i] as u64;
        let hi = words[2 * i + 1] as u64;
        result[i] = lo | (hi << 32);
    }
    result
}

/// Converts a slice of `u64` values into a `Vec<u32>` (little-endian: low 32 bits first).
fn u64_slice_to_words_le<const N: usize>(words: &[u64]) -> [u32; N] {
    assert_eq!(words.len(), N / 2, "Expected {} u64s for {} u32s", N / 2, N);

    let mut result = [0u32; N];
    for i in 0..N {
        result[2 * i] = words[i] as u32; // low 32 bits
        result[2 * i + 1] = (words[i] >> 32) as u32; // high 32 bits
    }
    result
}
