use slop_algebra::{AbstractField, PrimeField32};
use sp1_hypercube::{
    septic_curve::SepticCurve,
    septic_digest::{CURVE_CUMULATIVE_SUM_START_X, CURVE_CUMULATIVE_SUM_START_Y},
    septic_extension::SepticExtension,
};
use sp1_jit::SyscallContext;
use sp1_primitives::SP1Field;

/// Number of u64 words used to hold a septic curve point in memory (14 u32 words = 7 u64 words).
const SEPTIC_POINT_U64_WORDS: usize = 7;

/// Number of u64 words used to hold a 256-bit scalar (8 u32 words = 4 u64 words).
const SEPTIC_SCALAR_U64_WORDS: usize = 4;

/// Scalar bit length (256 bits = 4 u64 words).
const SEPTIC_SCALAR_BITS: usize = SEPTIC_SCALAR_U64_WORDS * 64;

/// The standard generator point for the septic curve, matching
/// `CURVE_CUMULATIVE_SUM_START` from `sp1_hypercube::septic_digest`.
fn septic_generator() -> SepticCurve<SP1Field> {
    let mut x = [SP1Field::zero(); 7];
    let mut y = [SP1Field::zero(); 7];
    for i in 0..7 {
        x[i] = SP1Field::from_canonical_u32(CURVE_CUMULATIVE_SUM_START_X[i]);
        y[i] = SP1Field::from_canonical_u32(CURVE_CUMULATIVE_SUM_START_Y[i]);
    }
    SepticCurve { x: SepticExtension(x), y: SepticExtension(y) }
}

/// Shamir's trick: compute `s*G + e*A` with shared doublings (MSB-first).
///
/// Runs ~381 EC operations instead of ~651 for two independent scalar mults: one
/// precomputed `G+A`, then at each bit position a shared double plus (at most)
/// a conditional add. Returns `(result, set)` where `set = false` indicates
/// both scalars were zero and the caller should emit the zero sentinel point.
fn shamirs_trick(
    g: SepticCurve<SP1Field>,
    a: SepticCurve<SP1Field>,
    s: &[u64; SEPTIC_SCALAR_U64_WORDS],
    e: &[u64; SEPTIC_SCALAR_U64_WORDS],
) -> (SepticCurve<SP1Field>, bool) {
    let g_plus_a = g.add_incomplete(a);

    let mut highest: Option<usize> = None;
    for pos in 0..SEPTIC_SCALAR_BITS {
        let word = pos / 64;
        let bit = pos % 64;
        if ((s[word] | e[word]) >> bit) & 1 == 1 {
            highest = Some(pos);
        }
    }

    let Some(highest) = highest else {
        return (
            SepticCurve {
                x: SepticExtension([SP1Field::zero(); 7]),
                y: SepticExtension([SP1Field::zero(); 7]),
            },
            false,
        );
    };

    let mut result = g;
    let mut result_set = false;

    for pos in (0..=highest).rev() {
        if result_set {
            result = result.double();
        }

        let word = pos / 64;
        let bit = pos % 64;
        let s_bit = (s[word] >> bit) & 1 == 1;
        let e_bit = (e[word] >> bit) & 1 == 1;

        let to_add = match (s_bit, e_bit) {
            (true, true) => Some(g_plus_a),
            (true, false) => Some(g),
            (false, true) => Some(a),
            (false, false) => None,
        };

        if let Some(p) = to_add {
            if result_set {
                result = result.add_incomplete(p);
            } else {
                result = p;
                result_set = true;
            }
        }
    }

    (result, result_set)
}

/// Execute a septic curve Schnorr-style verify syscall.
///
/// Reads a 15-u64 buffer laid out as `[A(7), s(4), e(4)]`, computes
/// `s*G + e*A` via Shamir's trick in one syscall (`G` is the hardcoded
/// generator above), then writes the 7-u64 result back over the `A` slot.
///
/// `s = 0 && e = 0` writes the all-zero sentinel point, matching the guest
/// API's handling of identity.
pub(crate) unsafe fn septic_verify(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    _arg2: u64,
) -> Option<u64> {
    let buf_ptr = arg1;
    if !buf_ptr.is_multiple_of(8) {
        panic!();
    }

    let a_point = u64_words_to_septic_point(ctx.mr_slice_unsafe(buf_ptr, SEPTIC_POINT_U64_WORDS));
    let scalars_ptr = buf_ptr + (SEPTIC_POINT_U64_WORDS as u64) * 8;
    let scalar_words: Vec<u64> =
        ctx.mr_slice(scalars_ptr, 2 * SEPTIC_SCALAR_U64_WORDS).into_iter().copied().collect();

    let mut s = [0u64; SEPTIC_SCALAR_U64_WORDS];
    let mut e = [0u64; SEPTIC_SCALAR_U64_WORDS];
    s.copy_from_slice(&scalar_words[..SEPTIC_SCALAR_U64_WORDS]);
    e.copy_from_slice(&scalar_words[SEPTIC_SCALAR_U64_WORDS..]);

    let g_point = septic_generator();
    let (result, result_set) = shamirs_trick(g_point, a_point, &s, &e);

    let result_words = if result_set {
        septic_point_to_u64_words(&result)
    } else {
        [0u64; SEPTIC_POINT_U64_WORDS]
    };

    ctx.bump_memory_clk();
    ctx.mw_slice(buf_ptr, &result_words);

    None
}

fn u64_words_to_septic_point<'a>(
    words: impl IntoIterator<Item = &'a u64>,
) -> SepticCurve<SP1Field> {
    let mut elems = [SP1Field::zero(); 14];
    for (i, w) in words.into_iter().enumerate() {
        elems[2 * i] = SP1Field::from_canonical_u32(*w as u32);
        elems[2 * i + 1] = SP1Field::from_canonical_u32((*w >> 32) as u32);
    }
    SepticCurve {
        x: SepticExtension([elems[0], elems[1], elems[2], elems[3], elems[4], elems[5], elems[6]]),
        y: SepticExtension([
            elems[7], elems[8], elems[9], elems[10], elems[11], elems[12], elems[13],
        ]),
    }
}

fn septic_point_to_u64_words(point: &SepticCurve<SP1Field>) -> [u64; SEPTIC_POINT_U64_WORDS] {
    let mut elems = [0u32; 14];
    for i in 0..7 {
        elems[i] = point.x.0[i].as_canonical_u32();
        elems[7 + i] = point.y.0[i].as_canonical_u32();
    }
    let mut out = [0u64; SEPTIC_POINT_U64_WORDS];
    for i in 0..SEPTIC_POINT_U64_WORDS {
        out[i] = (elems[2 * i] as u64) | ((elems[2 * i + 1] as u64) << 32);
    }
    out
}

/// Execute a septic curve add assign syscall.
pub(crate) unsafe fn septic_add(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let p_ptr = arg1;
    if !p_ptr.is_multiple_of(8) {
        panic!();
    }
    let q_ptr = arg2;
    if !q_ptr.is_multiple_of(8) {
        panic!();
    }

    let p_point = u64_words_to_septic_point(ctx.mr_slice_unsafe(p_ptr, SEPTIC_POINT_U64_WORDS));
    let q_point = u64_words_to_septic_point(ctx.mr_slice(q_ptr, SEPTIC_POINT_U64_WORDS));

    let result = p_point.add_incomplete(q_point);
    let result_words = septic_point_to_u64_words(&result);

    ctx.bump_memory_clk();
    ctx.mw_slice(p_ptr, &result_words);

    None
}

/// Execute a septic curve double assign syscall.
pub(crate) unsafe fn septic_double(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    _arg2: u64,
) -> Option<u64> {
    let p_ptr = arg1;
    if !p_ptr.is_multiple_of(8) {
        panic!();
    }

    let p_point = u64_words_to_septic_point(ctx.mr_slice_unsafe(p_ptr, SEPTIC_POINT_U64_WORDS));
    let result = p_point.double();
    let result_words = septic_point_to_u64_words(&result);

    ctx.mw_slice(p_ptr, &result_words);

    None
}

/// Execute a septic curve scalar multiplication syscall.
///
/// Performs the entire double-and-add loop in one syscall: reads the point at `arg1`
/// and the 256-bit little-endian scalar at `arg2`, then writes `scalar * P` back to
/// `arg1`. The scalar is stored as 4 u64 words (8 u32 words / 32 bytes).
///
/// The septic curve has no native identity element, so we keep a sentinel flag and
/// only invoke `add_incomplete` once we've accumulated a non-identity running sum.
/// `scalar = 0` produces the all-zero sentinel point used by the guest API.
pub(crate) unsafe fn septic_scalar_mul(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let p_ptr = arg1;
    if !p_ptr.is_multiple_of(8) {
        panic!();
    }
    let scalar_ptr = arg2;
    if !scalar_ptr.is_multiple_of(8) {
        panic!();
    }

    let p_point = u64_words_to_septic_point(ctx.mr_slice_unsafe(p_ptr, SEPTIC_POINT_U64_WORDS));
    let scalar_words: Vec<u64> =
        ctx.mr_slice(scalar_ptr, SEPTIC_SCALAR_U64_WORDS).into_iter().copied().collect();

    let mut result = SepticCurve {
        x: SepticExtension([SP1Field::zero(); 7]),
        y: SepticExtension([SP1Field::zero(); 7]),
    };
    let mut result_set = false;
    let mut temp = p_point;

    for word in &scalar_words {
        for bit in 0..64 {
            if (word >> bit) & 1 == 1 {
                if result_set {
                    result = result.add_incomplete(temp);
                } else {
                    result = temp;
                    result_set = true;
                }
            }
            temp = temp.double();
        }
    }

    let result_words = if result_set {
        septic_point_to_u64_words(&result)
    } else {
        [0u64; SEPTIC_POINT_U64_WORDS]
    };

    ctx.bump_memory_clk();
    ctx.mw_slice(p_ptr, &result_words);

    None
}
