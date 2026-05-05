use slop_algebra::AbstractField;
use sp1_primitives::{poseidon2_init, SP1Perm};

/// The digest size.
pub const DIGEST_SIZE: usize = 8;

/// Compute the ceiling of the base-2 logarithm of a number.
#[must_use]
pub fn log2_ceil_usize(n: usize) -> usize {
    // println!("n: {}", n);
    n.next_power_of_two().ilog2() as usize
}

/// Get the inner perm
#[must_use]
pub fn inner_perm() -> SP1Perm {
    poseidon2_init()
}

/// Get an array `xs` such that `xs[i] = i`.
#[must_use]
pub const fn indices_arr<const N: usize>() -> [usize; N] {
    let mut indices_arr = [0; N];
    let mut i = 0;
    while i < N {
        indices_arr[i] = i;
        i += 1;
    }
    indices_arr
}

/// Pad to the next multiple of 32, with an option to specify the fixed height.
//
// The `rows` argument represents the rows of a matrix stored in row-major order. The function will
// pad the rows using `row_fn` to create the padded rows. The padding will be to the next multiple
// of 32 if `height` is `None`, or to the specified `height` if it is not `None`. The
// function will panic of the number of rows is larger than the specified `height`.
pub fn pad_rows_fixed<R: Clone>(rows: &mut Vec<R>, row_fn: impl Fn() -> R, height: Option<usize>) {
    let nb_rows = rows.len();
    let dummy_row = row_fn();
    rows.resize(next_multiple_of_32(nb_rows, height), dummy_row);
}

/// Returns the internal value of the option if it is set, otherwise returns the next multiple of
/// 32.
#[track_caller]
#[inline]
#[allow(clippy::uninlined_format_args)]
#[must_use]
pub fn next_multiple_of_32(n: usize, fixed_height: Option<usize>) -> usize {
    if let Some(height) = fixed_height {
        if n > height {
            panic!("fixed height is too small: got height {} for number of rows {}", height, n);
        }
        height
    } else {
        n.next_multiple_of(32).max(16)
    }
}

/// Returns a 48-bit address as three u16 limbs.
#[must_use]
pub fn addr_to_limbs<F: AbstractField>(addr: u64) -> [F; 3] {
    [
        F::from_canonical_u16((addr & 0xFFFF) as u16),
        F::from_canonical_u16(((addr >> 16) & 0xFFFF) as u16),
        F::from_canonical_u16(((addr >> 32) & 0xFFFF) as u16),
    ]
}
