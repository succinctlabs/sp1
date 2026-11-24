pub mod concurrency;
mod logger;
mod prove;
mod span;
#[cfg(test)]
mod test;
mod zerocheck_unit_test;

pub use logger::*;
pub use prove::*;
use slop_algebra::{AbstractField, Field};
pub use span::*;
#[cfg(test)]
pub use test::*;
pub use zerocheck_unit_test::*;

use sp1_hypercube::{air::SP1AirBuilder, Word};
pub use sp1_primitives::consts::{
    bytes_to_words_le, bytes_to_words_le_vec, num_to_comma_separated, words_to_bytes_le,
    words_to_bytes_le_vec,
};
use sp1_primitives::{consts::WORD_BYTE_SIZE, utils::reverse_bits_len};

pub use sp1_hypercube::{indices_arr, next_multiple_of_32, pad_rows_fixed};

/// Fill a host trace while counting the byte lookups produced by the same row operations.
pub(crate) fn trace_with_byte_lookups<F: Field, E: Sync>(
    events: &[E],
    width: usize,
    padded_rows: usize,
    output: &mut sp1_core_executor::ExecutionRecord,
    populate: impl Fn(&E, &mut [F], &mut sp1_core_executor::events::DenseByteLookupCounts) + Sync,
) -> Vec<F> {
    use rayon::prelude::*;
    use sp1_core_executor::events::DenseByteLookupCounts;

    if padded_rows == 0 {
        return Vec::new();
    }
    let mut values = vec![F::zero(); padded_rows * width];
    let chunk = events.len().div_ceil(rayon::current_num_threads()).max(256);
    let counts = values[..events.len() * width]
        .par_chunks_mut(chunk * width)
        .zip(events.par_chunks(chunk))
        .map(|(rows, events)| {
            let mut counts = DenseByteLookupCounts::default();
            for (event, row) in events.iter().zip(rows.chunks_exact_mut(width)) {
                populate(event, row, &mut counts);
            }
            counts
        })
        .reduce_with(DenseByteLookupCounts::merge);
    if let Some(counts) = counts {
        output.add_byte_lookup_counts(counts.finish());
    }
    values
}

pub fn limbs_to_words<AB: SP1AirBuilder>(limbs: Vec<AB::Var>) -> Vec<Word<AB::Expr>> {
    let base = AB::Expr::from_canonical_u32(1 << 8);
    let result_words: Vec<Word<AB::Expr>> = limbs
        .as_chunks::<WORD_BYTE_SIZE>()
        .0
        .iter()
        .map(|l| {
            Word([
                l[0] + l[1] * base.clone(),
                l[2] + l[3] * base.clone(),
                l[4] + l[5] * base.clone(),
                l[6] + l[7] * base.clone(),
            ])
        })
        .collect();
    result_words
}

pub fn u32_to_half_word<F: Field>(value: u32) -> [F; 2] {
    [F::from_canonical_u16((value & 0xFFFF) as u16), F::from_canonical_u16((value >> 16) as u16)]
}

#[inline]
pub fn log2_strict_usize(n: usize) -> usize {
    let res = n.trailing_zeros();
    assert_eq!(n.wrapping_shr(res), 1, "Not a power of two: {n}");
    res as usize
}

/// Returns a vector of zeros of the given length. This is faster than vec![F::zero(); len] which
/// requires copying.
///
/// This function is safe to use only for fields that can be transmuted from 0u32.
pub fn zeroed_f_vec<F: Field>(len: usize) -> Vec<F> {
    debug_assert!(std::mem::size_of::<F>() == 4);

    let vec = vec![0u32; len];
    unsafe { std::mem::transmute::<Vec<u32>, Vec<F>>(vec) }
}

/// Reverse the order of elements in a slice using bit-reversed indices.
///
/// This function reorders the elements of a slice such that the element at index `i`
/// is moved to index `reverse_bits_len(i, log2(len))`.
pub fn reverse_slice_index_bits<T>(slice: &mut [T]) {
    let n = slice.len();
    assert!(n.is_power_of_two(), "Slice length must be a power of two");
    let log_n = log2_strict_usize(n);

    for i in 0..n {
        let j = reverse_bits_len(i, log_n);
        if i < j {
            slice.swap(i, j);
        }
    }
}
