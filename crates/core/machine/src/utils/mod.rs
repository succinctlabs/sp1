pub mod concurrency;
mod logger;
#[cfg(any(test, feature = "programs"))]
mod programs;
mod prove;
mod span;
mod tracer;

pub use logger::*;
use p3_field::Field;
pub use prove::*;
use sp1_curves::params::Limbs;
pub use span::*;
pub use tracer::*;

#[cfg(any(test, feature = "programs"))]
pub use programs::*;

use crate::memory::MemoryCols;
use generic_array::ArrayLength;
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator};

pub const fn indices_arr<const N: usize>() -> [usize; N] {
    let mut indices_arr = [0; N];
    let mut i = 0;
    while i < N {
        indices_arr[i] = i;
        i += 1;
    }
    indices_arr
}

pub fn pad_to_power_of_two<const N: usize, T: Clone + Default>(values: &mut Vec<T>) {
    debug_assert!(values.len() % N == 0);
    let mut n_real_rows = values.len() / N;
    if n_real_rows < 16 {
        n_real_rows = 16;
    }
    values.resize(n_real_rows.next_power_of_two() * N, T::default());
}

pub fn limbs_from_prev_access<T: Copy, N: ArrayLength, M: MemoryCols<T>>(
    cols: &[M],
) -> Limbs<T, N> {
    let vec = cols.iter().flat_map(|access| access.prev_value().0).collect::<Vec<T>>();

    let sized = vec.try_into().unwrap_or_else(|_| panic!("failed to convert to limbs"));
    Limbs(sized)
}

pub fn limbs_from_access<T: Copy, N: ArrayLength, M: MemoryCols<T>>(cols: &[M]) -> Limbs<T, N> {
    let vec = cols.iter().flat_map(|access| access.value().0).collect::<Vec<T>>();

    let sized = vec.try_into().unwrap_or_else(|_| panic!("failed to convert to limbs"));
    Limbs(sized)
}

/// Pad to a power of two, with an option to specify the power.
//
// The `rows` argument represents the rows of a matrix stored in row-major order. The function will
// pad the rows using `row_fn` to create the padded rows. The padding will be to the next power of
// of two of `size_log_2` is `None`, or to the specified `size_log_2` if it is not `None`. The
// function will panic of the number of rows is larger than the specified `size_log2`
pub fn pad_rows_fixed<R: Clone>(
    rows: &mut Vec<R>,
    row_fn: impl Fn() -> R,
    size_log2: Option<usize>,
) {
    let nb_rows = rows.len();
    let dummy_row = row_fn();
    rows.resize(next_power_of_two(nb_rows, size_log2), dummy_row);
}

/// Returns the next power of two that is >= `n` and >= 16. If `fixed_power` is set, it will return
/// `2^fixed_power` after checking that `n <= 2^fixed_power`.
pub fn next_power_of_two(n: usize, fixed_power: Option<usize>) -> usize {
    match fixed_power {
        Some(power) => {
            let padded_nb_rows = 1 << power;
            if n * 2 < padded_nb_rows {
                tracing::debug!(
                    "fixed log2 rows can be potentially reduced: got {}, expected {}",
                    n,
                    padded_nb_rows
                );
            }
            if n > padded_nb_rows {
                panic!("fixed log2 rows is too small: got {}, expected {}", n, padded_nb_rows);
            }
            padded_nb_rows
        }
        None => {
            let mut padded_nb_rows = n.next_power_of_two();
            if padded_nb_rows < 16 {
                padded_nb_rows = 16;
            }
            padded_nb_rows
        }
    }
}

/// Converts a slice of words to a slice of bytes in little endian.
pub fn words_to_bytes_le<const B: usize>(words: &[u32]) -> [u8; B] {
    debug_assert_eq!(words.len() * 4, B);
    words
        .iter()
        .flat_map(|word| word.to_le_bytes().to_vec())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// Converts a slice of words to a byte vector in little endian.
pub fn words_to_bytes_le_vec(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes().to_vec()).collect::<Vec<_>>()
}

/// Converts a byte array in little endian to a slice of words.
pub fn bytes_to_words_le<const W: usize>(bytes: &[u8]) -> [u32; W] {
    debug_assert_eq!(bytes.len(), W * 4);
    bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// Converts a byte array in little endian to a vector of words.
pub fn bytes_to_words_le_vec(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>()
}

/// Converts a num to a string with commas every 3 digits.
pub fn num_to_comma_separated<T: ToString>(value: T) -> String {
    value
        .to_string()
        .chars()
        .rev()
        .collect::<Vec<_>>()
        .chunks(3)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(",")
        .chars()
        .rev()
        .collect()
}

pub fn chunk_vec<T>(mut vec: Vec<T>, chunk_size: usize) -> Vec<Vec<T>> {
    let mut result = Vec::new();
    while !vec.is_empty() {
        let current_chunk_size = std::cmp::min(chunk_size, vec.len());
        let current_chunk = vec.drain(..current_chunk_size).collect::<Vec<T>>();
        result.push(current_chunk);
    }
    result
}

#[inline]
pub fn log2_strict_usize(n: usize) -> usize {
    let res = n.trailing_zeros();
    assert_eq!(n.wrapping_shr(res), 1, "Not a power of two: {n}");
    res as usize
}

pub fn par_for_each_row<P, F>(vec: &mut [F], num_elements_per_event: usize, processor: P)
where
    F: Send,
    P: Fn(usize, &mut [F]) + Send + Sync,
{
    // Split the vector into `num_cpus` chunks, but at least `num_cpus` rows per chunk.
    assert!(vec.len() % num_elements_per_event == 0);
    let len = vec.len() / num_elements_per_event;
    let cpus = num_cpus::get();
    let ceil_div = (len + cpus - 1) / cpus;
    let chunk_size = std::cmp::max(ceil_div, cpus);

    vec.chunks_mut(chunk_size * num_elements_per_event).enumerate().par_bridge().for_each(
        |(i, chunk)| {
            chunk.chunks_mut(num_elements_per_event).enumerate().for_each(|(j, row)| {
                assert!(row.len() == num_elements_per_event);
                processor(i * chunk_size + j, row);
            });
        },
    );
}

/// Returns whether the `SP1_DEBUG` environment variable is enabled or disabled.
///
/// This variable controls whether backtraces are attached to compiled circuit programs, as well
/// as whether cycle tracking is performed for circuit programs.
///
/// By default, the variable is disabled.
pub fn sp1_debug_mode() -> bool {
    let value = std::env::var("SP1_DEBUG").unwrap_or_else(|_| "false".to_string());
    value == "1" || value.to_lowercase() == "true"
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
