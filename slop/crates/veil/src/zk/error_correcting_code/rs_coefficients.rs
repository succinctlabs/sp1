use rayon::prelude::*;
use slop_algebra::{AbstractField, TwoAdicField};
use slop_dft::p3::{Radix2DitParallel, TwoAdicSubgroupDft};
use slop_matrix::{dense::RowMajorMatrix, Matrix};

use super::{ErrorCorrectingCode, ZkCode};

#[derive(Debug, Clone, Copy)]
/// Reed-Solomon taking coefficients in increasing order and outputting evaluations on a two-adic subgroup
/// Proof message is default: just the codewords
pub struct RsFromCoefficients<K> {
    _phantom: std::marker::PhantomData<K>,
}

impl<K> ErrorCorrectingCode<K> for RsFromCoefficients<K>
where
    K: Clone + TwoAdicField,
{
    fn compute_proximity_gap_parameters(inverse_rate: f64, security_bits: usize) -> usize {
        let denominator = -(0.5 + 0.5 * inverse_rate.recip()).log2();
        (security_bits as f64 / denominator).ceil() as usize
    }

    /// Needs to produce output with power-of-two length
    fn encode(input: &[K], output_length: usize) -> Vec<K> {
        let mut fft_input: Vec<K> = input.to_vec();
        fft_input.resize(output_length, K::zero());
        Radix2DitParallel.dft(fft_input)
    }

    /// Assumes output is a codeword and decodes to the original coefficients (by truncation)
    fn decode(output: &[K], input_length: usize) -> Vec<K> {
        let mut all_coeffs = Radix2DitParallel.idft(output.to_vec());
        all_coeffs.truncate(input_length);
        all_coeffs
    }

    fn batch_encode(mut input: RowMajorMatrix<K>, output_length: usize) -> RowMajorMatrix<K> {
        let num_cols = input.width();

        // Resize to accommodate output_length rows per column
        input.values.resize(output_length * num_cols, K::zero());

        // Apply DFT to each column
        Radix2DitParallel.dft_batch(input).to_row_major_matrix()
    }

    fn batch_decode(output: RowMajorMatrix<K>, input_length: usize) -> RowMajorMatrix<K> {
        let num_cols = output.width();

        // Apply inverse DFT to each column
        let mut all_coeffs = Radix2DitParallel.idft_batch(output);

        // Truncate to input_length rows per column
        all_coeffs.values.truncate(input_length * num_cols);

        all_coeffs
    }

    /// Evaluates the polynomial at specific points of the two-adic subgroup via Horner's method.
    ///
    /// This avoids computing a full FFT when only a few evaluations are needed.
    /// Complexity: O(num_indices * input_length) vs O(output_length * log(output_length)) for full FFT.
    fn encode_at_indices(input: &[K], output_length: usize, indices: &[usize]) -> Vec<K> {
        let log_n = output_length.trailing_zeros() as usize;
        let omega = K::two_adic_generator(log_n);
        indices
            .par_iter()
            .map(|&idx| {
                let point = omega.exp_u64(idx as u64);
                input.iter().rev().fold(K::zero(), |acc, coeff| acc * point + *coeff)
            })
            .collect()
    }
}

/// RsFromCoefficients is a valid ZkCode
impl<K> ZkCode<K> for RsFromCoefficients<K> where K: Clone + TwoAdicField {}
impl<K: Clone + Send + Sync> super::traits::private::Sealed for RsFromCoefficients<K> {}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_types)]

    use super::*;
    use rand::{thread_rng, Rng};
    use slop_koala_bear::KoalaBear;

    #[test]
    fn test_encode_decode_inverse() {
        let mut rng = thread_rng();

        // Test parameters
        let input_length = 64; // power of 2
        let output_length = 1024; // power of 2, larger than input_length

        // Generate random input vector
        let input: Vec<KoalaBear> = (0..input_length).map(|_| rng.gen()).collect();

        // Encode
        let encoded = RsFromCoefficients::encode(&input, output_length);

        // Verify encoded length
        assert_eq!(encoded.len(), output_length);

        // Decode
        let decoded = RsFromCoefficients::decode(&encoded, input_length);

        // Verify decode is the inverse of encode
        assert_eq!(decoded.len(), input_length);
        assert_eq!(decoded, input, "Decoded vector should match original input");
    }

    #[test]
    fn test_batch_encode_decode_inverse() {
        let mut rng = thread_rng();

        // Test parameters
        let input_length = 64; // power of 2
        let output_length = 1024; // power of 2, larger than input_length
        let num_vectors = 8;

        // Generate random input matrix (input_length rows × num_vectors columns)
        let input_values: Vec<KoalaBear> =
            (0..input_length * num_vectors).map(|_| rng.gen()).collect();
        let input = RowMajorMatrix::new(input_values.clone(), num_vectors);

        // Batch encode
        let encoded = RsFromCoefficients::batch_encode(input.clone(), output_length);

        // Verify encoded dimensions
        assert_eq!(encoded.height(), output_length);
        assert_eq!(encoded.width(), num_vectors);

        // Batch decode
        let decoded = RsFromCoefficients::batch_decode(encoded, input_length);

        // Verify decode is the inverse of encode
        assert_eq!(decoded.height(), input_length);
        assert_eq!(decoded.width(), num_vectors);
        assert_eq!(decoded.values, input_values, "Decoded matrix should match original input");
    }

    #[test]
    fn test_encode_at_indices_matches_full_encode() {
        let mut rng = thread_rng();

        let input_length = 100; // non-power-of-two, like real usage
        let output_length = 1024;

        let input: Vec<KoalaBear> = (0..input_length).map(|_| rng.gen()).collect();
        let full_encoded = RsFromCoefficients::encode(&input, output_length);

        let indices: Vec<usize> = vec![0, 1, 7, 42, 100, 511, 1023];
        let partial = RsFromCoefficients::encode_at_indices(&input, output_length, &indices);

        for (k, &idx) in indices.iter().enumerate() {
            assert_eq!(partial[k], full_encoded[idx], "mismatch at index {idx}");
        }
    }
}
