use slop_algebra::TwoAdicField;
use slop_dft::p3::{Radix2DitParallel, TwoAdicSubgroupDft};
use slop_matrix::{dense::RowMajorMatrix, Matrix};

use super::{ErrorCorrectingCode, MultiplicativeCode, ZkCode};

/// Reed-Solomon taking evaluations on a two-adic subgroup and outputting evaluations on a coset of a bigger two-adic subgroup
/// Pads non-power-of-two inputs to next power of two
#[derive(Debug, Clone, Copy)]
pub struct RsInterpolation<K> {
    _phantom: std::marker::PhantomData<K>,
}

impl<K> ErrorCorrectingCode<K> for RsInterpolation<K>
where
    K: TwoAdicField,
{
    /// Proximity gaps bounds using unique decoding radius
    fn compute_proximity_gap_parameters(inverse_rate: f64, security_bits: usize) -> usize {
        let denominator = -(0.5 + 0.5 * inverse_rate.recip()).log2();
        (security_bits as f64 / denominator).ceil() as usize
    }

    fn encode(input: &[K], output_length: usize) -> Vec<K> {
        let num_rows = input.len();
        let padded_num_rows = num_rows.next_power_of_two();
        let in_log_size = padded_num_rows.trailing_zeros() as usize;
        let out_log_size = output_length.trailing_zeros() as usize;

        let mut padded_input = input.to_vec();
        padded_input.resize(padded_num_rows, K::zero());

        Radix2DitParallel.coset_lde(
            padded_input,
            out_log_size - in_log_size,
            K::two_adic_generator(out_log_size + 1),
        )
    }

    fn decode(output: &[K], input_length: usize) -> Vec<K> {
        let num_rows = output.len();
        let out_log_size = num_rows.trailing_zeros() as usize;
        let padded_in_length = input_length.next_power_of_two();
        let in_log_size = padded_in_length.trailing_zeros() as usize;

        let inverse_ft = Radix2DitParallel.coset_lde(
            output.to_vec(),
            0,
            K::one() / K::two_adic_generator(out_log_size + 1),
        );
        let mut decimated =
            inverse_ft.into_iter().step_by(1 << (out_log_size - in_log_size)).collect::<Vec<_>>();
        decimated.truncate(input_length);
        decimated
    }

    fn batch_encode(mut input: RowMajorMatrix<K>, output_length: usize) -> RowMajorMatrix<K> {
        let num_cols = input.width();
        let num_rows = input.height();
        let padded_num_rows = num_rows.next_power_of_two();
        let in_log_size = padded_num_rows.trailing_zeros() as usize;
        let out_log_size = output_length.trailing_zeros() as usize;

        // Resize to accommodate output_length rows per column
        input.values.resize(padded_num_rows * num_cols, K::zero());
        Radix2DitParallel
            .coset_lde_batch(
                input,
                out_log_size - in_log_size,
                K::two_adic_generator(out_log_size + 1),
            )
            .to_row_major_matrix()
    }

    fn batch_decode(output: RowMajorMatrix<K>, input_length: usize) -> RowMajorMatrix<K> {
        let num_cols = output.width();
        let num_rows = output.height();
        let out_log_size = num_rows.trailing_zeros() as usize;
        let padded_in_length = input_length.next_power_of_two();
        let in_log_size = padded_in_length.trailing_zeros() as usize;

        let inverse_ft = Radix2DitParallel.coset_lde_batch(
            output,
            0,
            K::one() / K::two_adic_generator(out_log_size + 1),
        );
        let decimated = inverse_ft
            .rows()
            .step_by(1 << (out_log_size - in_log_size))
            .flatten()
            .collect::<Vec<_>>();
        let mut result = RowMajorMatrix::new(decimated, num_cols);
        result.values.truncate(input_length * num_cols);
        result
    }
}

/// RsInterpolation is a valid ZkCode
///
/// The evaluation points for the codeword do not intersect the evaluation points for the message.
impl<K> ZkCode<K> for RsInterpolation<K> where K: Clone + TwoAdicField {}
impl<K: Clone + Send + Sync> super::traits::private::Sealed for RsInterpolation<K> {}

/// RsInterpolation is a multiplicative code
/// The square code is an RS code of twice the degree.
///
/// If the input is evaluations on a subgroup of size 2^k and the output on a coset K of size 2^m,
/// then the square code "intermediate" message representation is evaluations on the subgroup of size 2^(k+1)
impl<K> MultiplicativeCode<K> for RsInterpolation<K>
where
    K: Clone + Send + Sync + TwoAdicField,
{
    fn decode_square_batch(codeword: RowMajorMatrix<K>, input_length: usize) -> RowMajorMatrix<K> {
        let num_cols = codeword.width();
        let num_rows = codeword.height();
        let padded_input_length = input_length.next_power_of_two();
        let in_log_size = padded_input_length.trailing_zeros() as usize;
        let out_log_size = num_rows.trailing_zeros() as usize;

        let interpolated = Radix2DitParallel.coset_lde_batch(
            codeword,
            0,
            K::one() / K::two_adic_generator(out_log_size + 1),
        );
        let intermediate_vec = interpolated
            .rows()
            .step_by(1 << (out_log_size - in_log_size - 1))
            .flatten()
            .collect::<Vec<_>>();
        RowMajorMatrix::new(intermediate_vec, num_cols)
    }

    fn encode_square(intermediate: &[K], output_length: usize, _input_length: usize) -> Vec<K> {
        let interm_log_size = intermediate.len().trailing_zeros() as usize;
        let out_log_size = output_length.trailing_zeros() as usize;
        Radix2DitParallel.coset_lde(
            intermediate.to_vec(),
            out_log_size - interm_log_size,
            K::two_adic_generator(out_log_size + 1),
        )
    }

    fn square_to_base(intermediate: &[K], _output_length: usize, input_length: usize) -> Vec<K> {
        let mut decimated = intermediate.iter().step_by(2).copied().collect::<Vec<_>>();
        decimated.truncate(input_length);
        decimated
    }
}

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
        let encoded = RsInterpolation::encode(&input, output_length);

        // Verify encoded length
        assert_eq!(encoded.len(), output_length);

        // Decode
        let decoded = RsInterpolation::decode(&encoded, input_length);

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
        let encoded = RsInterpolation::batch_encode(input.clone(), output_length);

        // Verify encoded dimensions
        assert_eq!(encoded.height(), output_length);
        assert_eq!(encoded.width(), num_vectors);

        // Batch decode
        let decoded = RsInterpolation::batch_decode(encoded, input_length);

        // Verify decode is the inverse of encode
        assert_eq!(decoded.height(), input_length);
        assert_eq!(decoded.width(), num_vectors);
        assert_eq!(decoded.values, input_values, "Decoded matrix should match original input");
    }

    #[test]
    fn test_intermediate_compositions() {
        let mut rng = thread_rng();

        // Test parameters
        let input_length = 64; // power of 2
        let output_length = 1024; // power of 2, larger than input_length

        // Generate random input vector
        let input: Vec<KoalaBear> = (0..input_length).map(|_| rng.gen()).collect();

        // Test: input -> codeword -> intermediate -> codeword
        let codeword1 = RsInterpolation::encode(&input, output_length);
        let intermediate = RsInterpolation::decode_square(&codeword1, input_length);
        assert_eq!(
            intermediate.len(),
            2 * input_length,
            "Intermediate representation should be twice the input length"
        );
        let codeword2 = RsInterpolation::encode_square(&intermediate, output_length, input_length);

        assert_eq!(
            codeword1, codeword2,
            "Codeword should be recoverable from intermediate representation"
        );

        // Test: input -> codeword -> intermediate -> input
        let recovered_input =
            RsInterpolation::square_to_base(&intermediate, output_length, input_length);

        assert_eq!(
            input, recovered_input,
            "Input should be recoverable from intermediate representation"
        );
    }

    #[test]
    fn test_multiplicative_homomorphism() {
        let mut rng = thread_rng();

        // Test parameters
        let input_length = 64; // power of 2
        let output_length = 1024; // power of 2, larger than input_length

        // Generate two random input vectors
        let input_a: Vec<KoalaBear> = (0..input_length).map(|_| rng.gen()).collect();
        let input_b: Vec<KoalaBear> = (0..input_length).map(|_| rng.gen()).collect();

        // Encode both inputs
        let enc_a = RsInterpolation::encode(&input_a, output_length);
        let enc_b = RsInterpolation::encode(&input_b, output_length);

        // Compute pointwise product of encodings: enc(a) * enc(b)
        let enc_a_times_enc_b: Vec<KoalaBear> =
            enc_a.iter().zip(enc_b.iter()).map(|(a, b)| *a * *b).collect();

        // Get intermediate representations
        let interm_a = RsInterpolation::decode_square(&enc_a, input_length);
        let interm_b = RsInterpolation::decode_square(&enc_b, input_length);

        // Compute pointwise product of intermediates: interm(a) * interm(b)
        let interm_a_times_interm_b: Vec<KoalaBear> =
            interm_a.iter().zip(interm_b.iter()).map(|(a, b)| *a * *b).collect();

        // Encode the product of intermediates: enc(interm(a) * interm(b))
        let enc_interm_product =
            RsInterpolation::encode_square(&interm_a_times_interm_b, output_length, input_length);

        // Verify: enc(a) * enc(b) = enc(interm(a) * interm(b))
        assert_eq!(
            enc_a_times_enc_b, enc_interm_product,
            "Multiplicative homomorphism property should hold: enc(a)*enc(b) = enc(interm(a)*interm(b))"
        );

        // Also verify: enc(interm(a)) * enc(interm(b)) = enc(interm(a) * interm(b))
        let enc_interm_a = RsInterpolation::encode_square(&interm_a, output_length, input_length);
        let enc_interm_b = RsInterpolation::encode_square(&interm_b, output_length, input_length);
        let enc_interm_a_times_enc_interm_b: Vec<KoalaBear> =
            enc_interm_a.iter().zip(enc_interm_b.iter()).map(|(a, b)| *a * *b).collect();

        assert_eq!(
            enc_interm_a_times_enc_interm_b, enc_interm_product,
            "Multiplicative homomorphism property should hold: enc(interm(a))*enc(interm(b)) = enc(interm(a)*interm(b))"
        );
    }
}
