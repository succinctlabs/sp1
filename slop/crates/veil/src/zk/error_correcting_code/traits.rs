use serde::{Deserialize, Serialize};
use slop_matrix::dense::RowMajorMatrix;

/// Trait for linear error-correcting codes (really a family of codes over input and output lengths)
pub trait ErrorCorrectingCode<K: Clone + Send + Sync>: std::fmt::Debug + Clone + Copy {
    /// How many evals you need to query on a purported linear combination of codewords
    ///  to know it actually came from codewords w/ certain bits of security
    fn compute_proximity_gap_parameters(inverse_rate: f64, security_bits: usize) -> usize;

    fn batch_encode(input: RowMajorMatrix<K>, output_length: usize) -> RowMajorMatrix<K>;

    fn batch_decode(output: RowMajorMatrix<K>, input_length: usize) -> RowMajorMatrix<K>;

    fn encode(input: &[K], output_length: usize) -> Vec<K> {
        let input_matrix = RowMajorMatrix::new(input.to_vec(), 1);
        let output_matrix = Self::batch_encode(input_matrix, output_length);
        output_matrix.values
    }

    fn decode(output: &[K], input_length: usize) -> Vec<K> {
        let output_matrix = RowMajorMatrix::new(output.to_vec(), 1);
        let input_matrix = Self::batch_decode(output_matrix, input_length);
        input_matrix.values
    }

    /// Encodes and returns only the values at the given indices.
    ///
    /// Default implementation computes a full encode and indexes into it.
    /// Implementations may override with more efficient point evaluations.
    fn encode_at_indices(input: &[K], output_length: usize, indices: &[usize]) -> Vec<K> {
        let full = Self::encode(input, output_length);
        indices.iter().map(|&i| full[i].clone()).collect()
    }
}

/// Marker trait for [`ErrorCorrectingCode`]'s that are valid for use in zk-protocols.
/// See the writeup for the precise definition.
///
/// I.e, the composition of embedding any k coordinates, encoding,
/// and then projecting to any k coordinates is always invertible.
pub trait ZkCode<K: Clone + Send + Sync>: ErrorCorrectingCode<K> + private::Sealed {}
pub(in crate::zk::error_correcting_code) mod private {
    pub trait Sealed {}
}

/// Trait for error-correcting codes that are "multiplicative"
/// i.e, there is an associated "square code" of "intermediate messages" such that
/// * square-code messages are twice as long as input.len().next_power_of_two()
/// * enc(a)*enc(b) is in the square code for a,b messages of the original code, where * is pointwise multiplication
///
/// Currently, this just has the functions needed for zk-hadamard to be efficient
pub trait MultiplicativeCode<K: Clone + Send + Sync>: ErrorCorrectingCode<K> {
    /// Given many codewords for the square code, returns the input messages
    fn decode_square_batch(codeword: RowMajorMatrix<K>, input_length: usize) -> RowMajorMatrix<K>;

    /// Given one codeword for the square code, returns the input message
    fn decode_square(codeword: &[K], input_length: usize) -> Vec<K> {
        let codeword_matrix = RowMajorMatrix::new(codeword.to_vec(), 1);
        Self::decode_square_batch(codeword_matrix, input_length).values
    }

    /// Encodes a message using the square code
    ///
    /// Needs to know the input and output lengths to know which code in the family to use.
    fn encode_square(intermediate: &[K], output_length: usize, input_length: usize) -> Vec<K>;

    /// Takes a message in the square code and generates a message in the base code.
    ///
    /// This should satisfy that square_to_base(decode_square(encode(a) * encode(b))) = a * b
    /// for all base code messages a,b.
    ///
    /// Needs to know the input and output lengths to know which code in the family to use.
    fn square_to_base(intermediate: &[K], output_length: usize, input_length: usize) -> Vec<K>;
}

/// Parameters computed based on message length and target security bits for the zk-protocols used elsewhere
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct CodeParametersForZk<EF: Clone + Send + Sync, Code: ErrorCorrectingCode<EF>> {
    /// Length of the message + a padding for each evaluation to be revealed (i.e. eval_scaling * evals elements)
    pub padded_message_length: usize,

    /// Length of output codeword
    pub code_length: usize,
    pub code_log_length: usize,

    /// How many total evaluations to reveal to make sure RLC's come from purported codewords
    pub total_padding: usize,

    pub code_inverse_rate: f64,
    pub security_bits: usize,

    _phantom: std::marker::PhantomData<(EF, Code)>,
}

impl<EF: Clone + Send + Sync, Code: ErrorCorrectingCode<EF> + Clone> CodeParametersForZk<EF, Code> {
    /// Computes code parameters for zk-protocols based on message length and target security bits
    ///
    /// `padding_schedule` specifies the degrees of codewords built from the commitment that need to be
    /// checked by proximity-gaps arguments.
    pub fn new(
        message_length: usize,
        security_bits: usize,
        code_inverse_rate: f64,
        padding_schedule: &[usize],
    ) -> Self {
        let total_padding = padding_schedule
            .iter()
            .map(|&p| {
                Code::compute_proximity_gap_parameters(
                    code_inverse_rate / (p as f64),
                    security_bits,
                )
            })
            .sum();

        let padded_message_length: usize = message_length + total_padding;
        let zero_padded_message_length = padded_message_length.next_power_of_two();
        let code_length = (zero_padded_message_length as f64 * code_inverse_rate) as usize;
        let code_log_length = code_length.trailing_zeros() as usize;

        Self {
            padded_message_length,
            code_length,
            code_log_length,
            total_padding,
            code_inverse_rate,
            security_bits,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Computes the number of needed eval reveals to check that an RLC of degree d expressions in
    /// codewords is a degree d expression in codewords.
    ///
    /// d > 1 is meaningless for non-multiplicative codes.
    pub fn evals(&self, d: usize) -> usize {
        Code::compute_proximity_gap_parameters(
            self.code_inverse_rate / (d as f64),
            self.security_bits,
        )
    }

    pub fn multi_evals(&self, ds: &[usize]) -> usize {
        ds.iter().map(|&d| self.evals(d)).sum()
    }
}
