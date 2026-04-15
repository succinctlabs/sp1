use serde::{Deserialize, Serialize};
use slop_algebra::{Field, TwoAdicField};
use slop_challenger::VariableLengthChallenger;

/// A fully expanded WHIR configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhirProofShape<F> {
    pub domain_generator: F,

    /// The OOD samples used in the commitment.
    pub starting_ood_samples: usize,

    /// The rate of the initial RS code used during the protocol.
    pub starting_log_inv_rate: usize,

    /// The initial folding factor.
    pub starting_interleaved_log_height: usize,

    /// The initial domain size
    pub starting_domain_log_size: usize,

    /// The initial pow bits used in the first fold.
    pub starting_folding_pow_bits: Vec<usize>,

    /// The round-specific parameters.
    pub round_parameters: Vec<RoundConfig>,

    /// Logarithm of the number of coefficients in the final polynomial. (The final polynomial
    /// technically has degree `2^final_poly_log_degree - 1`.)
    pub final_poly_log_degree: usize,

    /// Number of queries in the last round
    pub final_queries: usize,

    /// Number of final bits of proof of work (for the queries).
    pub final_pow_bits: usize,

    /// Number of final bits of proof of work (for the sumcheck).
    pub final_folding_pow_bits: Vec<usize>,
}

impl<F: TwoAdicField> WhirProofShape<F> {
    pub fn default_whir_config() -> Self {
        let folding_factor = 4;
        WhirProofShape::<F> {
            domain_generator: F::two_adic_generator(13),
            starting_ood_samples: 1,
            starting_log_inv_rate: 1,
            starting_interleaved_log_height: 12,
            starting_domain_log_size: 13,
            starting_folding_pow_bits: vec![10; folding_factor],
            round_parameters: vec![
                RoundConfig {
                    folding_factor,
                    evaluation_domain_log_size: 12,
                    queries_pow_bits: 10,
                    pow_bits: vec![10; folding_factor],
                    num_queries: 90,
                    ood_samples: 1,
                    log_inv_rate: 4,
                },
                RoundConfig {
                    folding_factor,
                    evaluation_domain_log_size: 11,
                    queries_pow_bits: 10,
                    pow_bits: vec![10; folding_factor],
                    num_queries: 15,
                    ood_samples: 1,
                    log_inv_rate: 7,
                },
            ],
            final_poly_log_degree: 4,
            final_queries: 10,
            final_pow_bits: 10,
            final_folding_pow_bits: vec![10; 8],
        }
    }
    pub fn big_beautiful_whir_config() -> Self {
        let folding_factor = 4;
        WhirProofShape::<F> {
            domain_generator: F::two_adic_generator(21),
            starting_ood_samples: 2,
            starting_log_inv_rate: 1,
            starting_interleaved_log_height: 20,
            starting_domain_log_size: 21,
            starting_folding_pow_bits: vec![0; 10],
            round_parameters: vec![
                RoundConfig {
                    folding_factor,
                    evaluation_domain_log_size: 20,
                    queries_pow_bits: 16,
                    pow_bits: vec![0; folding_factor],
                    num_queries: 84,
                    ood_samples: 2,
                    log_inv_rate: 4,
                },
                RoundConfig {
                    folding_factor,
                    evaluation_domain_log_size: 19,
                    queries_pow_bits: 16,
                    pow_bits: vec![0; folding_factor],
                    num_queries: 21,
                    ood_samples: 2,
                    log_inv_rate: 7,
                },
                RoundConfig {
                    folding_factor,
                    evaluation_domain_log_size: 18,
                    queries_pow_bits: 16,
                    pow_bits: vec![0; folding_factor],
                    num_queries: 12,
                    ood_samples: 2,
                    log_inv_rate: 10,
                },
            ],
            final_poly_log_degree: 8,
            final_queries: 9,
            final_pow_bits: 16,
            final_folding_pow_bits: vec![0; 8],
        }
    }
}
impl<F: Field> WhirProofShape<F> {
    pub fn write_to_challenger<D: Copy, C: VariableLengthChallenger<F, D>>(
        &self,
        challenger: &mut C,
    ) {
        let &WhirProofShape {
            domain_generator,
            starting_ood_samples,
            starting_log_inv_rate,
            starting_interleaved_log_height,
            starting_domain_log_size,
            ref starting_folding_pow_bits,
            ref round_parameters,
            final_poly_log_degree,
            final_queries,
            final_pow_bits,
            ref final_folding_pow_bits,
        } = self;
        challenger.observe(domain_generator);
        challenger.observe(F::from_canonical_usize(starting_ood_samples));
        challenger.observe(F::from_canonical_usize(starting_log_inv_rate));
        challenger.observe(F::from_canonical_usize(starting_interleaved_log_height));
        challenger.observe(F::from_canonical_usize(starting_domain_log_size));
        challenger.observe_variable_length_slice(
            &starting_folding_pow_bits
                .iter()
                .copied()
                .map(F::from_canonical_usize)
                .collect::<Vec<_>>(),
        );
        round_parameters.iter().for_each(|f| f.write_to_challenger(challenger));
        challenger.observe(F::from_canonical_usize(final_poly_log_degree));
        challenger.observe(F::from_canonical_usize(final_queries));
        challenger.observe(F::from_canonical_usize(final_pow_bits));
        challenger.observe_variable_length_slice(
            &final_folding_pow_bits
                .iter()
                .copied()
                .map(F::from_canonical_usize)
                .collect::<Vec<_>>(),
        );
    }
}
/// Round specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundConfig {
    /// Folding factor for this round.
    pub folding_factor: usize,
    /// Size of evaluation domain (of oracle sent in this round)
    pub evaluation_domain_log_size: usize,
    /// Number of bits of proof of work (for the queries).
    pub queries_pow_bits: usize,
    /// Number of bits of proof of work (for the folding).
    pub pow_bits: Vec<usize>,
    /// Number of queries in this round
    pub num_queries: usize,
    /// Number of OOD samples in this round
    pub ood_samples: usize,
    /// Rate of current RS codeword
    pub log_inv_rate: usize,
}

impl RoundConfig {
    pub fn write_to_challenger<F: Field, D: Copy, C: VariableLengthChallenger<F, D>>(
        &self,
        challenger: &mut C,
    ) {
        challenger.observe(F::from_canonical_usize(self.folding_factor));
        challenger.observe(F::from_canonical_usize(self.evaluation_domain_log_size));
        challenger.observe(F::from_canonical_usize(self.queries_pow_bits));
        challenger.observe_variable_length_slice(
            &self.pow_bits.iter().copied().map(F::from_canonical_usize).collect::<Vec<_>>(),
        );
        challenger.observe(F::from_canonical_usize(self.num_queries));
        challenger.observe(F::from_canonical_usize(self.ood_samples));
        challenger.observe(F::from_canonical_usize(self.log_inv_rate));
    }
}
