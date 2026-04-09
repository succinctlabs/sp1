use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use slop_algebra::{ExtensionField, Field, PrimeField64, TwoAdicField};
use slop_challenger::VariableLengthChallenger;

pub struct UncheckedWhirProofShape {
    pub starting_ood_samples: usize,
    pub starting_log_inv_rate: usize,
    pub starting_interleaved_log_height: usize,
    pub starting_folding_pow_bits: Vec<usize>,
    pub round_parameters: Vec<RoundConfig>,
    pub final_queries: usize,
    pub final_folding_pow_bits: Vec<usize>,
    pub final_pow_bits: usize,
}

impl UncheckedWhirProofShape {
    pub fn big_beautiful_whir_config() -> Self {
        let folding_factor = 4;
        Self {
            starting_ood_samples: 2,
            starting_log_inv_rate: 1,
            starting_interleaved_log_height: 20,
            starting_folding_pow_bits: vec![0; 10],
            round_parameters: vec![
                RoundConfig {
                    folding_factor,
                    evaluation_domain_log_size: 20,
                    queries_pow_bits: 16,
                    pow_bits: vec![0; folding_factor],
                    num_queries: 84,
                    ood_samples: 2,
                },
                RoundConfig {
                    folding_factor,
                    evaluation_domain_log_size: 19,
                    queries_pow_bits: 16,
                    pow_bits: vec![0; folding_factor],
                    num_queries: 21,
                    ood_samples: 2,
                },
                RoundConfig {
                    folding_factor,
                    evaluation_domain_log_size: 18,
                    queries_pow_bits: 16,
                    pow_bits: vec![0; folding_factor],
                    num_queries: 12,
                    ood_samples: 2,
                },
            ],
            final_queries: 9,
            final_folding_pow_bits: vec![0; 8],
            final_pow_bits: 16,
        }
    }

    pub fn default_whir_config() -> Self {
        let folding_factor = 4;
        Self {
            starting_ood_samples: 1,
            starting_log_inv_rate: 1,
            starting_interleaved_log_height: 12,
            starting_folding_pow_bits: vec![10; folding_factor],
            round_parameters: vec![
                RoundConfig {
                    folding_factor,
                    evaluation_domain_log_size: 12,
                    queries_pow_bits: 10,
                    pow_bits: vec![10; folding_factor],
                    num_queries: 90,
                    ood_samples: 1,
                },
                RoundConfig {
                    folding_factor,
                    evaluation_domain_log_size: 11,
                    queries_pow_bits: 10,
                    pow_bits: vec![10; folding_factor],
                    num_queries: 15,
                    ood_samples: 1,
                },
            ],
            final_queries: 10,
            final_pow_bits: 10,
            final_folding_pow_bits: vec![10; 8],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhirProofShape<F, EF> {
    /// The OOD samples used in the commitment.
    starting_ood_samples: usize,

    /// The rate of the initial RS code used during the protocol.
    starting_log_inv_rate: usize,

    /// The initial folding factor.
    starting_interleaved_log_height: usize,

    /// The initial pow bits used in the first fold.
    starting_folding_pow_bits: Vec<usize>,

    /// The round-specific parameters.
    round_parameters: Vec<RoundConfig>,

    /// Number of queries in the last round
    final_queries: usize,

    /// Number of final bits of proof of work (for the queries).
    final_pow_bits: usize,

    /// Number of final bits of proof of work (for the sumcheck).
    final_folding_pow_bits: Vec<usize>,

    _marker: std::marker::PhantomData<(F, EF)>,
}

impl<F: TwoAdicField + PrimeField64, EF: ExtensionField<F>> WhirProofShape<F, EF> {
    pub fn new(config: UncheckedWhirProofShape) -> Self {
        let starting_domain_log_size =
            config.starting_interleaved_log_height + config.starting_log_inv_rate;

        assert!(starting_domain_log_size >= config.round_parameters.len(), "each STIR round reduces the domain size by 1, so starting_domain_log_size must be at least round_params.len()");
        assert!(config.round_parameters.iter().enumerate().all(|(i, param)| param.evaluation_domain_log_size == starting_domain_log_size - i - 1), "each STIR round reduces the domain size by 1, so each round's evaluation_domain_log_size must be equal to starting_domain_log_size - i - 1");
        assert!(
            config.starting_interleaved_log_height < (usize::BITS as usize),
            "starting_interleaved_log_height must be less than usize::BITS"
        );
        assert!(
            starting_domain_log_size < (usize::BITS as usize),
            "starting_domain_log_size must be less than usize::BITS"
        );
        assert!(1 << starting_domain_log_size < F::ORDER_U64);

        assert!(config.starting_folding_pow_bits.iter().all(|&bits| 1 << bits < F::ORDER_U64));
        assert!(config.final_folding_pow_bits.iter().all(|&bits| 1 << bits < F::ORDER_U64));

        for round_param in &config.round_parameters {
            assert!(round_param.folding_factor < usize::BITS as usize);

            // Check that the folding factor does not overflow when multiplied by EF::D
            assert!(!(1usize << round_param.folding_factor).overflowing_mul(EF::D).1);

            assert!(1 << round_param.queries_pow_bits < F::ORDER_U64);

            assert!(round_param.pow_bits.iter().all(|&bits| 1 << bits < F::ORDER_U64));
        }

        let result = Self {
            starting_ood_samples: config.starting_ood_samples,
            starting_log_inv_rate: config.starting_log_inv_rate,
            starting_interleaved_log_height: config.starting_interleaved_log_height,
            starting_folding_pow_bits: config.starting_folding_pow_bits,
            round_parameters: config.round_parameters,
            final_queries: config.final_queries,
            final_folding_pow_bits: config.final_folding_pow_bits,
            final_pow_bits: config.final_pow_bits,
            _marker: std::marker::PhantomData,
        };

        assert!(result.check_usizes_bound_by_field_order());
        assert!(result.final_poly_log_degree() < usize::BITS as usize);
        result
    }
}
impl<F: TwoAdicField, EF: ExtensionField<F>> WhirProofShape<F, EF> {
    pub fn check_usizes_bound_by_field_order(&self) -> bool {
        let &WhirProofShape {
            starting_ood_samples,
            starting_log_inv_rate,
            starting_interleaved_log_height,
            ref starting_folding_pow_bits,
            ref round_parameters,
            final_queries,
            final_pow_bits,
            ref final_folding_pow_bits,
            ..
        } = self;
        let mut result = true;
        let order = F::order();
        result &= BigUint::from(starting_ood_samples) <= order;
        result &= BigUint::from(starting_log_inv_rate) <= order;
        result &= BigUint::from(starting_interleaved_log_height) <= order;
        result &= BigUint::from(self.starting_domain_log_size()) <= order;
        result &= starting_folding_pow_bits.iter().all(|&b| BigUint::from(b) <= order);
        round_parameters.iter().for_each(|rp| {
            let &RoundConfig {
                folding_factor,
                evaluation_domain_log_size,
                queries_pow_bits,
                ref pow_bits,
                num_queries,
                ood_samples,
            } = rp;
            result &= BigUint::from(folding_factor) <= order
                && BigUint::from(evaluation_domain_log_size) <= order
                && BigUint::from(queries_pow_bits) <= order
                && pow_bits.iter().all(|&b| BigUint::from(b) <= order)
                && BigUint::from(num_queries) <= order
                && BigUint::from(ood_samples) <= order;
        });
        result &= BigUint::from(self.final_poly_log_degree()) <= order;
        result &= BigUint::from(final_queries) <= order;
        result &= BigUint::from(final_pow_bits) <= order;
        result &= final_folding_pow_bits.iter().all(|&b| BigUint::from(b) <= order);
        result
    }
    pub fn write_to_challenger<D: Copy, C: VariableLengthChallenger<F, D>>(
        &self,
        challenger: &mut C,
    ) {
        assert!(self.check_usizes_bound_by_field_order());
        let &WhirProofShape {
            starting_ood_samples,
            starting_log_inv_rate,
            starting_interleaved_log_height,
            ref starting_folding_pow_bits,
            ref round_parameters,
            final_queries,
            final_pow_bits,
            ref final_folding_pow_bits,
            ..
        } = self;
        challenger.observe(F::from_canonical_usize(starting_ood_samples));
        challenger.observe(F::from_canonical_usize(starting_log_inv_rate));
        challenger.observe(F::from_canonical_usize(starting_interleaved_log_height));
        challenger
            .observe_variable_length_slice(
                &starting_folding_pow_bits
                    .iter()
                    .copied()
                    .map(F::from_canonical_usize)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        assert!(BigUint::from(round_parameters.len()) <= F::order());
        challenger.observe(F::from_canonical_usize(round_parameters.len()));
        round_parameters.iter().for_each(|f| f.write_to_challenger(challenger));
        challenger.observe(F::from_canonical_usize(final_queries));
        challenger.observe(F::from_canonical_usize(final_pow_bits));
        challenger
            .observe_variable_length_slice(
                &final_folding_pow_bits
                    .iter()
                    .copied()
                    .map(F::from_canonical_usize)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
    }

    pub fn domain_generator(&self) -> F
    where
        F: TwoAdicField,
    {
        F::two_adic_generator(self.starting_domain_log_size())
    }

    pub fn starting_ood_samples(&self) -> usize {
        self.starting_ood_samples
    }

    pub fn starting_log_inv_rate(&self) -> usize {
        self.starting_log_inv_rate
    }

    pub fn starting_interleaved_log_height(&self) -> usize {
        self.starting_interleaved_log_height
    }

    pub fn starting_domain_log_size(&self) -> usize {
        self.starting_interleaved_log_height + self.starting_log_inv_rate
    }

    pub fn starting_folding_pow_bits(&self) -> &[usize] {
        &self.starting_folding_pow_bits
    }

    pub fn round_parameters(&self) -> &[RoundConfig] {
        &self.round_parameters
    }

    pub fn final_poly_log_degree(&self) -> usize {
        let num_folded_variables =
            self.round_parameters.iter().map(|p| p.folding_factor).sum::<usize>();

        self.starting_interleaved_log_height - num_folded_variables
    }

    pub fn final_queries(&self) -> usize {
        self.final_queries
    }

    pub fn final_pow_bits(&self) -> usize {
        self.final_pow_bits
    }

    pub fn final_folding_pow_bits(&self) -> &[usize] {
        &self.final_folding_pow_bits
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
}

impl RoundConfig {
    pub fn write_to_challenger<F: Field, D: Copy, C: VariableLengthChallenger<F, D>>(
        &self,
        challenger: &mut C,
    ) {
        challenger.observe(F::from_canonical_usize(self.folding_factor));
        challenger.observe(F::from_canonical_usize(self.evaluation_domain_log_size));
        challenger.observe(F::from_canonical_usize(self.queries_pow_bits));
        challenger
            .observe_variable_length_slice(
                &self.pow_bits.iter().copied().map(F::from_canonical_usize).collect::<Vec<_>>(),
            )
            .unwrap();
        challenger.observe(F::from_canonical_usize(self.num_queries));
        challenger.observe(F::from_canonical_usize(self.ood_samples));
    }
}
