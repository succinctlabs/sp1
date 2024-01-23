use crate::utils::AirChip;
use p3_air::TwoRowMatrixView;
use p3_challenger::CanObserve;
use p3_challenger::FieldChallenger;
use p3_commit::UnivariatePcs;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use p3_field::Field;
use p3_field::TwoAdicField;
use p3_matrix::Dimensions;
use p3_uni_stark::StarkConfig;
use p3_util::log2_ceil_usize;
use std::marker::PhantomData;

use super::folder::VerifierConstraintFolder;
use super::permutation::eval_permutation_constraints;
use super::types::*;

pub struct Verifier<SC>(PhantomData<SC>);

impl<SC: StarkConfig> Verifier<SC> {
    /// Verify a proof for a collection of air chips.
    pub fn verify(
        config: &SC,
        chips: &[Box<dyn AirChip<SC>>],
        challenger: &mut SC::Challenger,
        proof: &SegmentProof<SC>,
    ) -> Result<(), VerificationError<SC>> {
        let max_constraint_degree = 3;
        let log_quotient_degree = log2_ceil_usize(max_constraint_degree - 1);

        let chips_interactions = chips
            .iter()
            .map(|chip| chip.all_interactions())
            .collect::<Vec<_>>();

        let SegmentProof {
            commitment,
            opened_values,
            commulative_sums: _,
            openning_proof,
            degree_bits,
        } = proof;

        let quotient_width = SC::Challenge::D << log_quotient_degree;
        let dims = &[
            chips
                .iter()
                .zip(degree_bits.iter())
                .map(|(chip, deg_bits)| Dimensions {
                    width: chip.air_width(),
                    height: 1 << deg_bits,
                })
                .collect::<Vec<_>>(),
            chips_interactions
                .iter()
                .zip(degree_bits.iter())
                .map(|(interactions, deg_bits)| Dimensions {
                    width: (interactions.len() + 1) * SC::Challenge::D,
                    height: 1 << deg_bits,
                })
                .collect::<Vec<_>>(),
            (0..chips.len())
                .zip(degree_bits.iter())
                .map(|(_, deg_bits)| Dimensions {
                    width: quotient_width,
                    height: 1 << deg_bits,
                })
                .collect::<Vec<_>>(),
        ];

        let g_subgroups = degree_bits
            .iter()
            .map(|log_deg| SC::Val::two_adic_generator(*log_deg))
            .collect::<Vec<_>>();

        let SegmentCommitment {
            main_commit,
            permutation_commit,
            quotient_commit,
        } = commitment;

        let permutation_challenges = (0..2)
            .map(|_| challenger.sample_ext_element::<SC::Challenge>())
            .collect::<Vec<_>>();

        challenger.observe(permutation_commit.clone());
        let alpha = challenger.sample_ext_element::<SC::Challenge>();

        // Observe the quotient commitments.
        challenger.observe(quotient_commit.clone());

        let zeta = challenger.sample_ext_element::<SC::Challenge>();

        // Verify the openning proof.
        let trace_openning_points = g_subgroups
            .iter()
            .map(|g| vec![zeta, zeta * *g])
            .collect::<Vec<_>>();

        let zeta_quot_pow = zeta.exp_power_of_2(log_quotient_degree);
        let quotient_openning_points = (0..chips.len())
            .map(|_| vec![zeta_quot_pow])
            .collect::<Vec<_>>();

        config
            .pcs()
            .verify_multi_batches(
                &[
                    (main_commit.clone(), &trace_openning_points),
                    (permutation_commit.clone(), &trace_openning_points),
                    (quotient_commit.clone(), &quotient_openning_points),
                ],
                dims,
                opened_values.clone().into_values(),
                openning_proof,
                challenger,
            )
            .map_err(|e| VerificationError::InvalidOpenningArgument(e))?;

        // Verify the constrtaint evaluations.

        Ok(())
    }

    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn verify_constraints<C>(
        config: &SC,
        chip: &C,
        main_openning: &AirOpenedValues<SC::Challenge>,
        permutation_openning: &AirOpenedValues<SC::Challenge>,
        quotient_openning: &QuotientOpenedValues<SC::Challenge>,
        commulative_sum: SC::Challenge,
        log_degree: usize,
        g: SC::Val,
        zeta: SC::Challenge,
        alpha: SC::Challenge,
        permutation_challenges: &[SC::Challenge],
    ) -> Result<(), OodEvaluationMismatch>
    where
        C: AirChip<SC>,
    {
        let z_h = zeta.exp_power_of_2(log_degree) - SC::Challenge::one();
        let is_first_row = z_h / (zeta - SC::Val::one());
        let is_last_row = z_h / (zeta - g.inverse());
        let is_transition = zeta - g.inverse();

        // Reconstruct the prmutation openning values as extention elements.
        let monomials = (0..SC::Challenge::D)
            .map(|i| SC::Challenge::monomial(i))
            .collect::<Vec<_>>();
        let embed = |v: &[SC::Challenge]| {
            v.chunks_exact(SC::Challenge::D)
                .map(|slice| {
                    slice
                        .into_iter()
                        .zip(monomials.iter())
                        .map(|(x, m)| *x * *m)
                        .sum::<SC::Challenge>()
                })
                .collect::<Vec<SC::Challenge>>()
        };

        let perm_openning = AirOpenedValues {
            local: embed(&permutation_openning.local),
            next: embed(&permutation_openning.next),
        };

        let mut folder = VerifierConstraintFolder {
            preprocessed: TwoRowMatrixView {
                local: &[],
                next: &[],
            },
            main: TwoRowMatrixView {
                local: &main_openning.local,
                next: &main_openning.next,
            },
            perm: TwoRowMatrixView {
                local: &perm_openning.local,
                next: &perm_openning.next,
            },
            perm_challenges: permutation_challenges,
            is_first_row,
            is_last_row,
            is_transition,
            alpha,
            accumulator: SC::Challenge::zero(),
        };
        chip.eval(&mut folder);
        eval_permutation_constraints(chip, &mut folder, commulative_sum);

        Ok(())
    }

    // fn verify_constraints<A>(
    //     config: &SC,
    //     air: &A,
    //     openning: AirOpenedValues,
    // ) -> Result<(), VerificationError<SC>>
    // where
    //     A: for<'a> Air<VerifierConstraintFolder<'a, Challenge<SC>>> + ?Sized,
    // {
    //     Ok(())
    // }

    // fn verify_proof_shape(chips: &[Box<dyn AirChip<SC>>], proof: &SegmentProof<SC>) {}
}

#[derive(Debug)]
pub enum ProofShapeError {
    InvalidProofShape,
}

pub struct OodEvaluationMismatch;

pub enum VerificationError<SC: StarkConfig> {
    InvalidProofShape(ProofShapeError),
    InvalidOpenningArgument(OpenningError<SC>),
    OodEvaluationMismatch,
}
