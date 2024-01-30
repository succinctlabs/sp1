use crate::utils::AirChip;
use p3_air::TwoRowMatrixView;
use p3_challenger::CanObserve;
use p3_challenger::FieldChallenger;
use p3_commit::UnivariatePcs;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use p3_field::Field;
use p3_field::Res;
use p3_field::TwoAdicField;
use p3_matrix::Dimensions;

use p3_util::log2_ceil_usize;
use p3_util::reverse_slice_index_bits;
use std::fmt::Formatter;
use std::marker::PhantomData;

use super::folder::VerifierConstraintFolder;
use super::permutation::eval_permutation_constraints;
use super::types::*;
use super::StarkConfig;

use core::fmt::Display;

pub struct Verifier<SC>(PhantomData<SC>);

impl<SC: StarkConfig> Verifier<SC> {
    /// Verify a proof for a collection of air chips.
    #[cfg(feature = "perf")]
    pub fn verify(
        config: &SC,
        chips: &[Box<dyn AirChip<SC>>],
        challenger: &mut SC::Challenger,
        proof: &SegmentProof<SC>,
    ) -> Result<(), VerificationError> {
        let max_constraint_degree = 3;
        let log_quotient_degree = log2_ceil_usize(max_constraint_degree - 1);

        let chips_interactions = chips
            .iter()
            .map(|chip| chip.all_interactions())
            .collect::<Vec<_>>();

        let SegmentProof {
            commitment,
            opened_values,
            commulative_sums,
            opening_proof,
            degree_bits,
        } = proof;

        // Verify the proof shapes.
        for ((((chip, interactions), main), perm), quotient) in chips
            .iter()
            .zip(chips_interactions.iter())
            .zip(opened_values.main.iter())
            .zip(opened_values.permutation.iter())
            .zip(opened_values.quotient.iter())
        {
            Self::verify_proof_shape(
                chip.as_ref(),
                interactions.len(),
                &AirOpenedValues {
                    local: vec![],
                    next: vec![],
                },
                main,
                perm,
                quotient,
                log_quotient_degree,
            )
            .map_err(|err| VerificationError::InvalidProofShape(err, chip.name()))?;
        }

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

        #[cfg(feature = "perf")]
        challenger.observe(permutation_commit.clone());

        let alpha = challenger.sample_ext_element::<SC::Challenge>();

        // Observe the quotient commitments.
        challenger.observe(quotient_commit.clone());

        let zeta = challenger.sample_ext_element::<SC::Challenge>();

        // Verify the opening proof.
        let trace_opening_points = g_subgroups
            .iter()
            .map(|g| vec![zeta, zeta * *g])
            .collect::<Vec<_>>();

        let zeta_quot_pow = zeta.exp_power_of_2(log_quotient_degree);
        let quotient_opening_points = (0..chips.len())
            .map(|_| vec![zeta_quot_pow])
            .collect::<Vec<_>>();

        config
            .pcs()
            .verify_multi_batches(
                &[
                    (main_commit.clone(), &trace_opening_points),
                    (permutation_commit.clone(), &trace_opening_points),
                    (quotient_commit.clone(), &quotient_opening_points),
                ],
                dims,
                opened_values.clone().into_values(),
                opening_proof,
                challenger,
            )
            .map_err(|_| VerificationError::InvalidopeningArgument)?;

        // Verify the constrtaint evaluations.
        let SegmentOpenedValues {
            main,
            permutation,
            quotient,
        } = opened_values;
        for (
            (
                ((((chip, main_opening), permutation_opening), quotient_opening), commulative_sum),
                log_degree,
            ),
            g,
        ) in chips
            .iter()
            .zip(main.iter())
            .zip(permutation.iter())
            .zip(quotient.iter())
            .zip(commulative_sums.iter())
            .zip(degree_bits.iter())
            .zip(g_subgroups.iter())
        {
            Self::verify_constraints(
                chip.as_ref(),
                main_opening,
                permutation_opening,
                quotient_opening,
                *commulative_sum,
                *log_degree,
                *g,
                zeta,
                alpha,
                &permutation_challenges,
            )
            .map_err(|_| VerificationError::OodEvaluationMismatch(chip.name()))?;
        }

        Ok(())
    }

    #[cfg(not(feature = "perf"))]
    pub fn verify(
        _config: &SC,
        _chips: &[Box<dyn AirChip<SC>>],
        _challenger: &mut SC::Challenger,
        _proof: &SegmentProof<SC>,
    ) -> Result<(), VerificationError> {
        Ok(())
    }

    /// Verify the shape of opening arguments and permutation challenges.
    ///
    /// This function checks that the preprocessed_opening, main opening, permutation opening,
    /// quotient opening have the expected dimensions.
    fn verify_proof_shape<C>(
        chip: &C,
        num_interactions: usize,
        preprocessed_opening: &AirOpenedValues<SC::Challenge>,
        main_opening: &AirOpenedValues<SC::Challenge>,
        permutation_opening: &AirOpenedValues<SC::Challenge>,
        quotient_opening: &QuotientOpenedValues<SC::Challenge>,
        log_quotient_degree: usize,
    ) -> Result<(), ProofShapeError>
    where
        C: AirChip<SC> + ?Sized,
    {
        // Todo : check preprocessed shape.
        let preprocesses_width = 0;
        if preprocessed_opening.local.len() != preprocesses_width
            || preprocessed_opening.next.len() != preprocesses_width
        {
            return Err(ProofShapeError::Preprocessed);
        }

        // Check that the main opening rows have lengths that match the chip width.
        let main_width = chip.air_width();
        if main_opening.local.len() != main_width || main_opening.next.len() != main_width {
            return Err(ProofShapeError::MainTrace);
        }

        // Check that the permutation openninps have lengths that match the number of interactions.
        let perm_width = SC::Challenge::D * (num_interactions + 1);
        if permutation_opening.local.len() != perm_width
            || permutation_opening.next.len() != perm_width
        {
            return Err(ProofShapeError::Permuation);
        }

        // Check that the quotient opening has the expected length for the given degree.
        let quotient_width = SC::Challenge::D << log_quotient_degree;
        if quotient_opening.len() != quotient_width {
            return Err(ProofShapeError::Quotient);
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_constraints<C>(
        chip: &C,
        main_opening: &AirOpenedValues<SC::Challenge>,
        permutation_opening: &AirOpenedValues<SC::Challenge>,
        quotient_opening: &QuotientOpenedValues<SC::Challenge>,
        commulative_sum: SC::Challenge,
        log_degree: usize,
        g: SC::Val,
        zeta: SC::Challenge,
        alpha: SC::Challenge,
        permutation_challenges: &[SC::Challenge],
    ) -> Result<(), OodEvaluationMismatch>
    where
        C: AirChip<SC> + ?Sized,
    {
        let z_h = zeta.exp_power_of_2(log_degree) - SC::Challenge::one();
        let is_first_row = z_h / (zeta - SC::Val::one());
        let is_last_row = z_h / (zeta - g.inverse());
        let is_transition = zeta - g.inverse();

        // Reconstruct the prmutation opening values as extention elements.
        let monomials = (0..SC::Challenge::D)
            .map(SC::Challenge::monomial)
            .collect::<Vec<_>>();

        let res = |v: &[SC::Challenge]| {
            v.iter()
                .map(|x| Res::from_inner(*x))
                .collect::<Vec<Res<SC::Val, SC::Challenge>>>()
        };

        let embed_alg = |v: &[SC::Challenge]| {
            v.chunks_exact(SC::Challenge::D)
                .map(|chunk| {
                    let res_chunk = chunk
                        .iter()
                        .map(|x| Res::from_inner(*x))
                        .collect::<Vec<Res<SC::Val, SC::Challenge>>>();
                    SC::ChallengeAlgebra::from_base_slice(&res_chunk)
                })
                .collect::<Vec<SC::ChallengeAlgebra>>()
        };

        let mut quotient_parts = quotient_opening
            .chunks_exact(SC::Challenge::D)
            .map(|chunk| {
                chunk
                    .iter()
                    .zip(monomials.iter())
                    .map(|(x, m)| *x * *m)
                    .sum()
            })
            .collect::<Vec<SC::Challenge>>();

        reverse_slice_index_bits(&mut quotient_parts);
        let quotient: SC::Challenge = zeta
            .powers()
            .zip(quotient_parts)
            .map(|(weight, part)| part * weight)
            .sum();

        let perm_opening = AirOpenedValues {
            local: embed_alg(&permutation_opening.local),
            next: embed_alg(&permutation_opening.next),
        };

        let mut folder = VerifierConstraintFolder {
            preprocessed: TwoRowMatrixView {
                local: &[],
                next: &[],
            },
            main: TwoRowMatrixView {
                local: &res(&main_opening.local),
                next: &res(&main_opening.next),
            },
            perm: TwoRowMatrixView {
                local: &perm_opening.local,
                next: &perm_opening.next,
            },
            perm_challenges: permutation_challenges,
            is_first_row,
            is_last_row,
            is_transition,
            alpha,
            accumulator: Res::zero(),
        };
        chip.eval(&mut folder);
        eval_permutation_constraints(chip, &mut folder, commulative_sum);

        let folded_constraints = folder.accumulator.into_inner();

        match folded_constraints == z_h * quotient {
            true => Ok(()),
            false => Err(OodEvaluationMismatch),
        }
    }
}

#[derive(Debug)]
pub enum ProofShapeError {
    Preprocessed,
    MainTrace,
    Permuation,
    Quotient,
}

pub struct OodEvaluationMismatch;

#[derive(Debug)]
pub enum VerificationError {
    /// The shape of openings does not match the chip shapes.
    InvalidProofShape(ProofShapeError, String),
    /// opening proof is invalid.
    InvalidopeningArgument,
    /// Out-of-domain evaluation mismatch.
    ///
    /// `constraints(zeta)` did not match `quotient(zeta) Z_H(zeta)`.
    OodEvaluationMismatch(String),
}

impl Display for VerificationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            VerificationError::InvalidProofShape(err, chip) => {
                write!(f, "Invalid proof shape for chip {}: {:?}", chip, err)
            }
            VerificationError::InvalidopeningArgument => {
                write!(f, "Invalid opening argument")
            }
            VerificationError::OodEvaluationMismatch(chip) => {
                write!(f, "Out-of-domain evaluation mismatch on chip {}", chip)
            }
        }
    }
}
