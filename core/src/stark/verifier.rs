use itertools::izip;
use p3_challenger::CanObserve;
use p3_challenger::FieldChallenger;
use p3_commit::UnivariatePcs;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use p3_field::Field;
use p3_field::TwoAdicField;
use p3_matrix::Dimensions;

use p3_util::log2_ceil_usize;
use p3_util::reverse_slice_index_bits;
use std::fmt::Formatter;
use std::marker::PhantomData;

use crate::chip::AirChip;
use crate::lookup::Interaction;

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
        chips: Vec<Box<dyn AirChip<SC>>>,
        challenger: &mut SC::Challenger,
        proof: &SegmentProof<SC>,
    ) -> Result<(), VerificationError> {
        let max_constraint_degree = 3;
        let log_quotient_degree = log2_ceil_usize(max_constraint_degree - 1);
        let SegmentProof {
            commitment,
            opened_values,
            opening_proof,
            chip_ids,
        } = proof;

        // Filter the chips.
        let chips = chips
            .into_iter()
            .filter(|chip| chip_ids.contains(&chip.name()))
            .collect::<Vec<_>>();

        let sends = chips.iter().map(|chip| chip.sends()).collect::<Vec<_>>();
        let receives = chips.iter().map(|chip| chip.receives()).collect::<Vec<_>>();

        let num_interactions = sends
            .iter()
            .zip(receives.iter())
            .map(|(s, r)| s.len() + r.len())
            .collect::<Vec<usize>>();

        // // Verify the proof shapes.
        // for ((chip, interactions), opened_vals) in chips
        //     .iter()
        //     .zip(chips_interactions.iter())
        //     .zip(opened_values.chips.iter())
        // {
        //     Self::verify_proof_shape(
        //         chip.as_ref(),
        //         interactions.len(),
        //         opened_vals,
        //         log_quotient_degree,
        //     )
        //     .map_err(|err| VerificationError::InvalidProofShape(err, chip.name()))?;
        // }

        let quotient_width = SC::Challenge::D << log_quotient_degree;
        let dims = &[
            chips
                .iter()
                .zip(opened_values.chips.iter())
                .map(|(chip, val)| Dimensions {
                    width: chip.air_width(),
                    height: 1 << val.log_degree,
                })
                .collect::<Vec<_>>(),
            num_interactions
                .iter()
                .zip(opened_values.chips.iter())
                .map(|(n_int, val)| Dimensions {
                    width: (*n_int + 1) * SC::Challenge::D,
                    height: 1 << val.log_degree,
                })
                .collect::<Vec<_>>(),
            (0..chips.len())
                .zip(opened_values.chips.iter())
                .map(|(_, val)| Dimensions {
                    width: quotient_width,
                    height: 1 << val.log_degree,
                })
                .collect::<Vec<_>>(),
        ];

        let g_subgroups = opened_values
            .chips
            .iter()
            .map(|val| SC::Val::two_adic_generator(val.log_degree))
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

        for (i, (chip, values, g)) in
            izip!(chips.iter(), opened_values.chips.iter(), g_subgroups.iter()).enumerate()
        {
            Self::verify_constraints(
                chip.as_ref(),
                &sends[i],
                &receives[i],
                values.clone(),
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

    // /// Verify the shape of opening arguments and permutation challenges.
    // ///
    // /// This function checks that the preprocessed_opening, main opening, permutation opening,
    // /// quotient opening have the expected dimensions.
    // fn verify_proof_shape<C>(
    //     chip: &C,
    //     num_interactions: usize,
    //     opened_values: &ChipOpenedValues<SC::Challenge>,
    //     log_quotient_degree: usize,
    // ) -> Result<(), ProofShapeError>
    // where
    //     C: AirChip<SC> + ?Sized,
    // {
    //     // Todo : check preprocessed shape.
    //     let preprocesses_width = 0;
    //     if opened_values.preprocessed.local.len() != preprocesses_width
    //         || opened_values.preprocessed.next.len() != preprocesses_width
    //     {
    //         return Err(ProofShapeError::Preprocessed);
    //     }

    //     // Check that the main opening rows have lengths that match the chip width.
    //     let main_width = chip.air_width();
    //     if opened_values.main.local.len() != main_width
    //         || opened_values.main.next.len() != main_width
    //     {
    //         return Err(ProofShapeError::MainTrace);
    //     }

    //     // Check that the permutation openninps have lengths that match the number of interactions.
    //     let perm_width = SC::Challenge::D * (num_interactions + 1);
    //     if opened_values.permutation.local.len() != perm_width
    //         || opened_values.permutation.next.len() != perm_width
    //     {
    //         return Err(ProofShapeError::Permuation);
    //     }

    //     // Check that the quotient opening has the expected length for the given degree.
    //     let quotient_width = SC::Challenge::D << log_quotient_degree;
    //     if opened_values.quotient.len() != quotient_width {
    //         return Err(ProofShapeError::Quotient);
    //     }

    //     Ok(())
    // }

    #[allow(clippy::too_many_arguments)]
    fn verify_constraints<C>(
        chip: &C,
        sends: &[Interaction<SC::Val>],
        receives: &[Interaction<SC::Val>],
        opening: ChipOpenedValues<SC::Challenge>,
        g: SC::Val,
        zeta: SC::Challenge,
        alpha: SC::Challenge,
        permutation_challenges: &[SC::Challenge],
    ) -> Result<(), OodEvaluationMismatch>
    where
        C: AirChip<SC> + ?Sized,
    {
        let z_h = zeta.exp_power_of_2(opening.log_degree) - SC::Challenge::one();
        let is_first_row = z_h / (zeta - SC::Val::one());
        let is_last_row = z_h / (zeta - g.inverse());
        let is_transition = zeta - g.inverse();

        // Reconstruct the prmutation opening values as extention elements.
        let monomials = (0..SC::Challenge::D)
            .map(SC::Challenge::monomial)
            .collect::<Vec<_>>();

        let unflatten = |v: &[SC::Challenge]| {
            v.chunks_exact(SC::Challenge::D)
                .map(|chunk| {
                    chunk
                        .iter()
                        .zip(monomials.iter())
                        .map(|(x, m)| *x * *m)
                        .sum()
                })
                .collect::<Vec<SC::Challenge>>()
        };

        let mut quotient_parts = opening
            .quotient
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
            local: unflatten(&opening.permutation.local),
            next: unflatten(&opening.permutation.next),
        };

        let mut folder = VerifierConstraintFolder {
            preprocessed: opening.preprocessed.view(),
            main: opening.main.view(),
            perm: perm_opening.view(),
            perm_challenges: permutation_challenges,
            is_first_row,
            is_last_row,
            is_transition,
            alpha,
            accumulator: SC::Challenge::zero(),
        };
        chip.eval(&mut folder);
        eval_permutation_constraints(sends, receives, &mut folder, opening.cumulative_sum);

        let folded_constraints = folder.accumulator;

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
