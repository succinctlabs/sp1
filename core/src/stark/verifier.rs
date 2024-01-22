use crate::utils::AirChip;
use p3_uni_stark::StarkConfig;
use p3_util::log2_ceil_usize;
use std::marker::PhantomData;

use super::types::{OpenningError, SegmentProof};

pub struct Verifier<SC>(PhantomData<SC>);

impl<SC: StarkConfig> Verifier<SC> {
    /// Verify a proof for a collection of air chips.
    #[allow(unused_variables)]
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

        todo!()

        //     let dims = &[
        //         chips
        //             .iter()
        //             .zip(degree_bits.iter())
        //             .map(|(chip, deg_bits)| Dimensions {
        //                 width: chip.air_width(),
        //                 height: 1 << deg_bits,
        //             })
        //             .collect::<Vec<_>>(),
        //         vec![],
        //         vec![],
        //     ];

        //     let g_subgroups = degree_bits
        //         .iter()
        //         .map(|log_deg| SC::Val::two_adic_generator(*log_deg))
        //         .collect::<Vec<_>>();

        //     let SegmentCommitment {
        //         main_commit,
        //         permutation_commit,
        //         quotient_commit,
        //     } = commitment;

        //     let permutation_challenges = (0..2)
        //         .map(|_| challenger.sample_ext_element::<SC::Challenge>())
        //         .collect::<Vec<_>>();

        //     challenger.observe(permutation_commit.clone());
        //     let alpha = challenger.sample_ext_element::<SC::Challenge>();

        //     // Observe the quotient commitments.
        //     challenger.observe(quotient_commit.clone());

        //     let zeta = challenger.sample_ext_element::<SC::Challenge>();

        //     // Verify the openning proof.
        //     let trace_openning_points = g_subgroups
        //         .iter()
        //         .map(|g| vec![zeta, zeta * *g])
        //         .collect::<Vec<_>>();

        //     let zeta_quot_pow = zeta.exp_power_of_2(log_quotient_degree);
        //     let quotient_openning_points = (0..chips.len())
        //         .map(|_| vec![zeta_quot_pow])
        //         .collect::<Vec<_>>();

        //     config
        //         .pcs()
        //         .verify_multi_batches(
        //             &[
        //                 (main_commit.clone(), &trace_openning_points),
        //                 (permutation_commit.clone(), &trace_openning_points),
        //                 (quotient_commit.clone(), &quotient_openning_points),
        //             ],
        //             dims,
        //             opened_values.clone().into_values(),
        //             openning_proof,
        //             challenger,
        //         )
        //         .map_err(|e| VerificationError::InvalidOpenningArgument(e))?;

        //     Ok(())
        // }
    }

    // fn verify_proof_shape(chips: &[Box<dyn AirChip<SC>>], proof: &SegmentProof<SC>) {}
}

#[derive(Debug)]
pub enum ProofShapeError {
    InvalidProofShape,
}

#[allow(dead_code)]
pub struct InvalidOpenningArgument;

#[allow(dead_code)]
pub struct OodEvaluationMismatch;

pub enum VerificationError<SC: StarkConfig> {
    InvalidProofShape(ProofShapeError),
    InvalidOpenningArgument(OpenningError<SC>),
    OodEvaluationMismatch,
}

// impl Display for VerificationError {
//     fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
//         match self {
//             VerificationError::InvalidProofShape => write!(f, "Invalid proof shape"),
//             VerificationError::InvalidOpenningArgument => write!(f, "Invalid openning argument"),
//             VerificationError::OodEvaluationMismatch => write!(f, "Ood evaluation mismatch"),
//         }
//     }
// }

// impl Error for VerificationError {}
