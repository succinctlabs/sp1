use core::fmt::Display;
use std::fmt::Formatter;
use std::marker::PhantomData;

use itertools::Itertools;
use p3_air::Air;
use p3_challenger::CanObserve;
use p3_challenger::FieldChallenger;
use p3_commit::LagrangeSelectors;
use p3_commit::Pcs;
use p3_commit::PolynomialSpace;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;

use super::folder::VerifierConstraintFolder;
use super::types::*;
use super::Domain;
use super::StarkGenericConfig;
use super::StarkVerifyingKey;
use super::Val;
use crate::air::MachineAir;
use crate::stark::MachineChip;

pub struct Verifier<SC, A>(PhantomData<SC>, PhantomData<A>);

impl<SC: StarkGenericConfig, A: MachineAir<Val<SC>>> Verifier<SC, A> {
    /// Verify a proof for a collection of air chips.
    pub fn verify_shard(
        config: &SC,
        vk: &StarkVerifyingKey<SC>,
        chips: &[&MachineChip<SC, A>],
        challenger: &mut SC::Challenger,
        proof: &ShardProof<SC>,
    ) -> Result<(), VerificationError>
    where
        A: for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    {
        use itertools::izip;

        let ShardProof {
            commitment,
            opened_values,
            opening_proof,
            ..
        } = proof;

        let pcs = config.pcs();

        let log_degrees = opened_values
            .chips
            .iter()
            .map(|val| val.log_degree)
            .collect::<Vec<_>>();

        let log_quotient_degrees = chips
            .iter()
            .map(|chip| chip.log_quotient_degree())
            .collect::<Vec<_>>();

        let trace_domains = log_degrees
            .iter()
            .map(|log_degree| pcs.natural_domain_for_degree(1 << log_degree))
            .collect::<Vec<_>>();

        let ShardCommitment {
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

        let preprocessed_domains_points_and_opens = vk
            .chip_information
            .iter()
            .map(|(name, domain, _)| {
                let i = proof.chip_ordering[name];
                let values = proof.opened_values.chips[i].preprocessed.clone();
                (
                    *domain,
                    vec![
                        (zeta, values.local),
                        (domain.next_point(zeta).unwrap(), values.next),
                    ],
                )
            })
            .collect::<Vec<_>>();

        let main_domains_points_and_opens = trace_domains
            .iter()
            .zip_eq(proof.opened_values.chips.iter())
            .map(|(domain, values)| {
                (
                    *domain,
                    vec![
                        (zeta, values.main.local.clone()),
                        (domain.next_point(zeta).unwrap(), values.main.next.clone()),
                    ],
                )
            })
            .collect::<Vec<_>>();

        let perm_domains_points_and_opens = trace_domains
            .iter()
            .zip_eq(proof.opened_values.chips.iter())
            .map(|(domain, values)| {
                (
                    *domain,
                    vec![
                        (zeta, values.permutation.local.clone()),
                        (
                            domain.next_point(zeta).unwrap(),
                            values.permutation.next.clone(),
                        ),
                    ],
                )
            })
            .collect::<Vec<_>>();

        let quotient_chunk_domains = trace_domains
            .iter()
            .zip_eq(log_degrees)
            .zip_eq(log_quotient_degrees)
            .map(|((domain, log_degree), log_quotient_degree)| {
                let quotient_degree = 1 << log_quotient_degree;
                let quotient_domain =
                    domain.create_disjoint_domain(1 << (log_degree + log_quotient_degree));
                quotient_domain.split_domains(quotient_degree)
            })
            .collect::<Vec<_>>();

        let quotient_domains_points_and_opens = proof
            .opened_values
            .chips
            .iter()
            .zip_eq(quotient_chunk_domains.iter())
            .flat_map(|(values, qc_domains)| {
                values
                    .quotient
                    .iter()
                    .zip_eq(qc_domains)
                    .map(move |(values, q_domain)| (*q_domain, vec![(zeta, values.clone())]))
            })
            .collect::<Vec<_>>();

        config
            .pcs()
            .verify(
                vec![
                    (vk.commit.clone(), preprocessed_domains_points_and_opens),
                    (main_commit.clone(), main_domains_points_and_opens),
                    (permutation_commit.clone(), perm_domains_points_and_opens),
                    (quotient_commit.clone(), quotient_domains_points_and_opens),
                ],
                opening_proof,
                challenger,
            )
            .map_err(|_| VerificationError::InvalidopeningArgument)?;

        // Verify the constrtaint evaluations.

        for (chip, trace_domain, qc_domains, values) in izip!(
            chips.iter(),
            trace_domains,
            quotient_chunk_domains,
            opened_values.chips.iter(),
        ) {
            Self::verify_constraints(
                chip,
                values.clone(),
                trace_domain,
                qc_domains,
                zeta,
                alpha,
                &permutation_challenges,
                proof.public_values.clone(),
            )
            .map_err(|_| VerificationError::OodEvaluationMismatch(chip.name()))?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_constraints(
        chip: &MachineChip<SC, A>,
        opening: ChipOpenedValues<SC::Challenge>,
        trace_domain: Domain<SC>,
        qc_domains: Vec<Domain<SC>>,
        zeta: SC::Challenge,
        alpha: SC::Challenge,
        permutation_challenges: &[SC::Challenge],
        public_values: Vec<Val<SC>>,
    ) -> Result<(), OodEvaluationMismatch>
    where
        A: for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    {
        let sels = trace_domain.selectors_at_point(zeta);

        let quotient = Self::recompute_quotient(&opening, &qc_domains, zeta);
        let folded_constraints = Self::eval_constraints(
            chip,
            &opening,
            &sels,
            alpha,
            permutation_challenges,
            public_values,
        );

        // Check that the constraints match the quotient, i.e.
        //     folded_constraints(zeta) / Z_H(zeta) = quotient(zeta)
        match folded_constraints * sels.inv_zeroifier == quotient {
            true => Ok(()),
            false => Err(OodEvaluationMismatch),
        }
    }

    pub fn eval_constraints(
        chip: &MachineChip<SC, A>,
        opening: &ChipOpenedValues<SC::Challenge>,
        selectors: &LagrangeSelectors<SC::Challenge>,
        alpha: SC::Challenge,
        permutation_challenges: &[SC::Challenge],
        public_values: Vec<Val<SC>>,
    ) -> SC::Challenge
    where
        A: for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    {
        // Reconstruct the prmutation opening values as extention elements.
        let unflatten = |v: &[SC::Challenge]| {
            v.chunks_exact(SC::Challenge::D)
                .map(|chunk| {
                    chunk
                        .iter()
                        .enumerate()
                        .map(|(e_i, &x)| SC::Challenge::monomial(e_i) * x)
                        .sum()
                })
                .collect::<Vec<SC::Challenge>>()
        };

        let perm_opening = AirOpenedValues {
            local: unflatten(&opening.permutation.local),
            next: unflatten(&opening.permutation.next),
        };

        let public_values = public_values.to_vec();
        let mut folder = VerifierConstraintFolder::<SC> {
            preprocessed: opening.preprocessed.view(),
            main: opening.main.view(),
            perm: perm_opening.view(),
            perm_challenges: permutation_challenges,
            cumulative_sum: opening.cumulative_sum,
            is_first_row: selectors.is_first_row,
            is_last_row: selectors.is_last_row,
            is_transition: selectors.is_transition,
            alpha,
            accumulator: SC::Challenge::zero(),
            public_values: &public_values,
            _marker: PhantomData,
        };

        chip.eval(&mut folder);

        folder.accumulator
    }

    pub fn recompute_quotient(
        opening: &ChipOpenedValues<SC::Challenge>,
        qc_domains: &[Domain<SC>],
        zeta: SC::Challenge,
    ) -> SC::Challenge {
        use p3_field::Field;

        let zps = qc_domains
            .iter()
            .enumerate()
            .map(|(i, domain)| {
                qc_domains
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, other_domain)| {
                        other_domain.zp_at_point(zeta)
                            * other_domain.zp_at_point(domain.first_point()).inverse()
                    })
                    .product::<SC::Challenge>()
            })
            .collect_vec();

        opening
            .quotient
            .iter()
            .enumerate()
            .map(|(ch_i, ch)| {
                assert_eq!(ch.len(), SC::Challenge::D);
                ch.iter()
                    .enumerate()
                    .map(|(e_i, &c)| zps[ch_i] * SC::Challenge::monomial(e_i) * c)
                    .sum::<SC::Challenge>()
            })
            .sum::<SC::Challenge>()
    }
}

pub struct OodEvaluationMismatch;

#[derive(Debug)]
pub enum VerificationError {
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
            VerificationError::InvalidopeningArgument => {
                write!(f, "Invalid opening argument")
            }
            VerificationError::OodEvaluationMismatch(chip) => {
                write!(f, "Out-of-domain evaluation mismatch on chip {}", chip)
            }
        }
    }
}
