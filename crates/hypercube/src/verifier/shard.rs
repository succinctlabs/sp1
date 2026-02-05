use derive_where::derive_where;
use slop_basefold::FriConfig;
use slop_merkle_tree::MerkleTreeTcs;
#[allow(clippy::disallowed_types)]
use slop_stacked::{StackedBasefoldProof, StackedPcsVerifier};
use slop_whir::{Verifier, WhirProofShape};
use sp1_primitives::{SP1GlobalContext, SP1OuterGlobalContext};
use std::{
    collections::{BTreeMap, BTreeSet},
    iter::once,
    marker::PhantomData,
    ops::Deref,
};

use itertools::Itertools;
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField32, TwoAdicField};
use slop_challenger::{CanObserve, FieldChallenger, IopCtx, VariableLengthChallenger};
use slop_commit::Rounds;
use slop_jagged::{JaggedPcsVerifier, JaggedPcsVerifierError};
use slop_matrix::dense::RowMajorMatrixView;
use slop_multilinear::{full_geq, Evaluations, Mle, MleEval, MultilinearPcsVerifier};
use slop_sumcheck::{partially_verify_sumcheck_proof, SumcheckError};
use thiserror::Error;

use crate::{
    air::MachineAir,
    prover::{CoreProofShape, PcsProof, ZerocheckAir},
    Chip, ChipOpenedValues, LogUpEvaluations, LogUpGkrVerifier, LogupGkrVerificationError, Machine,
    ShardContext, ShardContextImpl, VerifierConstraintFolder, MAX_CONSTRAINT_DEGREE,
    PROOF_MAX_NUM_PVS, SP1SC,
};

use super::{MachineVerifyingKey, ShardOpenedValues, ShardProof};

/// The number of commitments in an SP1 shard proof, corresponding to the preprocessed and main
/// commitments.
pub const NUM_SP1_COMMITMENTS: usize = 2;

/// The number of bits to grind in sampling the GKR randomness.
pub const GKR_GRINDING_BITS: usize = 12;

#[allow(clippy::disallowed_types)]
/// The Multilinear PCS used in SP1 shard proofs, generic in the `IopCtx`.
pub type SP1Pcs<GC> = StackedPcsVerifier<GC>;

/// The PCS used for all stages of SP1 proving except for wrap.
pub type SP1InnerPcs = SP1Pcs<SP1GlobalContext>;

/// The PCS used for wrap proving.
pub type SP1OuterPcs = SP1Pcs<SP1OuterGlobalContext>;

/// The PCS proof type used in SP1 shard proofs.
#[allow(clippy::disallowed_types)]
pub type SP1PcsProof<GC> = StackedBasefoldProof<GC>;

/// The proof type for all stages of SP1 proving except for wrap.
pub type SP1PcsProofInner = SP1PcsProof<SP1GlobalContext>;

/// The proof type for wrap proving.
pub type SP1PcsProofOuter = SP1PcsProof<SP1OuterGlobalContext>;

/// A verifier for shard proofs.
#[derive_where(Clone)]
pub struct ShardVerifier<GC: IopCtx, SC: ShardContext<GC>> {
    /// The jagged pcs verifier.
    pub jagged_pcs_verifier: JaggedPcsVerifier<GC, SC::Config>,
    /// The machine.
    pub machine: Machine<GC::F, SC::Air>,
}

/// An error that occurs during the verification of a shard proof.
#[derive(Debug, Error)]
pub enum ShardVerifierError<EF, PcsError> {
    /// The pcs opening proof is invalid.
    #[error("invalid pcs opening proof: {0}")]
    InvalidopeningArgument(#[from] JaggedPcsVerifierError<EF, PcsError>),
    /// The constraints check failed.
    #[error("constraints check failed: {0}")]
    ConstraintsCheckFailed(SumcheckError),
    /// The cumulative sums error.
    #[error("cumulative sums error: {0}")]
    CumulativeSumsError(&'static str),
    /// The preprocessed chip id mismatch.
    #[error("preprocessed chip id mismatch: {0}")]
    PreprocessedChipIdMismatch(String, String),
    /// The error to report when the preprocessed chip height in the verifying key does not match
    /// the chip opening height.
    #[error("preprocessed chip height mismatch: {0}")]
    PreprocessedChipHeightMismatch(String),
    /// The chip opening length mismatch.
    #[error("chip opening length mismatch")]
    ChipOpeningLengthMismatch,
    /// The cpu chip is missing.
    #[error("missing cpu chip")]
    MissingCpuChip,
    /// The shape of the openings does not match the expected shape.
    #[error("opening shape mismatch: {0}")]
    OpeningShapeMismatch(#[from] OpeningShapeError),
    /// The GKR verification failed.
    #[error("GKR verification failed: {0}")]
    GkrVerificationFailed(LogupGkrVerificationError<EF>),
    /// The public values verification failed.
    #[error("public values verification failed")]
    InvalidPublicValues,
    /// The proof has entries with invalid shape.
    #[error("invalid shape of proof")]
    InvalidShape,
    /// The provided chip opened values has incorrect order.
    #[error("invalid chip opening order: ({0}, {1})")]
    InvalidChipOrder(String, String),
    /// The height of the chip is not sent over correctly as bitwise decomposition.
    #[error("invalid height bit decomposition")]
    InvalidHeightBitDecomposition,
    /// The height is larger than `1 << max_log_row_count`.
    #[error("height is larger than maximum possible value")]
    HeightTooLarge,
}

/// Derive the error type from the jagged config.
pub type ShardVerifierConfigError<GC, C> =
    ShardVerifierError<<GC as IopCtx>::EF, <C as MultilinearPcsVerifier<GC>>::VerifierError>;

/// An error that occurs when the shape of the openings does not match the expected shape.
#[derive(Debug, Error)]
pub enum OpeningShapeError {
    /// The width of the preprocessed trace does not match the expected width.
    #[error("preprocessed width mismatch: {0} != {1}")]
    PreprocessedWidthMismatch(usize, usize),
    /// The width of the main trace does not match the expected width.
    #[error("main width mismatch: {0} != {1}")]
    MainWidthMismatch(usize, usize),
}

impl<GC: IopCtx, SC: ShardContext<GC>> ShardVerifier<GC, SC> {
    /// Get a shard verifier from a jagged pcs verifier.
    pub fn new(
        pcs_verifier: JaggedPcsVerifier<GC, SC::Config>,
        machine: Machine<GC::F, SC::Air>,
    ) -> Self {
        Self { jagged_pcs_verifier: pcs_verifier, machine }
    }

    /// Get the maximum log row count.
    #[must_use]
    #[inline]
    pub fn max_log_row_count(&self) -> usize {
        self.jagged_pcs_verifier.max_log_row_count
    }

    /// Get the machine.
    #[must_use]
    #[inline]
    pub fn machine(&self) -> &Machine<GC::F, SC::Air> {
        &self.machine
    }

    /// Get the log stacking height.
    #[must_use]
    #[inline]
    pub fn log_stacking_height(&self) -> u32 {
        <SC::Config>::log_stacking_height(&self.jagged_pcs_verifier.pcs_verifier)
    }

    /// Get a new challenger.
    #[must_use]
    #[inline]
    pub fn challenger(&self) -> GC::Challenger {
        self.jagged_pcs_verifier.challenger()
    }

    /// Get the shape of a shard proof.
    pub fn shape_from_proof(
        &self,
        proof: &ShardProof<GC, PcsProof<GC, SC>>,
    ) -> CoreProofShape<GC::F, SC::Air> {
        let shard_chips = self
            .machine()
            .chips()
            .iter()
            .filter(|air| proof.opened_values.chips.keys().any(|k| k == air.name()))
            .cloned()
            .collect::<BTreeSet<_>>();
        debug_assert_eq!(shard_chips.len(), proof.opened_values.chips.len());

        let multiples = <SC::Config>::round_multiples(&proof.evaluation_proof.pcs_proof);
        let preprocessed_multiple = multiples[0];
        let main_multiple = multiples[1];

        let added_columns: Vec<usize> = proof
            .evaluation_proof
            .row_counts_and_column_counts
            .iter()
            .map(|cc| cc[cc.len() - 2].1 + 1)
            .collect();

        CoreProofShape {
            shard_chips,
            preprocessed_multiple,
            main_multiple,
            preprocessed_padding_cols: added_columns[0],
            main_padding_cols: added_columns[1],
        }
    }

    /// Compute the padded row adjustment for a chip.
    pub fn compute_padded_row_adjustment(
        chip: &Chip<GC::F, SC::Air>,
        alpha: GC::EF,
        public_values: &[GC::F],
    ) -> GC::EF
where {
        let dummy_preprocessed_trace = vec![GC::EF::zero(); chip.preprocessed_width()];
        let dummy_main_trace = vec![GC::EF::zero(); chip.width()];

        let mut folder = VerifierConstraintFolder::<GC::F, GC::EF> {
            preprocessed: RowMajorMatrixView::new_row(&dummy_preprocessed_trace),
            main: RowMajorMatrixView::new_row(&dummy_main_trace),
            alpha,
            accumulator: GC::EF::zero(),
            public_values,
            _marker: PhantomData,
        };

        chip.eval(&mut folder);

        folder.accumulator
    }

    /// Evaluates the constraints for a chip and opening.
    pub fn eval_constraints(
        chip: &Chip<GC::F, SC::Air>,
        opening: &ChipOpenedValues<GC::F, GC::EF>,
        alpha: GC::EF,
        public_values: &[GC::F],
    ) -> GC::EF
where {
        let mut folder = VerifierConstraintFolder::<GC::F, GC::EF> {
            preprocessed: RowMajorMatrixView::new_row(&opening.preprocessed.local),
            main: RowMajorMatrixView::new_row(&opening.main.local),
            alpha,
            accumulator: GC::EF::zero(),
            public_values,
            _marker: PhantomData,
        };

        chip.eval(&mut folder);

        folder.accumulator
    }

    fn verify_opening_shape(
        chip: &Chip<GC::F, SC::Air>,
        opening: &ChipOpenedValues<GC::F, GC::EF>,
    ) -> Result<(), OpeningShapeError> {
        // Verify that the preprocessed width matches the expected value for the chip.
        if opening.preprocessed.local.len() != chip.preprocessed_width() {
            return Err(OpeningShapeError::PreprocessedWidthMismatch(
                chip.preprocessed_width(),
                opening.preprocessed.local.len(),
            ));
        }

        // Verify that the main width matches the expected value for the chip.
        if opening.main.local.len() != chip.width() {
            return Err(OpeningShapeError::MainWidthMismatch(
                chip.width(),
                opening.main.local.len(),
            ));
        }

        Ok(())
    }
}

impl<GC: IopCtx, SC: ShardContext<GC>> ShardVerifier<GC, SC>
where
    GC::F: PrimeField32,
{
    /// Verify the zerocheck proof.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    pub fn verify_zerocheck(
        &self,
        shard_chips: &BTreeSet<Chip<GC::F, SC::Air>>,
        opened_values: &ShardOpenedValues<GC::F, GC::EF>,
        gkr_evaluations: &LogUpEvaluations<GC::EF>,
        proof: &ShardProof<GC, PcsProof<GC, SC>>,
        public_values: &[GC::F],
        challenger: &mut GC::Challenger,
    ) -> Result<
        (),
        ShardVerifierError<GC::EF, <SC::Config as MultilinearPcsVerifier<GC>>::VerifierError>,
    >
where {
        let max_log_row_count = self.jagged_pcs_verifier.max_log_row_count;

        // Get the random challenge to merge the constraints.
        let alpha = challenger.sample_ext_element::<GC::EF>();

        let gkr_batch_open_challenge = challenger.sample_ext_element::<GC::EF>();

        // Get the random lambda to RLC the zerocheck polynomials.
        let lambda = challenger.sample_ext_element::<GC::EF>();

        if gkr_evaluations.point.dimension() != max_log_row_count
            || proof.zerocheck_proof.point_and_eval.0.dimension() != max_log_row_count
        {
            return Err(ShardVerifierError::InvalidShape);
        }

        // Get the value of eq(zeta, sumcheck's reduced point).
        let zerocheck_eq_val = Mle::full_lagrange_eval(
            &gkr_evaluations.point,
            &proof.zerocheck_proof.point_and_eval.0,
        );

        // To verify the constraints, we need to check that the RLC'ed reduced eval in the zerocheck
        // proof is correct.
        let mut rlc_eval = GC::EF::zero();
        for (chip, (chip_name, openings)) in shard_chips.iter().zip_eq(opened_values.chips.iter()) {
            assert_eq!(chip.name(), chip_name);
            // Verify the shape of the opening arguments matches the expected values.
            Self::verify_opening_shape(chip, openings)?;

            let mut point_extended = proof.zerocheck_proof.point_and_eval.0.clone();
            point_extended.add_dimension(GC::EF::zero());
            for &x in openings.degree.iter() {
                if x * (x - GC::F::one()) != GC::F::zero() {
                    return Err(ShardVerifierError::InvalidHeightBitDecomposition);
                }
            }
            for &x in openings.degree.iter().skip(1) {
                if x * *openings.degree.first().unwrap() != GC::F::zero() {
                    return Err(ShardVerifierError::HeightTooLarge);
                }
            }

            let geq_val = full_geq(&openings.degree, &point_extended);

            let padded_row_adjustment =
                Self::compute_padded_row_adjustment(chip, alpha, public_values);

            let constraint_eval = Self::eval_constraints(chip, openings, alpha, public_values)
                - padded_row_adjustment * geq_val;

            let openings_batch = openings
                .main
                .local
                .iter()
                .chain(openings.preprocessed.local.iter())
                .copied()
                .zip(gkr_batch_open_challenge.powers().skip(1))
                .map(|(opening, power)| opening * power)
                .sum::<GC::EF>();

            // Horner's method.
            rlc_eval = rlc_eval * lambda + zerocheck_eq_val * (constraint_eval + openings_batch);
        }

        if proof.zerocheck_proof.point_and_eval.1 != rlc_eval {
            return Err(ShardVerifierError::<
                _,
                <SC::Config as MultilinearPcsVerifier<GC>>::VerifierError,
            >::ConstraintsCheckFailed(SumcheckError::InconsistencyWithEval));
        }

        let zerocheck_sum_modifications_from_gkr = gkr_evaluations
            .chip_openings
            .values()
            .map(|chip_evaluation| {
                chip_evaluation
                    .main_trace_evaluations
                    .deref()
                    .iter()
                    .copied()
                    .chain(
                        chip_evaluation
                            .preprocessed_trace_evaluations
                            .as_ref()
                            .iter()
                            .flat_map(|&evals| evals.deref().iter().copied()),
                    )
                    .zip(gkr_batch_open_challenge.powers().skip(1))
                    .map(|(opening, power)| opening * power)
                    .sum::<GC::EF>()
            })
            .collect::<Vec<_>>();

        let zerocheck_sum_modification = zerocheck_sum_modifications_from_gkr
            .iter()
            .fold(GC::EF::zero(), |acc, modification| lambda * acc + *modification);

        // Verify that the rlc claim matches the random linear combination of evaluation claims from
        // gkr.
        if proof.zerocheck_proof.claimed_sum != zerocheck_sum_modification {
            return Err(ShardVerifierError::<
                _,
                <SC::Config as MultilinearPcsVerifier<GC>>::VerifierError,
            >::ConstraintsCheckFailed(
                SumcheckError::InconsistencyWithClaimedSum
            ));
        }

        // Verify the zerocheck proof.
        partially_verify_sumcheck_proof(
            &proof.zerocheck_proof,
            challenger,
            max_log_row_count,
            MAX_CONSTRAINT_DEGREE + 1,
        )
        .map_err(|e| {
            ShardVerifierError::<
                _,
                <SC::Config as MultilinearPcsVerifier<GC>>::VerifierError,
            >::ConstraintsCheckFailed(e)
        })?;

        // Observe the openings
        let len = shard_chips.len();
        challenger.observe(GC::F::from_canonical_usize(len));
        for (_, opening) in opened_values.chips.iter() {
            challenger.observe_variable_length_extension_slice(&opening.preprocessed.local);
            challenger.observe_variable_length_extension_slice(&opening.main.local);
        }

        Ok(())
    }

    /// Verify a shard proof.
    #[allow(clippy::too_many_lines)]
    pub fn verify_shard(
        &self,
        vk: &MachineVerifyingKey<GC>,
        proof: &ShardProof<GC, PcsProof<GC, SC>>,
        challenger: &mut GC::Challenger,
    ) -> Result<(), ShardVerifierConfigError<GC, SC::Config>>
where {
        let ShardProof {
            main_commitment,
            opened_values,
            evaluation_proof,
            zerocheck_proof,
            public_values,
            logup_gkr_proof,
        } = proof;

        let max_log_row_count = self.jagged_pcs_verifier.max_log_row_count;

        if public_values.len() != PROOF_MAX_NUM_PVS
            || public_values.len() < self.machine.num_pv_elts()
        {
            tracing::error!("invalid public values length: {}", public_values.len());
            return Err(ShardVerifierError::InvalidPublicValues);
        }

        if public_values[self.machine.num_pv_elts()..].iter().any(|v| *v != GC::F::zero()) {
            return Err(ShardVerifierError::InvalidPublicValues);
        }
        let shard_chips = opened_values.chips.keys().cloned().collect::<BTreeSet<_>>();

        // Observe the public values.
        challenger.observe_constant_length_extension_slice(public_values);
        // Observe the main commitment.
        challenger.observe(*main_commitment);
        // Observe the number of chips.
        let shard_chips_len = shard_chips.len();
        challenger.observe(GC::F::from_canonical_usize(shard_chips_len));

        let mut heights: BTreeMap<String, GC::F> = BTreeMap::new();
        for (name, chip_values) in opened_values.chips.iter() {
            if chip_values.degree.len() != max_log_row_count + 1 || chip_values.degree.len() >= 30 {
                return Err(ShardVerifierError::InvalidShape);
            }
            let acc =
                chip_values.degree.iter().fold(GC::F::zero(), |acc, &x| x + GC::F::two() * acc);
            heights.insert(name.clone(), acc);
            challenger.observe(acc);
            challenger.observe(GC::F::from_canonical_usize(name.len()));
            for byte in name.as_bytes() {
                challenger.observe(GC::F::from_canonical_u8(*byte));
            }
        }

        let machine_chip_names =
            self.machine.chips().iter().map(|c| c.name().to_string()).collect::<BTreeSet<_>>();

        let preprocessed_chips = self
            .machine
            .chips()
            .iter()
            .filter(|chip| chip.preprocessed_width() != 0)
            .collect::<BTreeSet<_>>();

        // Check:
        // 1. All shard chips in the proof are expected from the machine configuration.
        // 2. All chips with non-zero preprocessed width in the machine configuration appear in
        //  the proof.
        // 3. The preprocessed widths as deduced from the jagged proof exactly match those
        // expected from the machine configuration.
        if !shard_chips.is_subset(&machine_chip_names)
            || !preprocessed_chips
                .iter()
                .map(|chip| chip.name().to_string())
                .collect::<BTreeSet<_>>()
                .is_subset(&shard_chips)
            || evaluation_proof.row_counts_and_column_counts[0]
                .iter()
                .map(|&(_, c)| c)
                .take(preprocessed_chips.len())
                .collect::<Vec<_>>()
                != preprocessed_chips
                    .iter()
                    .map(|chip| chip.preprocessed_width())
                    .collect::<Vec<_>>()
        {
            return Err(ShardVerifierError::InvalidShape);
        }

        let shard_chips = self
            .machine
            .chips()
            .iter()
            .filter(|chip| shard_chips.contains(chip.name()))
            .cloned()
            .collect::<BTreeSet<_>>();

        if shard_chips.len() != shard_chips_len || shard_chips_len == 0 {
            return Err(ShardVerifierError::InvalidShape);
        }

        if !self.machine().shape().chip_clusters.contains(&shard_chips) {
            return Err(ShardVerifierError::InvalidShape);
        }

        let degrees = opened_values
            .chips
            .iter()
            .map(|x| (x.0.clone(), x.1.degree.clone()))
            .collect::<BTreeMap<_, _>>();

        if shard_chips.len() != opened_values.chips.len()
            || shard_chips.len() != degrees.len()
            || shard_chips.len() != logup_gkr_proof.logup_evaluations.chip_openings.len()
        {
            return Err(ShardVerifierError::InvalidShape);
        }

        for ((shard_chip, (chip_name, _)), (gkr_chip_name, gkr_opened_values)) in shard_chips
            .iter()
            .zip_eq(opened_values.chips.iter())
            .zip_eq(logup_gkr_proof.logup_evaluations.chip_openings.iter())
        {
            if shard_chip.name() != chip_name.as_str() {
                return Err(ShardVerifierError::InvalidChipOrder(
                    shard_chip.name().to_string(),
                    chip_name.clone(),
                ));
            }
            if shard_chip.name() != gkr_chip_name.as_str() {
                return Err(ShardVerifierError::InvalidChipOrder(
                    shard_chip.name().to_string(),
                    gkr_chip_name.clone(),
                ));
            }

            if gkr_opened_values
                .preprocessed_trace_evaluations
                .as_ref()
                .map_or(0, MleEval::num_polynomials)
                != shard_chip.preprocessed_width()
            {
                return Err(ShardVerifierError::InvalidShape);
            }

            if gkr_opened_values.main_trace_evaluations.len() != shard_chip.width() {
                return Err(ShardVerifierError::InvalidShape);
            }
        }

        // Verify the logup GKR proof.
        LogUpGkrVerifier::<GC, SC>::verify_logup_gkr(
            &shard_chips,
            &degrees,
            max_log_row_count,
            logup_gkr_proof,
            public_values,
            challenger,
        )
        .map_err(ShardVerifierError::GkrVerificationFailed)?;

        // Verify the zerocheck proof.
        self.verify_zerocheck(
            &shard_chips,
            opened_values,
            &logup_gkr_proof.logup_evaluations,
            proof,
            public_values,
            challenger,
        )?;

        // Verify the opening proof.
        // `preprocessed_openings_for_proof` is `Vec` of preprocessed `AirOpenedValues` of chips.
        // `main_openings_for_proof` is `Vec` of main `AirOpenedValues` of chips.
        let (preprocessed_openings_for_proof, main_openings_for_proof): (Vec<_>, Vec<_>) = proof
            .opened_values
            .chips
            .values()
            .map(|opening| (opening.preprocessed.clone(), opening.main.clone()))
            .unzip();

        // `preprocessed_openings` is the `Vec` of preprocessed openings of all chips.
        let preprocessed_openings = preprocessed_openings_for_proof
            .iter()
            .map(|x| x.local.iter().as_slice())
            .collect::<Vec<_>>();

        // `main_openings` is the `Evaluations` derived by collecting all the main openings.
        let main_openings = main_openings_for_proof
            .iter()
            .map(|x| x.local.iter().copied().collect::<MleEval<_>>())
            .collect::<Evaluations<_>>();

        // `filtered_preprocessed_openings` is the `Evaluations` derived by collecting all the
        // non-empty preprocessed openings.
        let filtered_preprocessed_openings = preprocessed_openings
            .into_iter()
            .filter(|x| !x.is_empty())
            .map(|x| x.iter().copied().collect::<MleEval<_>>())
            .collect::<Evaluations<_>>();

        let (commitments, openings) = (
            vec![vk.preprocessed_commit, *main_commitment],
            Rounds { rounds: vec![filtered_preprocessed_openings, main_openings] },
        );

        let flattened_openings = openings
            .into_iter()
            .map(|round| {
                round
                    .into_iter()
                    .flat_map(std::iter::IntoIterator::into_iter)
                    .collect::<MleEval<_>>()
            })
            .collect::<Vec<_>>();

        self.jagged_pcs_verifier
            .verify_trusted_evaluations(
                &commitments,
                zerocheck_proof.point_and_eval.0.clone(),
                flattened_openings.as_slice(),
                evaluation_proof,
                challenger,
            )
            .map_err(ShardVerifierError::InvalidopeningArgument)?;

        let [mut preprocessed_row_counts, mut main_row_counts]: [Vec<usize>; 2] = proof
            .evaluation_proof
            .row_counts_and_column_counts
            .clone()
            .into_iter()
            .map(|r_c| r_c.into_iter().map(|(r, _)| r).collect::<Vec<_>>())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Remove the last two row row counts because we add the padding columns as two extra
        // tables.
        for _ in 0..2 {
            preprocessed_row_counts.pop();
            main_row_counts.pop();
        }

        let mut preprocessed_chip_degrees = vec![];
        let mut main_chip_degrees = vec![];

        for chip in shard_chips.iter() {
            if chip.preprocessed_width() > 0 {
                preprocessed_chip_degrees.push(
                    proof.opened_values.chips[chip.name()]
                        .degree
                        .bit_string_evaluation()
                        .as_canonical_u32(),
                );
            }
            main_chip_degrees.push(
                proof.opened_values.chips[chip.name()]
                    .degree
                    .bit_string_evaluation()
                    .as_canonical_u32(),
            );
        }

        // Check that the row counts in the jagged proof match the chip degrees in the
        // `ChipOpenedValues` struct.
        for (chip_opening_row_counts, proof_row_counts) in
            [preprocessed_chip_degrees, main_chip_degrees]
                .iter()
                .zip_eq([preprocessed_row_counts, main_row_counts].iter())
        {
            if proof_row_counts.len() != chip_opening_row_counts.len() {
                return Err(ShardVerifierError::InvalidShape);
            }
            for (a, b) in proof_row_counts.iter().zip(chip_opening_row_counts.iter()) {
                if *a != *b as usize {
                    return Err(ShardVerifierError::InvalidShape);
                }
            }
        }

        // Check that the shape of the proof struct column counts matches the shape of the shard
        // chips. In the future, we may allow for a layer of abstraction where the proof row
        // counts and column counts can be separate from the machine chips (e.g. if two
        // chips in a row have the same height, the proof could have the column counts
        // merged).
        if !proof
            .evaluation_proof
            .row_counts_and_column_counts
            .iter()
            .cloned()
            .zip(
                once(
                    shard_chips
                        .iter()
                        .map(MachineAir::<GC::F>::preprocessed_width)
                        .filter(|&width| width > 0)
                        .collect::<Vec<_>>(),
                )
                .chain(once(shard_chips.iter().map(Chip::width).collect())),
            )
            // The jagged verifier has already checked that `a.len()>=2`, so this indexing is safe.
            .all(|(a, b)| a[..a.len() - 2].iter().map(|(_, c)| *c).collect::<Vec<_>>() == b)
        {
            Err(ShardVerifierError::InvalidShape)
        } else {
            Ok(())
        }
    }
}

impl<GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>, A> ShardVerifier<GC, SP1SC<GC, A>>
where
    A: ZerocheckAir<GC::F, GC::EF>,
    GC::F: PrimeField32,
{
    /// Create a shard verifier from basefold parameters.
    #[must_use]
    pub fn from_basefold_parameters(
        fri_config: FriConfig<GC::F>,
        log_stacking_height: u32,
        max_log_row_count: usize,
        machine: Machine<GC::F, A>,
    ) -> Self {
        let pcs_verifier = JaggedPcsVerifier::<GC, SP1Pcs<GC>>::new_from_basefold_params(
            fri_config,
            log_stacking_height,
            max_log_row_count,
            NUM_SP1_COMMITMENTS,
        );
        Self { jagged_pcs_verifier: pcs_verifier, machine }
    }
}

impl<GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>, A>
    ShardVerifier<GC, ShardContextImpl<GC, Verifier<GC>, A>>
where
    A: ZerocheckAir<GC::F, GC::EF>,
    GC::F: PrimeField32,
{
    /// Create a shard verifier from basefold parameters.
    #[must_use]
    pub fn from_config(
        config: &WhirProofShape<GC::F>,
        max_log_row_count: usize,
        machine: Machine<GC::F, A>,
        num_expected_commitments: usize,
    ) -> Self {
        let merkle_verifier = MerkleTreeTcs::default();
        let verifier =
            Verifier::<GC>::new(merkle_verifier, config.clone(), num_expected_commitments);

        let jagged_verifier =
            JaggedPcsVerifier::<GC, Verifier<GC>>::new(verifier, max_log_row_count);
        Self { jagged_pcs_verifier: jagged_verifier, machine }
    }
}
