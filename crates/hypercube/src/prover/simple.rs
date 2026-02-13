//! Simplified prover for test and development use.

use slop_air::BaseAir;
use slop_algebra::PrimeField32;
use slop_challenger::IopCtx;
use std::{collections::BTreeMap, collections::BTreeSet, sync::Arc};

use crate::{
    air::MachineAir,
    prover::{shard::AirProver, CoreProofShape, PcsProof, ProvingKey},
    MachineVerifier, MachineVerifierConfigError, MachineVerifyingKey, ShardContext, ShardProof,
    ShardVerifier,
};

use super::{PreprocessedData, ProverSemaphore};

/// Given a record, compute the shape of the resulting shard proof.
///
/// This is a standalone function that can be used outside of `SimpleProver`.
pub fn shape_from_record<GC: IopCtx, SC: ShardContext<GC>>(
    verifier: &MachineVerifier<GC, SC>,
    record: &<<SC as ShardContext<GC>>::Air as MachineAir<GC::F>>::Record,
) -> Option<CoreProofShape<GC::F, SC::Air>> {
    let log_stacking_height = verifier.log_stacking_height() as usize;
    let max_log_row_count = verifier.max_log_row_count();
    let airs = verifier.machine().chips();
    let shard_chips: BTreeSet<_> =
        airs.iter().filter(|air| air.included(record)).cloned().collect();
    let preprocessed_multiple = shard_chips
        .iter()
        .map(|air| air.preprocessed_width() * air.num_rows(record).unwrap_or_default())
        .sum::<usize>()
        .div_ceil(1 << log_stacking_height);
    let main_multiple = shard_chips
        .iter()
        .map(|air| air.width() * air.num_rows(record).unwrap_or_default())
        .sum::<usize>()
        .div_ceil(1 << log_stacking_height);

    let main_padding_cols = (main_multiple * (1 << log_stacking_height)
        - shard_chips
            .iter()
            .map(|air| air.width() * air.num_rows(record).unwrap_or_default())
            .sum::<usize>())
    .div_ceil(1 << max_log_row_count)
    .max(1);

    let preprocessed_padding_cols = (preprocessed_multiple * (1 << log_stacking_height)
        - shard_chips
            .iter()
            .map(|air| air.preprocessed_width() * air.num_rows(record).unwrap_or_default())
            .sum::<usize>())
    .div_ceil(1 << max_log_row_count)
    .max(1);

    let shard_chips = verifier.machine().smallest_cluster(&shard_chips).cloned()?;
    Some(CoreProofShape {
        shard_chips,
        preprocessed_multiple,
        main_multiple,
        preprocessed_padding_cols,
        main_padding_cols,
    })
}

/// Create a single-permit semaphore for simple prover operations.
fn single_permit() -> ProverSemaphore {
    ProverSemaphore::new(1)
}

/// The type of program this prover can make proofs for.
pub type Program<GC, SC> =
    <<SC as ShardContext<GC>>::Air as MachineAir<<GC as IopCtx>::F>>::Program;

/// The execution record for this prover.
pub type Record<GC, SC> = <<SC as ShardContext<GC>>::Air as MachineAir<<GC as IopCtx>::F>>::Record;

/// A prover that proves traces sequentially using a single `AirProver`.
///
/// Prioritizes simplicity over performance - suitable for tests and development.
pub struct SimpleProver<GC: IopCtx, SC: ShardContext<GC>, C: AirProver<GC, SC>> {
    /// The underlying prover.
    prover: Arc<C>,
    /// The verifier.
    verifier: MachineVerifier<GC, SC>,
}

impl<GC: IopCtx, SC: ShardContext<GC>, C: AirProver<GC, SC>> SimpleProver<GC, SC, C> {
    /// Create a new simple prover.
    #[must_use]
    pub fn new(shard_verifier: ShardVerifier<GC, SC>, prover: C) -> Self {
        Self { prover: Arc::new(prover), verifier: MachineVerifier::new(shard_verifier) }
    }

    /// Verify a machine proof.
    pub fn verify(
        &self,
        vk: &MachineVerifyingKey<GC>,
        proof: &crate::MachineProof<GC, PcsProof<GC, SC>>,
    ) -> Result<(), MachineVerifierConfigError<GC, SC::Config>>
    where
        GC::F: PrimeField32,
    {
        self.verifier.verify(vk, proof)
    }

    /// Get the verifier.
    #[must_use]
    #[inline]
    pub fn verifier(&self) -> &MachineVerifier<GC, SC> {
        &self.verifier
    }

    /// Get a new challenger.
    #[must_use]
    #[inline]
    pub fn challenger(&self) -> GC::Challenger {
        self.verifier.challenger()
    }

    /// Get the machine.
    #[must_use]
    #[inline]
    pub fn machine(&self) -> &crate::Machine<GC::F, SC::Air> {
        self.verifier.machine()
    }

    /// Get the maximum log row count.
    #[must_use]
    pub fn max_log_row_count(&self) -> usize {
        self.verifier.max_log_row_count()
    }

    /// Get the log stacking height.
    #[must_use]
    pub fn log_stacking_height(&self) -> u32 {
        self.verifier.log_stacking_height()
    }

    /// Given a record, compute the shape of the resulting shard proof.
    pub fn shape_from_record(
        &self,
        record: &Record<GC, SC>,
    ) -> Option<CoreProofShape<GC::F, SC::Air>> {
        shape_from_record(&self.verifier, record)
    }

    /// Setup the prover for a given program.
    #[inline]
    #[must_use]
    #[tracing::instrument(skip_all, name = "simple_setup")]
    pub async fn setup(
        &self,
        program: Arc<Program<GC, SC>>,
    ) -> (PreprocessedData<ProvingKey<GC, SC, C>>, MachineVerifyingKey<GC>) {
        self.prover.setup(program, single_permit()).await
    }

    /// Prove a shard with a given proving key.
    #[inline]
    #[must_use]
    #[tracing::instrument(skip_all, name = "simple_prove_shard")]
    pub async fn prove_shard(
        &self,
        pk: Arc<ProvingKey<GC, SC, C>>,
        record: Record<GC, SC>,
    ) -> ShardProof<GC, PcsProof<GC, SC>> {
        let (proof, _) = self.prover.prove_shard_with_pk(pk, record, single_permit()).await;

        proof
    }

    /// Setup and prove a shard in one call.
    #[inline]
    #[must_use]
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(skip_all, name = "simple_setup_and_prove_shard")]
    pub async fn setup_and_prove_shard(
        &self,
        program: Arc<Program<GC, SC>>,
        vk: Option<MachineVerifyingKey<GC>>,
        record: Record<GC, SC>,
    ) -> (MachineVerifyingKey<GC>, ShardProof<GC, PcsProof<GC, SC>>) {
        let (vk, proof, _) =
            self.prover.setup_and_prove_shard(program, record, vk, single_permit()).await;

        (vk, proof)
    }

    /// Get the preprocessed table heights from the proving key.
    pub async fn preprocessed_table_heights(
        &self,
        pk: Arc<ProvingKey<GC, SC, C>>,
    ) -> BTreeMap<String, usize> {
        C::preprocessed_table_heights(pk).await
    }
}
