use std::hash::Hash;

use p3_air::{Air, BaseAir, PairBuilder};
use p3_field::{extension::BinomiallyExtendable, ExtensionField, Field, PrimeField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_util::log2_ceil_usize;

use crate::{
    air::{MachineAir, MultiTableAirBuilder, SP1AirBuilder},
    lookup::{Interaction, InteractionBuilder},
    runtime::{ExecutionRecord, Program},
};

use super::{
    eval_permutation_constraints, generate_permutation_trace, DebugConstraintBuilder,
    ProverConstraintFolder, RiscvAir, StarkGenericConfig, VerifierConstraintFolder,
};

/// An Air that encodes lookups based on interactions.
pub struct Chip<F: Field, A> {
    /// The underlying AIR of the chip for constraint evaluation.
    air: A,
    /// The interactions that the chip sends.
    sends: Vec<Interaction<F>>,
    /// The interactions that the chip receives.
    receives: Vec<Interaction<F>>,
    /// The relative log degree of the quotient polynomial, i.e. `log2(max_constraint_degree - 1)`.
    log_quotient_degree: usize,
}

impl<F: Field, A> Chip<F, A> {
    /// The send interactions of the chip.
    pub fn sends(&self) -> &[Interaction<F>] {
        &self.sends
    }

    /// The receive interactions of the chip.
    pub fn receives(&self) -> &[Interaction<F>] {
        &self.receives
    }

    /// The relative log degree of the quotient polynomial, i.e. `log2(max_constraint_degree - 1)`.
    pub const fn log_quotient_degree(&self) -> usize {
        self.log_quotient_degree
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<4>> Chip<F, RiscvAir<F>> {
    /// Returns whether the given chip is included in the execution record of the shard.
    pub fn included(&self, shard: &ExecutionRecord) -> bool {
        self.air.included(shard)
    }
}

/// A trait for AIRs that can be used with STARKs.
///
/// This trait is for specifying a trait bound for explicit types of builders used in the stark
/// proving system. It is automatically implemented on any type that implements `Air<AB>` with
/// `AB: SP1AirBuilder`. Users should not need to implement this trait manually.
pub trait StarkAir<SC: StarkGenericConfig>:
    MachineAir<SC::Val>
    + Air<InteractionBuilder<SC::Val>>
    + for<'a> Air<ProverConstraintFolder<'a, SC>>
    + for<'a> Air<VerifierConstraintFolder<'a, SC>>
    + for<'a> Air<DebugConstraintBuilder<'a, SC::Val, SC::Challenge>>
{
}

impl<SC: StarkGenericConfig, T> StarkAir<SC> for T where
    T: MachineAir<SC::Val>
        + Air<InteractionBuilder<SC::Val>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>
        + for<'a> Air<DebugConstraintBuilder<'a, SC::Val, SC::Challenge>>
{
}

impl<F, A> Chip<F, A>
where
    F: Field,
{
    /// Records the interactions and constraint degree from the air and crates a new chip.
    pub fn new(air: A) -> Self
    where
        A: Air<InteractionBuilder<F>>,
    {
        let mut builder = InteractionBuilder::new(air.width());
        air.eval(&mut builder);
        let (sends, receives) = builder.interactions();

        // TODO: count constraints from the air.
        let max_constraint_degree = 3;
        let log_quotient_degree = log2_ceil_usize(max_constraint_degree - 1);

        Self {
            air,
            sends,
            receives,
            log_quotient_degree,
        }
    }

    pub fn num_interactions(&self) -> usize {
        self.sends.len() + self.receives.len()
    }

    pub fn generate_permutation_trace<EF: ExtensionField<F>>(
        &self,
        preprocessed: &Option<RowMajorMatrix<F>>,
        main: &RowMajorMatrix<F>,
        random_elements: &[EF],
    ) -> RowMajorMatrix<EF>
    where
        F: PrimeField,
    {
        generate_permutation_trace(
            &self.sends,
            &self.receives,
            preprocessed,
            main,
            random_elements,
        )
    }
}

impl<F, A> BaseAir<F> for Chip<F, A>
where
    F: Field,
    A: BaseAir<F>,
{
    fn width(&self) -> usize {
        self.air.width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        self.air.preprocessed_trace()
    }
}

impl<F, A> MachineAir<F> for Chip<F, A>
where
    F: Field,
    A: MachineAir<F>,
{
    fn name(&self) -> String {
        self.air.name()
    }
    fn generate_preprocessed_trace(&self, program: &Program) -> Option<RowMajorMatrix<F>> {
        <A as MachineAir<F>>::generate_preprocessed_trace(&self.air, program)
    }

    fn preprocessed_width(&self) -> usize {
        self.air.preprocessed_width()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        self.air.generate_trace(input, output)
    }
}

// Implement AIR directly on Chip, evaluating both execution and permutation constraints.
impl<F, A, AB> Air<AB> for Chip<F, A>
where
    F: Field,
    A: Air<AB>,
    AB: SP1AirBuilder<F = F> + MultiTableAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        // Evaluate the execution trace constraints.
        self.air.eval(builder);
        // Evaluate permutation constraints.
        eval_permutation_constraints(&self.sends, &self.receives, builder);
    }
}

impl<F, A> PartialEq for Chip<F, A>
where
    F: Field,
    A: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.air == other.air
    }
}

impl<F: Field, A: Eq> Eq for Chip<F, A> where F: Field + Eq {}

impl<F, A> Hash for Chip<F, A>
where
    F: Field,
    A: Hash,
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.air.hash(state);
    }
}
