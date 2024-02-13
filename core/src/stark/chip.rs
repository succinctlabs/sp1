use p3_air::{Air, BaseAir, PairBuilder};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_util::log2_ceil_usize;

use crate::{
    air::{CurtaAirBuilder, ExecutionAir, MachineAir, MultiTableAirBuilder},
    lookup::{Interaction, InteractionBuilder},
    runtime::{EmptyHost, ExecutionRecord, Host, Program},
};

use super::{
    eval_permutation_constraints, DebugConstraintBuilder, ProverConstraintFolder,
    StarkGenericConfig, VerifierConstraintFolder,
};

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

pub struct ChipRef<'a, SC: StarkGenericConfig> {
    air: &'a dyn StarkAir<SC>,
    sends: &'a [Interaction<SC::Val>],
    receives: &'a [Interaction<SC::Val>],
    log_quotient_degree: usize,
}

impl<F: Field, A> Chip<F, A> {
    pub fn sends(&self) -> &[Interaction<F>] {
        &self.sends
    }

    pub fn receives(&self) -> &[Interaction<F>] {
        &self.receives
    }

    pub const fn log_quotient_degree(&self) -> usize {
        self.log_quotient_degree
    }
}

impl<'a, SC: StarkGenericConfig> ChipRef<'a, SC> {
    pub fn sends(&self) -> &[Interaction<SC::Val>] {
        self.sends
    }

    pub fn receives(&self) -> &[Interaction<SC::Val>] {
        self.receives
    }

    pub const fn log_quotient_degree(&self) -> usize {
        self.log_quotient_degree
    }
}

/// A trait for AIRs that can be used with STARKs.
///
/// This trait is for specifying a trait bound for explicit types of builders used in the stark
/// proving system. It is automatically implemented on any type that implements `Air<AB>` with
/// `AB: CurtaAirBuilder`. Users should not need to implement this trait manually.
pub trait StarkAir<SC: StarkGenericConfig>:
    MachineAir<SC::Val>
    + ExecutionAir<SC::Val, EmptyHost<ExecutionRecord>>
    + ExecutionAir<SC::Val, ExecutionRecord>
    + Air<InteractionBuilder<SC::Val>>
    + for<'a> Air<ProverConstraintFolder<'a, SC>>
    + for<'a> Air<VerifierConstraintFolder<'a, SC>>
    + for<'a> Air<DebugConstraintBuilder<'a, SC::Val, SC::Challenge>>
{
}

impl<SC: StarkGenericConfig, T> StarkAir<SC> for T where
    T: MachineAir<SC::Val>
        + ExecutionAir<SC::Val, EmptyHost<ExecutionRecord>>
        + ExecutionAir<SC::Val, ExecutionRecord>
        + Air<InteractionBuilder<SC::Val>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>
        + for<'a> Air<DebugConstraintBuilder<'a, SC::Val, SC::Challenge>>
{
}

impl<F, A> Chip<F, A>
where
    F: Field,
    A: Air<InteractionBuilder<F>>,
{
    pub fn new(air: A) -> Self {
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

    pub fn as_ref<SC: StarkGenericConfig<Val = F>>(&self) -> ChipRef<SC>
    where
        A: StarkAir<SC>,
    {
        ChipRef {
            air: &self.air,
            sends: &self.sends,
            receives: &self.receives,
            log_quotient_degree: self.log_quotient_degree,
        }
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
}

impl<F, H, A> ExecutionAir<F, H> for Chip<F, A>
where
    F: Field,
    A: ExecutionAir<F, H>,
    H: Host,
{
    fn generate_trace(&self, record: &H::Record, host: &mut H) -> RowMajorMatrix<F> {
        self.air.generate_trace(record, host)
    }

    fn shard(&self, input: &H::Record, outputs: &mut Vec<H::Record>) {
        self.air.shard(input, outputs);
    }

    fn include(&self, record: &ExecutionRecord) -> bool {
        self.air.include(record)
    }
}

// Implement AIR directly on Chip, evaluating both execution and permutation constraints.
impl<F, A, AB> Air<AB> for Chip<F, A>
where
    F: Field,
    A: Air<AB>,
    AB: CurtaAirBuilder<F = F> + MultiTableAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        // Evaluate the execution trace constraints.
        self.air.eval(builder);
        // Evaluate permutation constraints.
        eval_permutation_constraints(&self.sends, &self.receives, builder);
    }
}

// Implement Air on ChipRef similar to Chip.

impl<'a, SC: StarkGenericConfig> BaseAir<SC::Val> for ChipRef<'a, SC> {
    fn width(&self) -> usize {
        <dyn StarkAir<SC> as BaseAir<SC::Val>>::width(self.air)
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<SC::Val>> {
        <dyn StarkAir<SC> as BaseAir<SC::Val>>::preprocessed_trace(self.air)
    }
}

impl<'a, SC: StarkGenericConfig> MachineAir<SC::Val> for ChipRef<'a, SC> {
    fn name(&self) -> String {
        <dyn StarkAir<SC> as MachineAir<SC::Val>>::name(self.air)
    }

    fn generate_preprocessed_trace(&self, program: &Program) -> Option<RowMajorMatrix<SC::Val>> {
        <dyn StarkAir<SC> as MachineAir<SC::Val>>::generate_preprocessed_trace(self.air, program)
    }

    fn preprocessed_width(&self) -> usize {
        <dyn StarkAir<SC> as MachineAir<SC::Val>>::preprocessed_width(self.air)
    }
}

impl<'a, SC: StarkGenericConfig> ExecutionAir<SC::Val, EmptyHost<ExecutionRecord>>
    for ChipRef<'a, SC>
{
    fn generate_trace(
        &self,
        record: &ExecutionRecord,
        host: &mut EmptyHost<ExecutionRecord>,
    ) -> RowMajorMatrix<SC::Val> {
        <dyn StarkAir<SC> as ExecutionAir<SC::Val, EmptyHost<ExecutionRecord>>>::generate_trace(
            self.air, record, host,
        )
    }

    fn shard(&self, input: &ExecutionRecord, outputs: &mut Vec<ExecutionRecord>) {
        <dyn StarkAir<SC> as ExecutionAir<SC::Val, EmptyHost<ExecutionRecord>>>::shard(
            self.air, input, outputs,
        );
    }

    fn include(&self, record: &ExecutionRecord) -> bool {
        <dyn StarkAir<SC> as ExecutionAir<SC::Val, EmptyHost<ExecutionRecord>>>::include(
            self.air, record,
        )
    }
}

impl<'a, SC: StarkGenericConfig> ExecutionAir<SC::Val, ExecutionRecord> for ChipRef<'a, SC> {
    fn generate_trace(
        &self,
        record: &ExecutionRecord,
        host: &mut ExecutionRecord,
    ) -> RowMajorMatrix<SC::Val> {
        <dyn StarkAir<SC> as ExecutionAir<SC::Val, ExecutionRecord>>::generate_trace(
            self.air, record, host,
        )
    }

    fn shard(&self, input: &ExecutionRecord, outputs: &mut Vec<ExecutionRecord>) {
        <dyn StarkAir<SC> as ExecutionAir<SC::Val, EmptyHost<ExecutionRecord>>>::shard(
            self.air, input, outputs,
        );
    }

    fn include(&self, record: &ExecutionRecord) -> bool {
        <dyn StarkAir<SC> as ExecutionAir<SC::Val, EmptyHost<ExecutionRecord>>>::include(
            self.air, record,
        )
    }
}

impl<'a, 'b, SC: StarkGenericConfig> Air<ProverConstraintFolder<'b, SC>> for ChipRef<'a, SC> {
    fn eval(&self, builder: &mut ProverConstraintFolder<'b, SC>) {
        <dyn StarkAir<SC> as Air<ProverConstraintFolder<'b, SC>>>::eval(self.air, builder);
    }
}

impl<'a, 'b, SC: StarkGenericConfig> Air<VerifierConstraintFolder<'b, SC>> for ChipRef<'a, SC> {
    fn eval(&self, builder: &mut VerifierConstraintFolder<'b, SC>) {
        <dyn StarkAir<SC> as Air<VerifierConstraintFolder<'b, SC>>>::eval(self.air, builder);
    }
}

impl<'a, 'b, SC: StarkGenericConfig> Air<DebugConstraintBuilder<'b, SC::Val, SC::Challenge>>
    for ChipRef<'a, SC>
{
    fn eval(&self, builder: &mut DebugConstraintBuilder<'b, SC::Val, SC::Challenge>) {
        <dyn StarkAir<SC> as Air<DebugConstraintBuilder<'b, SC::Val, SC::Challenge>>>::eval(
            self.air, builder,
        );
    }
}
