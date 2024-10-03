use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use itertools::Itertools;
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, PairBuilder};
use p3_field::{AbstractField, PrimeField};
use p3_matrix::{dense::RowMajorMatrix, Matrix};

use sp1_core_executor::{ExecutionRecord, Program};
use sp1_derive::AlignedBorrow;
use sp1_stark::{
    air::{
        AirInteraction, InteractionScope, MachineAir, PublicValues, SP1AirBuilder,
        SP1_PROOF_NUM_PV_ELTS,
    },
    InteractionKind, Word,
};

use crate::{operations::IsZeroOperation, utils::pad_rows_fixed};

pub const NUM_MEMORY_PROGRAM_PREPROCESSED_COLS: usize =
    size_of::<MemoryProgramPreprocessedCols<u8>>();
pub const NUM_MEMORY_PROGRAM_MULT_COLS: usize = size_of::<MemoryProgramMultCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct MemoryProgramPreprocessedCols<T> {
    pub addr: T,
    pub value: Word<T>,
    pub is_real: T,
}

/// Multiplicity columns.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct MemoryProgramMultCols<T> {
    /// The multiplicity of the event.
    ///
    /// This column is technically redundant with `is_real`, but it's included for clarity.
    pub multiplicity: T,

    /// Whether the shard is the first shard.
    pub is_first_shard: IsZeroOperation<T>,
}

/// Chip that initializes memory that is provided from the program. The table is preprocessed and
/// receives each row in the first shard. This prevents any of these addresses from being
/// overwritten through the normal MemoryInit.
#[derive(Default)]
pub struct MemoryProgramChip;

impl MemoryProgramChip {
    pub const fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField> MachineAir<F> for MemoryProgramChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "MemoryProgram".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_MEMORY_PROGRAM_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let program_memory = &program.memory_image;
        // Note that BTreeMap is guaranteed to be sorted by key. This makes the row order
        // deterministic.
        let mut rows = program_memory
            .iter()
            .sorted()
            .map(|(&addr, &word)| {
                let mut row = [F::zero(); NUM_MEMORY_PROGRAM_PREPROCESSED_COLS];
                let cols: &mut MemoryProgramPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.addr = F::from_canonical_u32(addr);
                cols.value = Word::from(word);
                cols.is_real = F::one();
                row
            })
            .collect::<Vec<_>>();

        // Pad the trace to a power of two depending on the proof shape in `input`.
        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_MEMORY_PROGRAM_PREPROCESSED_COLS],
            program.fixed_log2_rows::<F, _>(self),
        );

        // Convert the trace to a row major matrix.
        let trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_PROGRAM_PREPROCESSED_COLS,
        );
        Some(trace)
    }

    fn generate_dependencies(&self, _input: &ExecutionRecord, _output: &mut ExecutionRecord) {
        // Do nothing since this chip has no dependencies.
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let program_memory_addrs = input.program.memory_image.keys().copied().sorted();

        let mult = if input.public_values.shard == 1 { F::one() } else { F::zero() };

        // Generate the trace rows for each event.
        let mut rows = program_memory_addrs
            .into_iter()
            .map(|_| {
                let mut row = [F::zero(); NUM_MEMORY_PROGRAM_MULT_COLS];
                let cols: &mut MemoryProgramMultCols<F> = row.as_mut_slice().borrow_mut();
                cols.multiplicity = mult;
                cols.is_first_shard.populate(input.public_values.shard - 1);
                row
            })
            .collect::<Vec<_>>();

        // Pad the trace to a power of two depending on the proof shape in `input`.
        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_MEMORY_PROGRAM_MULT_COLS],
            input.fixed_log2_rows::<F, _>(self),
        );

        // Convert the trace to a row major matrix.

        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_PROGRAM_MULT_COLS,
        )
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }

    fn commit_scope(&self) -> InteractionScope {
        InteractionScope::Global
    }
}

impl<F> BaseAir<F> for MemoryProgramChip {
    fn width(&self) -> usize {
        NUM_MEMORY_PROGRAM_MULT_COLS
    }
}

impl<AB> Air<AB> for MemoryProgramChip
where
    AB: SP1AirBuilder + PairBuilder + AirBuilderWithPublicValues,
{
    fn eval(&self, builder: &mut AB) {
        let preprocessed = builder.preprocessed();
        let main = builder.main();

        let prep_local = preprocessed.row_slice(0);
        let prep_local: &MemoryProgramPreprocessedCols<AB::Var> = (*prep_local).borrow();

        let mult_local = main.row_slice(0);
        let mult_local: &MemoryProgramMultCols<AB::Var> = (*mult_local).borrow();

        // Get shard from public values and evaluate whether it is the first shard.
        let public_values_slice: [AB::Expr; SP1_PROOF_NUM_PV_ELTS] =
            core::array::from_fn(|i| builder.public_values()[i].into());
        let public_values: &PublicValues<Word<AB::Expr>, AB::Expr> =
            public_values_slice.as_slice().borrow();

        // Constrain `is_first_shard` to be 1 if and only if the shard is the first shard.
        IsZeroOperation::<AB::F>::eval(
            builder,
            public_values.shard.clone() - AB::F::one(),
            mult_local.is_first_shard,
            prep_local.is_real.into(),
        );

        // Multiplicity must be either 0 or 1.
        builder.assert_bool(mult_local.multiplicity);

        // If first shard and preprocessed is real, multiplicity must be one.
        builder
            .when(mult_local.is_first_shard.result)
            .assert_eq(mult_local.multiplicity, prep_local.is_real.into());

        // If it's not the first shard, then the multiplicity must be zero.
        builder.when_not(mult_local.is_first_shard.result).assert_zero(mult_local.multiplicity);

        let mut values = vec![AB::Expr::zero(), AB::Expr::zero(), prep_local.addr.into()];
        values.extend(prep_local.value.map(Into::into));
        builder.send(
            AirInteraction::new(values, mult_local.multiplicity.into(), InteractionKind::Memory),
            InteractionScope::Global,
        );
    }
}
