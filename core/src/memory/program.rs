use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, PairBuilder};
use p3_field::AbstractField;
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use sp1_derive::AlignedBorrow;

use crate::air::{AirInteraction, PublicValues, SP1AirBuilder};
use crate::air::{MachineAir, Word};
use crate::operations::IsZeroOperation;
use crate::runtime::{ExecutionRecord, Program};
use crate::utils::pad_to_power_of_two;

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
    /// The multiplicity of the event, must be 1 in the first shard and 0 otherwise.
    pub multiplicity: T,
    /// Columns to see if current shard is 1.
    pub is_first_shard: IsZeroOperation<T>,
}

/// Chip that initializes memory that is provided from the program. The table is preprocessed and
/// receives each row in the first shard. This prevents any of these addresses from being
/// overwritten through the normal MemoryInit.
#[derive(Default)]
pub struct MemoryProgramChip;

impl MemoryProgramChip {
    pub fn new() -> Self {
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
        let program_memory = program.memory_image.clone();
        // Note that BTreeMap is guaranteed to be sorted by key. This makes the row order
        // deterministic.
        let rows = program_memory
            .into_iter()
            .map(|(addr, word)| {
                let mut row = [F::zero(); NUM_MEMORY_PROGRAM_PREPROCESSED_COLS];
                let cols: &mut MemoryProgramPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.addr = F::from_canonical_u32(addr);
                cols.value = Word::from(word);
                cols.is_real = F::one();

                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_PROGRAM_PREPROCESSED_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_MEMORY_PROGRAM_PREPROCESSED_COLS, F>(&mut trace.values);

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
        let program_memory_addrs = input
            .program
            .memory_image
            .keys()
            .copied()
            .collect::<Vec<_>>();

        let mult = if input.index == 1 {
            F::one()
        } else {
            F::zero()
        };

        // Generate the trace rows for each event.
        let rows = program_memory_addrs
            .into_iter()
            .map(|_| {
                let mut row = [F::zero(); NUM_MEMORY_PROGRAM_MULT_COLS];
                let cols: &mut MemoryProgramMultCols<F> = row.as_mut_slice().borrow_mut();
                cols.multiplicity = mult;
                IsZeroOperation::populate(&mut cols.is_first_shard, input.index - 1);

                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_PROGRAM_MULT_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_MEMORY_PROGRAM_MULT_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
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
        let public_values = PublicValues::<Word<AB::Expr>, AB::Expr>::from_vec(
            builder
                .public_values()
                .iter()
                .map(|elm| (*elm).into())
                .collect::<Vec<_>>(),
        );
        IsZeroOperation::<AB::F>::eval(
            builder,
            public_values.shard - AB::Expr::one(),
            mult_local.is_first_shard,
            prep_local.is_real.into(),
        );
        let is_first_shard = mult_local.is_first_shard.result;

        // Multiplicity must be either 0 or 1.
        builder.assert_bool(mult_local.multiplicity);
        // If first shard and preprocessed is real, multiplicity must be one.
        builder
            .when(is_first_shard * prep_local.is_real)
            .assert_one(mult_local.multiplicity);
        // If not first shard or preprocessed is not real, multiplicity must be zero.
        builder
            .when((AB::Expr::one() - is_first_shard) + (AB::Expr::one() - prep_local.is_real))
            .assert_zero(mult_local.multiplicity);

        let mut values = vec![AB::Expr::zero(), AB::Expr::zero(), prep_local.addr.into()];
        values.extend(prep_local.value.map(Into::into));
        builder.receive(AirInteraction::new(
            values,
            mult_local.multiplicity.into(),
            crate::lookup::InteractionKind::Memory,
        ));
    }
}
