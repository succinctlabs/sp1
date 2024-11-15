use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, PairBuilder};
use p3_field::AbstractField;
use p3_matrix::{dense::RowMajorMatrix, Matrix};

use crate::{operations::GlobalAccumulationOperation, operations::GlobalInteractionOperation};
use hashbrown::HashMap;
use p3_field::PrimeField32;
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator};
use sp1_core_executor::events::ByteLookupEvent;
use sp1_core_executor::events::ByteRecord;
use sp1_core_executor::{ExecutionRecord, Program};
use sp1_derive::AlignedBorrow;
use sp1_stark::{
    air::{InteractionScope, MachineAir, PublicValues, SP1AirBuilder, SP1_PROOF_NUM_PV_ELTS},
    septic_digest::SepticDigest,
    Word,
};

use crate::{
    operations::IsZeroOperation,
    utils::{next_power_of_two, pad_rows_fixed, zeroed_f_vec},
};

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

    /// The columns for the global interaction.
    pub global_interaction_cols: GlobalInteractionOperation<T>,

    /// The columns for accumulating the elliptic curve digests.
    pub global_accumulation_cols: GlobalAccumulationOperation<T, 1>,
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

impl<F: PrimeField32> MachineAir<F> for MemoryProgramChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "MemoryProgram".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_MEMORY_PROGRAM_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        // Generate the trace rows for each event.
        let nb_rows = program.memory_image.len();
        let size_log2 = program.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_MEMORY_PROGRAM_PREPROCESSED_COLS);
        let chunk_size = std::cmp::max((nb_rows + 1) / num_cpus::get(), 1);

        let memory = program.memory_image.iter().collect::<Vec<_>>();
        values
            .chunks_mut(chunk_size * NUM_MEMORY_PROGRAM_PREPROCESSED_COLS)
            .enumerate()
            .par_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_MEMORY_PROGRAM_PREPROCESSED_COLS).enumerate().for_each(
                    |(j, row)| {
                        let idx = i * chunk_size + j;

                        if idx < nb_rows {
                            let (addr, word) = memory[idx];
                            let cols: &mut MemoryProgramPreprocessedCols<F> = row.borrow_mut();
                            cols.addr = F::from_canonical_u32(*addr);
                            cols.value = Word::from(*word);
                            cols.is_real = F::one();
                        }
                    },
                );
            });

        // Convert the trace to a row major matrix.
        Some(RowMajorMatrix::new(values, NUM_MEMORY_PROGRAM_PREPROCESSED_COLS))
    }

    fn generate_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        let program_memory = &input.program.memory_image;

        let mult_bool = input.public_values.shard == 1;

        let mut blu: HashMap<u32, HashMap<ByteLookupEvent, usize>> = HashMap::new();

        program_memory.iter().for_each(|(&addr, &word)| {
            let mut row = [F::zero(); NUM_MEMORY_PROGRAM_MULT_COLS];
            let cols: &mut MemoryProgramMultCols<F> = row.as_mut_slice().borrow_mut();
            cols.global_interaction_cols
                .populate_memory(0, 0, addr, word, false, mult_bool, &mut blu);
        });

        output.add_sharded_byte_lookup_events(vec![&blu]);
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let program_memory = &input.program.memory_image;

        let mult_bool = input.public_values.shard == 1;
        let mult = F::from_bool(mult_bool);

        let mut global_cumulative_sum = SepticDigest::<F>::zero().0;
        // Generate the trace rows for each event.
        let mut rows = program_memory
            .iter()
            .map(|(&addr, &word)| {
                let mut row = [F::zero(); NUM_MEMORY_PROGRAM_MULT_COLS];
                let cols: &mut MemoryProgramMultCols<F> = row.as_mut_slice().borrow_mut();
                let mut blu = Vec::new();
                cols.multiplicity = mult;
                cols.is_first_shard.populate(input.public_values.shard - 1);
                cols.global_interaction_cols
                    .populate_memory(0, 0, addr, word, false, mult_bool, &mut blu);
                cols.global_accumulation_cols.populate(
                    &mut global_cumulative_sum,
                    [cols.global_interaction_cols],
                    [cols.multiplicity],
                );
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
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_PROGRAM_MULT_COLS,
        );

        let len = input.program.memory_image.len();
        for i in len..trace.height() {
            let cols: &mut MemoryProgramMultCols<F> = trace.values
                [i * NUM_MEMORY_PROGRAM_MULT_COLS..(i + 1) * NUM_MEMORY_PROGRAM_MULT_COLS]
                .borrow_mut();
            cols.global_interaction_cols.populate_dummy();
            cols.global_accumulation_cols.populate(
                &mut global_cumulative_sum,
                [cols.global_interaction_cols],
                [cols.multiplicity],
            );
        }

        trace
    }

    fn included(&self, _: &Self::Record) -> bool {
        false
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

        let mult_next = main.row_slice(1);
        let mult_next: &MemoryProgramMultCols<AB::Var> = (*mult_next).borrow();

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
        GlobalInteractionOperation::<AB::F>::eval_single_digest_memory(
            builder,
            AB::Expr::zero(),
            AB::Expr::zero(),
            prep_local.addr.into(),
            prep_local.value.map(Into::into).0,
            mult_local.global_interaction_cols,
            false,
            mult_local.multiplicity,
        );

        GlobalAccumulationOperation::<AB::F, 1>::eval_accumulation(
            builder,
            [mult_local.global_interaction_cols],
            [mult_local.multiplicity],
            [mult_next.multiplicity],
            mult_local.global_accumulation_cols,
            mult_next.global_accumulation_cols,
        );
    }
}
