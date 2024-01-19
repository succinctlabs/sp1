use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{ProverConstraintFolder, StarkConfig};

use crate::{
    cpu::{cols::cpu_cols::MemoryAccessCols, MemoryRecord},
    field::event::FieldEvent,
    lookup::{Interaction, InteractionBuilder},
    prover::DebugConstraintBuilder,
    runtime::Segment,
};

pub trait Chip<F: Field>: Air<InteractionBuilder<F>> {
    fn name(&self) -> String {
        "".to_string()
    }

    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F>;

    fn receives(&self) -> Vec<Interaction<F>> {
        let mut builder = InteractionBuilder::new(self.width());
        self.eval(&mut builder);
        let (_, receives) = builder.interactions();
        receives
    }

    fn sends(&self) -> Vec<Interaction<F>> {
        let mut builder = InteractionBuilder::new(self.width());
        self.eval(&mut builder);
        let (sends, _) = builder.interactions();
        sends
    }

    fn all_interactions(&self) -> Vec<Interaction<F>> {
        let mut builder = InteractionBuilder::new(self.width());
        self.eval(&mut builder);
        let (mut sends, receives) = builder.interactions();
        sends.extend(receives);
        sends
    }

    fn populate_access(
        &self,
        cols: &mut MemoryAccessCols<F>,
        current_record: MemoryRecord,
        prev_record: Option<MemoryRecord>,
        new_field_events: &mut Vec<FieldEvent>,
    ) {
        cols.value = current_record.value.into();
        // If `imm_b` or `imm_c` is set, then the record won't exist since we're not accessing from memory.
        if let Some(prev_record) = prev_record {
            cols.prev_value = prev_record.value.into();
            cols.prev_segment = F::from_canonical_u32(prev_record.segment);
            cols.prev_clk = F::from_canonical_u32(prev_record.timestamp);

            // Fill columns used for verifying current memory access time value is greater than previous's.
            let use_clk_comparison = prev_record.segment == current_record.segment;
            cols.use_clk_comparison = F::from_bool(use_clk_comparison);
            let prev_time_value = if use_clk_comparison {
                prev_record.timestamp
            } else {
                prev_record.segment
            };
            cols.prev_time_value = F::from_canonical_u32(prev_time_value);
            let current_time_value = if use_clk_comparison {
                current_record.timestamp
            } else {
                current_record.segment
            };
            cols.current_time_value = F::from_canonical_u32(current_time_value);

            // Add a field op event for the prev_time_value < current_time_value constraint.
            let field_event = FieldEvent::new(true, prev_time_value, current_time_value);
            new_field_events.push(field_event);
        }
    }
}

pub trait AirChip<SC: StarkConfig>:
    Chip<SC::Val>
    + for<'a> Air<ProverConstraintFolder<'a, SC>>
    + for<'a> Air<DebugConstraintBuilder<'a, SC::Val, SC::Challenge>>
{
    fn air_width(&self) -> usize {
        <Self as BaseAir<SC::Val>>::width(self)
    }
}

impl<SC: StarkConfig, T> AirChip<SC> for T where
    T: Chip<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<DebugConstraintBuilder<'a, SC::Val, SC::Challenge>>
{
}

pub const fn indices_arr<const N: usize>() -> [usize; N] {
    let mut indices_arr = [0; N];
    let mut i = 0;
    while i < N {
        indices_arr[i] = i;
        i += 1;
    }
    indices_arr
}

pub fn pad_to_power_of_two<const N: usize, T: Clone + Default>(values: &mut Vec<T>) {
    debug_assert!(values.len() % N == 0);
    let mut n_real_rows = values.len() / N;
    if n_real_rows == 0 {
        n_real_rows = 8;
    } else if n_real_rows == 1 {
        n_real_rows = 8;
    }
    values.resize(n_real_rows.next_power_of_two() * N, T::default());
}
