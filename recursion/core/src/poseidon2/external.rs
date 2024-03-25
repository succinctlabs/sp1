use crate::air::Block;
use crate::memory::{MemoryReadWriteCols, MemoryRecord};
use core::borrow::Borrow;
use core::mem::size_of;
use p3_air::AirBuilder;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use sp1_core::air::{MachineAir, SP1AirBuilder};
use sp1_core::utils::pad_to_power_of_two;
use sp1_core::utils::poseidon2_instance::RC_16_30_U32;
use sp1_derive::AlignedBorrow;
use std::borrow::BorrowMut;
use tracing::instrument;

use crate::runtime::{ExecutionRecord, POSEIDON2_WIDTH};

use super::{
    apply_m_4, matmul_internal, MATRIX_DIAG_16_BABYBEAR_U32, P_END, ROUNDS, ROUNDS_F_BEGINNING,
};

/// The number of main trace columns for `AddChip`.
pub const NUM_POSEIDON2_COLS: usize = size_of::<Poseidon2Cols<u8>>();

/// The numebr of rounds in the trace generation for the Poseidon2 permutation. The first round is
/// kept for memory reading and the last round is kept for memory writing. The permutation starts
/// from the second round.
const NUM_TOTAL_ROUNDS: usize = 32;

#[derive(Default, Debug, Clone)]
pub struct Poseidon2Event<T> {
    pub state_ptr: T,
    pub clk: T,
    pub initial_state: [T; POSEIDON2_WIDTH],
    pub initial_state_records: Vec<MemoryRecord<T>>,
    pub final_state: [T; POSEIDON2_WIDTH],
    pub final_state_records: Vec<MemoryRecord<T>>,
}

/// A chip that implements addition for the opcode ADD.
#[derive(Default)]
pub struct Poseidon2Chip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2Cols<T> {
    pub state_ptr: T,
    pub clk: T,
    pub first_round: T,
    pub state: [MemoryReadWriteCols<T>; POSEIDON2_WIDTH],
    pub rounds: [T; NUM_TOTAL_ROUNDS - 1],
    pub add_rc: [T; POSEIDON2_WIDTH],
    pub sbox_deg_3: [T; POSEIDON2_WIDTH],
    pub sbox_deg_7: [T; POSEIDON2_WIDTH],
    pub is_initial: T,
    pub is_internal: T,
    pub is_external: T,
    // only the first and the last round of the poseidon2 permutation needs memory check.
    pub do_memory_check: T,
    pub is_real: T,
}

impl<F: PrimeField32> MachineAir<F> for Poseidon2Chip {
    type Record = ExecutionRecord<F>;

    fn name(&self) -> String {
        "Poseidon2".to_string()
    }

    #[instrument(name = "generate poseidon2 trace", level = "debug", skip_all)]
    #[allow(clippy::needless_range_loop)]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _output: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();
        // let mut record = ExecutionRecord::default();

        for i in 0..input.poseidon2_events.len() {
            let event = input.poseidon2_events[i].clone();

            // init state for the first round.
            // this will also be used to store the pre-state for the next round.
            let mut pre_state = event.initial_state;

            let memory = event.initial_state_records.clone();

            for i in 0..NUM_TOTAL_ROUNDS {
                let mut row = [F::zero(); NUM_POSEIDON2_COLS];
                let cols: &mut Poseidon2Cols<F> = row.as_mut_slice().borrow_mut();

                // increment the clock.
                cols.clk = event.clk + F::from_canonical_usize(i);

                cols.state_ptr = event.state_ptr;

                // If this is the first round, we need to initialize the memory records.
                if i == 0 {
                    for j in 0..POSEIDON2_WIDTH {
                        cols.state[j].populate(&event.initial_state_records[j]);
                    }

                    cols.do_memory_check = F::one();
                    cols.first_round = F::one();

                    // this row is only for memory readfing.
                    continue;
                } else {
                    for j in 0..POSEIDON2_WIDTH {
                        cols.state[j].populate(&MemoryRecord {
                            addr: cols.state[j].addr,
                            value: memory[j].value,
                            timestamp: cols.clk,

                            prev_value: Block::from([F::zero(), F::zero(), F::zero(), F::zero()]),
                            prev_timestamp: F::zero(),
                        });
                    }
                }

                let r = i - 1;

                cols.rounds[r] = F::one();
                let is_initial_layer = r == 0;
                let is_external_layer = r != 0
                    && (((r - 1) < ROUNDS_F_BEGINNING) || (P_END <= (r - 1) && (r - 1) < ROUNDS));

                if is_initial_layer {
                    // Mark the selector as initial.
                    cols.is_initial = F::one();

                    // initialize the pre_state from the memory records.
                    // Don't apply the round constants and copy the `pre_state` as it is.
                    cols.add_rc.copy_from_slice(&pre_state);
                } else if is_external_layer {
                    // Mark the selector as external.
                    cols.is_external = F::one();

                    // Apply the round constants.
                    for j in 0..POSEIDON2_WIDTH {
                        cols.add_rc[j] = pre_state[j] + F::from_wrapped_u32(RC_16_30_U32[r - 1][j]);
                    }
                } else {
                    // Mark the selector as internal.
                    cols.is_internal = F::one();

                    // Apply the round constants only on the first element.
                    cols.add_rc.copy_from_slice(&pre_state);
                    cols.add_rc[0] = pre_state[0] + F::from_wrapped_u32(RC_16_30_U32[r - 1][0]);
                };

                // Apply the sbox.
                for j in 0..POSEIDON2_WIDTH {
                    cols.sbox_deg_3[j] = cols.add_rc[j] * cols.add_rc[j] * cols.add_rc[j];
                    cols.sbox_deg_7[j] = cols.sbox_deg_3[j] * cols.sbox_deg_3[j] * cols.add_rc[j];
                }

                // What state to use for the linear layer.
                let mut state = if is_initial_layer {
                    cols.add_rc
                } else if is_external_layer {
                    cols.sbox_deg_7
                } else {
                    let mut state = cols.add_rc;
                    state[0] = cols.sbox_deg_7[0];
                    state
                };

                // Apply either the external or internal linear layer.
                if cols.is_initial == F::one() || cols.is_external == F::one() {
                    for j in (0..POSEIDON2_WIDTH).step_by(4) {
                        apply_m_4(&mut state[j..j + 4]);
                    }
                    let sums: [F; 4] = core::array::from_fn(|k| {
                        (0..POSEIDON2_WIDTH)
                            .step_by(4)
                            .map(|j| state[j + k])
                            .sum::<F>()
                    });
                    for j in 0..POSEIDON2_WIDTH {
                        state[j] += sums[j % 4];
                    }
                } else if cols.is_internal == F::one() {
                    let matmul_constants: [F; POSEIDON2_WIDTH] = MATRIX_DIAG_16_BABYBEAR_U32
                        .iter()
                        .map(|x| F::from_wrapped_u32(*x))
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap();
                    matmul_internal(&mut state, matmul_constants);
                }

                // If this is the last round, we need to populate the memory records.
                if i == NUM_TOTAL_ROUNDS - 1 {
                    for j in 0..POSEIDON2_WIDTH {
                        cols.state[j].populate(&event.final_state_records[j]);
                    }

                    cols.do_memory_check = F::one();
                } else {
                    // Copy the state to the memory records.
                    for j in 0..POSEIDON2_WIDTH {
                        cols.state[j].populate(&MemoryRecord {
                            addr: cols.state[j].addr,
                            value: Block::from([state[j], F::zero(), F::zero(), F::zero()]),
                            timestamp: cols.clk,
                            prev_value: Block::from([
                                pre_state[j],
                                F::zero(),
                                F::zero(),
                                F::zero(),
                            ]),
                            prev_timestamp: cols.clk,
                        });
                    }
                }

                // update the pre_state for the next round.
                pre_state = state;

                cols.is_real = F::one();

                rows.push(row);
            }
        }

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_POSEIDON2_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_POSEIDON2_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }
}

impl<F> BaseAir<F> for Poseidon2Chip {
    fn width(&self) -> usize {
        NUM_POSEIDON2_COLS
    }
}

impl<AB> Air<AB> for Poseidon2Chip
where
    AB: SP1AirBuilder,
{
    #[allow(clippy::needless_range_loop)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &Poseidon2Cols<AB::Var> = main.row_slice(0).borrow();
        let next: &Poseidon2Cols<AB::Var> = main.row_slice(1).borrow();

        // Convert the u32 round constants to field elements.
        let constants: [[AB::F; POSEIDON2_WIDTH]; 30] = RC_16_30_U32
            .iter()
            .map(|round| round.map(AB::F::from_wrapped_u32))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let local_record = local.state;
        let next_record = next.state;

        // Memory read for the first round.
        for i in 0..POSEIDON2_WIDTH {
            builder
                .when_first_row()
                .assert_eq(local_record[i].value.0[0], next_record[i].prev_value.0[0]);
        }

        let pre_state = local_record
            .iter()
            .map(|block| block.prev_value.0[0])
            .collect::<Vec<_>>();

        let post_state = local_record
            .iter()
            .map(|block| block.value.0[0])
            .collect::<Vec<_>>();

        // Apply the round constants.

        // Initial Layer: Don't apply the round constants.
        // External Layers: Apply the round constants.
        // Internal Layers: Only apply the round constants to the first element.
        for i in 0..POSEIDON2_WIDTH {
            let mut result: AB::Expr = pre_state[i].into();
            for r in 0..ROUNDS {
                if i == 0 {
                    result += local.rounds[r + 1]
                        * constants[r][i]
                        * (local.is_external + local.is_internal);
                } else {
                    result += local.rounds[r + 1] * constants[r][i] * local.is_external;
                }
            }
            builder
                .when_not(local.rounds[30])
                .assert_eq(result, local.add_rc[i]);
        }

        // For the last round, apply the round constants. The prev state for the next round will not be
        // the same as the post state of the current round.
        for i in 0..POSEIDON2_WIDTH {
            let mut result: AB::Expr = post_state[i].into();
            for r in 0..ROUNDS {
                result += next.rounds[r + 1] * constants[29][i];
            }
            builder
                .when(local.rounds[29])
                .assert_eq(result, next.add_rc[i]);
        }

        // Apply the sbox.
        //
        // To differentiate between external and internal layers, we use a masking operation
        // to only apply the state change to the first element for internal layers.
        for i in 0..POSEIDON2_WIDTH {
            let sbox_deg_3 = local.add_rc[i] * local.add_rc[i] * local.add_rc[i];
            builder.assert_eq(sbox_deg_3, local.sbox_deg_3[i]);
            let sbox_deg_7 = local.sbox_deg_3[i] * local.sbox_deg_3[i] * local.add_rc[i];
            builder.assert_eq(sbox_deg_7, local.sbox_deg_7[i]);
        }
        let sbox_result: [AB::Expr; POSEIDON2_WIDTH] = local
            .sbox_deg_7
            .iter()
            .enumerate()
            .map(|(i, x)| {
                // The masked first result of the sbox.
                //
                // Initial Layer: Pass through the result of the round constant layer.
                // External Layer: Pass through the result of the sbox layer.
                // Internal Layer: Pass through the result of the sbox layer.
                if i == 0 {
                    local.is_initial * local.add_rc[i] + (AB::Expr::one() - local.is_initial) * *x
                }
                // The masked result of the rest of the sbox.
                //
                // Initial layer: Pass through the result of the round constant layer.
                // External layer: Pass through the result of the sbox layer.
                // Internal layer: Pass through the result of the round constant layer.
                else {
                    (local.is_initial + local.is_internal) * local.add_rc[i]
                        + (AB::Expr::one() - (local.is_initial + local.is_internal)) * *x
                }
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // EXTERNAL LAYER + INITIAL LAYER
        {
            // First, we apply M_4 to each consecutive four elements of the state.
            // In Appendix B's terminology, this replaces each x_i with x_i'.
            let mut state: [AB::Expr; POSEIDON2_WIDTH] = sbox_result.clone();
            for i in (0..POSEIDON2_WIDTH).step_by(4) {
                apply_m_4(&mut state[i..i + 4]);
            }

            // Now, we apply the outer circulant matrix (to compute the y_i values).
            //
            // We first precompute the four sums of every four elements.
            let sums: [AB::Expr; 4] = core::array::from_fn(|k| {
                (0..POSEIDON2_WIDTH)
                    .step_by(4)
                    .map(|j| state[j + k].clone())
                    .sum::<AB::Expr>()
            });

            // The formula for each y_i involves 2x_i' term and x_j' terms for each j that equals i mod 4.
            // In other words, we can add a single copy of x_i' to the appropriate one of our precomputed sums.
            for i in 0..POSEIDON2_WIDTH {
                state[i] += sums[i % 4].clone();
                builder
                    .when(local.is_external + local.is_initial)
                    .assert_eq(state[i].clone(), post_state[i]);
            }
        }

        // INTERNAL LAYER
        {
            // Use a simple matrix multiplication as the permutation.
            let mut state: [AB::Expr; POSEIDON2_WIDTH] = sbox_result.clone();
            let matmul_constants: [<<AB as AirBuilder>::Expr as AbstractField>::F;
                POSEIDON2_WIDTH] = MATRIX_DIAG_16_BABYBEAR_U32
                .iter()
                .map(|x| <<AB as AirBuilder>::Expr as AbstractField>::F::from_wrapped_u32(*x))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            matmul_internal(&mut state, matmul_constants);
            for i in 0..POSEIDON2_WIDTH {
                builder
                    .when(local.is_internal)
                    .assert_eq(state[i].clone(), post_state[i]);
            }
        }

        // Range check all flags.
        for i in 0..local.rounds.len() {
            builder.assert_bool(local.rounds[i]);
        }
        builder.assert_bool(local.is_initial);
        builder.assert_bool(local.is_external);
        builder.assert_bool(local.is_internal);
        builder.assert_bool(local.do_memory_check);
        builder.assert_bool(local.is_real);

        // only one of them can be true. thus the sum of them should be equal to 1.
        builder.when(local.is_real).assert_eq(
            local.is_initial + local.is_external + local.is_internal,
            AB::Expr::one(),
        );

        // Constrain the initial flag.
        builder.assert_eq(local.is_initial, local.rounds[0]);

        // Constrain the external flag.
        let is_external_first_half = (0..4).map(|i| local.rounds[i + 1].into()).sum::<AB::Expr>();
        let is_external_second_half = (26..30)
            .map(|i| local.rounds[i + 1].into())
            .sum::<AB::Expr>();
        builder.assert_eq(
            local.is_external,
            is_external_first_half + is_external_second_half,
        );

        // Constrain the internal flag.
        let is_internal = (4..26)
            .map(|i| local.rounds[i + 1].into())
            .sum::<AB::Expr>();
        builder.assert_eq(local.is_internal, is_internal);

        // If the memory check flag is set, we need to check if the respective round flag
        // either the first or the last round is set.
        builder.assert_eq(local.first_round + local.rounds[30], local.do_memory_check);

        // // Constrain the memory on first and last round.
        // builder.constraint_memory_access_slice(
        //     AB::F::zero(),
        //     local.clk.into(),
        //     local.state_ptr,
        //     &local.state,
        //     local.do_memory_check,
        // );
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::BorrowMut;

    use p3_baby_bear::BabyBear;
    use p3_baby_bear::DiffusionMatrixBabybear;
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_poseidon2::Poseidon2;
    use sp1_core::stark::StarkGenericConfig;
    use sp1_core::{
        air::MachineAir,
        utils::{poseidon2_instance::RC_16_30, uni_stark_prove, BabyBearPoseidon2},
    };

    use crate::air::Block;
    use crate::memory::MemoryRecord;
    use crate::poseidon2::Poseidon2Event;
    use crate::runtime::POSEIDON2_WIDTH;
    use crate::{poseidon2::external::Poseidon2Chip, runtime::ExecutionRecord};
    use p3_symmetric::Permutation;

    use super::{Poseidon2Cols, NUM_POSEIDON2_COLS};

    #[allow(clippy::needless_range_loop)]
    fn generate_poseidon2_event() -> Vec<Poseidon2Event<BabyBear>> {
        let state_ptr = BabyBear::from_canonical_u32(100);
        let clk = BabyBear::from_canonical_u32(100);
        let mut initial_state_records = Vec::new();
        let mut initial_state = [BabyBear::one(); POSEIDON2_WIDTH];

        for i in 0..POSEIDON2_WIDTH {
            initial_state[i] = BabyBear::from_canonical_u32(i as u32);
            initial_state_records.push(MemoryRecord {
                addr: state_ptr + BabyBear::from_canonical_usize(i),
                value: Block::from([
                    initial_state[i],
                    BabyBear::zero(),
                    BabyBear::zero(),
                    BabyBear::zero(),
                ]),
                timestamp: clk,
                prev_value: Block::from([
                    BabyBear::zero(),
                    BabyBear::zero(),
                    BabyBear::zero(),
                    BabyBear::zero(),
                ]),
                prev_timestamp: clk,
            });
        }

        let gt: Poseidon2<BabyBear, DiffusionMatrixBabybear, 16, 7> =
            Poseidon2::new(8, 22, RC_16_30.to_vec(), DiffusionMatrixBabybear);

        let final_state = gt.permute(initial_state);

        let mut final_state_records = Vec::new();

        for i in 0..POSEIDON2_WIDTH {
            final_state_records.push(MemoryRecord {
                addr: state_ptr + BabyBear::from_canonical_usize(i),
                value: Block::from([
                    final_state[i],
                    BabyBear::zero(),
                    BabyBear::zero(),
                    BabyBear::zero(),
                ]),
                timestamp: clk + BabyBear::from_canonical_usize(31),
                prev_value: Block::from([
                    BabyBear::zero(),
                    BabyBear::zero(),
                    BabyBear::zero(),
                    BabyBear::zero(),
                ]),
                prev_timestamp: clk - BabyBear::from_canonical_usize(1),
            });
        }

        let poseidon2_event = Poseidon2Event {
            state_ptr,
            clk,
            initial_state,
            initial_state_records,
            final_state,
            final_state_records,
        };

        vec![poseidon2_event]
    }

    #[test]
    fn generate_trace() {
        let chip = Poseidon2Chip;
        let input = ExecutionRecord::<BabyBear> {
            poseidon2_events: generate_poseidon2_event(),
            ..Default::default()
        };
        let _: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&input, &mut ExecutionRecord::<BabyBear>::default());
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let chip = Poseidon2Chip;
        let input = ExecutionRecord::<BabyBear> {
            poseidon2_events: generate_poseidon2_event(),
            ..Default::default()
        };
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&input, &mut ExecutionRecord::<BabyBear>::default());

        let gt: Poseidon2<BabyBear, DiffusionMatrixBabybear, 16, 7> =
            Poseidon2::new(8, 22, RC_16_30.to_vec(), DiffusionMatrixBabybear);
        let input = input.poseidon2_events[0].initial_state;
        let output = gt.permute(input);

        let mut row: [BabyBear; NUM_POSEIDON2_COLS] = trace.values
            [NUM_POSEIDON2_COLS * 30..(NUM_POSEIDON2_COLS) * 31]
            .try_into()
            .unwrap();
        let cols: &mut Poseidon2Cols<BabyBear> = row.as_mut_slice().borrow_mut();

        let memory_record = cols.state;
        let output_state: [BabyBear; POSEIDON2_WIDTH] = memory_record
            .iter()
            .map(|block| block.value.0[0])
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        assert_eq!(output_state, output);

        uni_stark_prove(&config, &chip, &mut challenger, trace);
    }
}
