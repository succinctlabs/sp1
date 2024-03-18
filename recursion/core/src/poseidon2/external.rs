use core::borrow::Borrow;
use core::mem::size_of;
use p3_air::AirBuilder;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::Field;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use sp1_core::air::{MachineAir, SP1AirBuilder};
use sp1_core::utils::pad_to_power_of_two;
use sp1_core::utils::poseidon2_instance::RC_16_30_U32;
use sp1_derive::AlignedBorrow;
use std::borrow::BorrowMut;
use tracing::instrument;

use crate::runtime::ExecutionRecord;

/// The number of main trace columns for `AddChip`.
pub const NUM_POSEIDON2_COLS: usize = size_of::<Poseidon2Cols<u8>>();

pub const WIDTH: usize = 16;

/// A chip that implements addition for the opcode ADD.
#[derive(Default)]
pub struct Poseidon2Chip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2Cols<T> {
    pub input: [T; WIDTH],
    pub rounds: [T; 30],
    pub add_rc: [T; WIDTH],
    pub sbox_deg_3: [T; WIDTH],
    pub sbox_deg_7: [T; WIDTH],
    pub output: [T; WIDTH],
    pub is_external: T,
}

impl<F: PrimeField32> MachineAir<F> for Poseidon2Chip {
    type Record = ExecutionRecord<F>;

    fn name(&self) -> String {
        "Poseidon2External".to_string()
    }

    #[instrument(name = "generate add trace", level = "debug", skip_all)]
    fn generate_trace(
        &self,
        _: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut row = [F::zero(); NUM_POSEIDON2_COLS];
        let cols: &mut Poseidon2Cols<F> = row.as_mut_slice().borrow_mut();
        cols.input = [F::zero(); WIDTH];
        cols.rounds[0] = F::one();
        for i in 0..WIDTH {
            cols.add_rc[i] = cols.input[i] + F::from_wrapped_u32(RC_16_30_U32[0][i]);
        }
        cols.is_external = F::one();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(row.to_vec(), NUM_POSEIDON2_COLS);

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

        let rounds_f = 8;
        let rounds_p = 22;
        let rounds = rounds_f + rounds_p;

        // Convert the u32 round constants to field elements.
        let constants: [[AB::F; WIDTH]; 30] = RC_16_30_U32
            .iter()
            .map(|round| round.map(AB::F::from_wrapped_u32))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Apply the round constants.
        //
        // To differentiate between external and internal layers, we set the round constants to zero
        // for the internal layers have been set to zero for the appropriate indices.
        for i in 0..WIDTH {
            let mut result = AB::Expr::zero();

            for r in 0..rounds {
                result += local.input[i] + local.rounds[r] * constants[r][i];
            }

            builder.assert_eq(result, local.add_rc[i]);
        }

        // // Apply the sbox.
        // //
        // // To differentiate between external and internal layers, we use a masking operation
        // // to only apply the state change to the first element for internal layers.
        // for i in 0..WIDTH {
        //     let sbox_deg_3 = local.add_rc[i] * local.add_rc[i] * local.add_rc[i];
        //     builder.assert_eq(sbox_deg_3, local.sbox_deg_3[i]);
        //     let sbox_deg_7 = local.sbox_deg_3[i] * local.sbox_deg_3[i] * local.add_rc[i];
        //     builder.assert_eq(sbox_deg_7, local.sbox_deg_7[i]);
        // }
        // let sbox_result: [AB::Expr; WIDTH] = local
        //     .sbox_deg_7
        //     .iter()
        //     .enumerate()
        //     .map(|(i, x)| {
        //         // Always pass through the first element.
        //         if i == 0 {
        //             AB::Expr::zero() + *x
        //         }
        //         // If it's an internal layer, pass through the element, otherwise use the result
        //         // of the round constants layer.
        //         else {
        //             local.is_external * *x + (AB::Expr::one() - local.is_external) * local.add_rc[i]
        //         }
        //     })
        //     .collect::<Vec<_>>()
        //     .try_into()
        //     .unwrap();

        // // EXTERNAL LAYER
        // {
        //     // First, we apply M_4 to each consecutive four elements of the state.
        //     // In Appendix B's terminology, this replaces each x_i with x_i'.
        //     let mut state: [AB::Expr; WIDTH] = sbox_result.clone();
        //     for i in (0..WIDTH).step_by(4) {
        //         apply_m_4(&mut state[i..i + 4]);
        //     }

        //     // Now, we apply the outer circulant matrix (to compute the y_i values).
        //     //
        //     // We first precompute the four sums of every four elements.
        //     let sums: [AB::Expr; 4] = core::array::from_fn(|k| {
        //         (0..WIDTH)
        //             .step_by(4)
        //             .map(|j| state[j + k].clone())
        //             .sum::<AB::Expr>()
        //     });

        //     // The formula for each y_i involves 2x_i' term and x_j' terms for each j that equals i mod 4.
        //     // In other words, we can add a single copy of x_i' to the appropriate one of our precomputed sums.
        //     for i in 0..WIDTH {
        //         state[i] += sums[i % 4].clone();
        //         builder
        //             .when(local.is_external)
        //             .assert_eq(state[i].clone(), local.output[i]);
        //     }
        // }

        // // INTERNAL LAYER
        // {
        //     // Use a simple matrix multiplication as the permutation.
        //     let mut state: [AB::Expr; WIDTH] = sbox_result.clone();
        //     let matmul_constants: [<<AB as AirBuilder>::Expr as AbstractField>::F; WIDTH] =
        //         MATRIX_DIAG_16_BABYBEAR_U32
        //             .iter()
        //             .map(|x| <<AB as AirBuilder>::Expr as AbstractField>::F::from_wrapped_u32(*x))
        //             .collect::<Vec<_>>()
        //             .try_into()
        //             .unwrap();
        //     matmul_internal(&mut state, matmul_constants);
        //     for i in 0..WIDTH {
        //         builder
        //             .when_not(local.is_external)
        //             .assert_eq(state[i].clone(), local.output[i]);
        //     }
        // }
    }
}

pub fn apply_m_4<AF>(x: &mut [AF])
where
    AF: AbstractField,
{
    let t0 = x[0].clone() + x[1].clone();
    let t1 = x[2].clone() + x[3].clone();
    let t2 = x[1].clone() + x[1].clone() + t1.clone();
    let t3 = x[3].clone() + x[3].clone() + t0.clone();
    let t4 = t1.clone() + t1.clone() + t1.clone() + t1 + t3.clone();
    let t5 = t0.clone() + t0.clone() + t0.clone() + t0 + t2.clone();
    let t6 = t3 + t5.clone();
    let t7 = t2 + t4.clone();
    x[0] = t6;
    x[1] = t5;
    x[2] = t7;
    x[3] = t4;
}

pub fn matmul_internal<F: Field, AF: AbstractField<F = F>, const WIDTH: usize>(
    state: &mut [AF; WIDTH],
    mat_internal_diag_m_1: [F; WIDTH],
) {
    let sum: AF = state.iter().cloned().sum();
    for i in 0..WIDTH {
        state[i] *= AF::from_f(mat_internal_diag_m_1[i]);
        state[i] += sum.clone();
    }
}

pub const MATRIX_DIAG_16_BABYBEAR_U32: [u32; 16] = [
    0x0a632d94, 0x6db657b7, 0x56fbdc9e, 0x052b3d8a, 0x33745201, 0x5c03108c, 0x0beba37b, 0x258c2e8b,
    0x12029f39, 0x694909ce, 0x6d231724, 0x21c3b222, 0x3c0904a5, 0x01d6acda, 0x27705c83, 0x5231c802,
];

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use sp1_core::{
        air::MachineAir,
        utils::{uni_stark_prove, BabyBearPoseidon2, StarkUtils},
    };

    use crate::{poseidon2::external::Poseidon2Chip, runtime::ExecutionRecord};

    #[test]
    fn generate_trace() {
        let chip = Poseidon2Chip;
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(
            &ExecutionRecord::<BabyBear>::default(),
            &mut ExecutionRecord::<BabyBear>::default(),
        );
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let chip = Poseidon2Chip;
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(
            &ExecutionRecord::<BabyBear>::default(),
            &mut ExecutionRecord::<BabyBear>::default(),
        );
        uni_stark_prove(&config, &chip, &mut challenger, trace);
    }
}
