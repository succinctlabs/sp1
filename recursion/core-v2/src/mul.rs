use core::borrow::Borrow;
use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::MachineAir;
use sp1_core::air::SP1AirBuilder;
// use sp1_core::runtime::ExecutionRecord;
use sp1_core::runtime::Program;
use sp1_core::utils::pad_rows_fixed;
use sp1_core::utils::pad_to_power_of_two;
use sp1_derive::AlignedBorrow;
use std::borrow::BorrowMut;
use tracing::instrument;

use crate::*;

pub const NUM_MUL_COLS: usize = core::mem::size_of::<MulCols<u8>>();

#[derive(Default)]
pub struct MulChip {}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MulCols<T: Copy> {
    pub a: T,
    pub b: T,
    pub c: T,
    pub is_real: T,
}

impl<F> BaseAir<F> for MulChip {
    fn width(&self) -> usize {
        NUM_MUL_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for MulChip {
    type Record = ExecutionRecord<F>;

    type Program = crate::RecursionProgram<F>;

    fn name(&self) -> String {
        "Mul".to_string()
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn generate_trace(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let mul_events = input.mul_events.clone();

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let rows = mul_events
            .into_iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_MUL_COLS];

                assert_eq!(event.opcode, Opcode::Mul);

                let AluEvent { a, b, c, .. } = event;

                let cols: &mut MulCols<_> = row.as_mut_slice().borrow_mut();
                *cols = MulCols {
                    a,
                    b,
                    c,
                    is_real: F::one(),
                };

                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_MUL_COLS);

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_MUL_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB> Air<AB> for MulChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MulCols<AB::Var> = (*local).borrow();
        builder
            .when(local.is_real)
            .assert_eq(local.a, local.b * local.c);
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use p3_baby_bear::BabyBear;
    use p3_baby_bear::DiffusionMatrixBabyBear;
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::Matrix;
    use p3_poseidon2::Poseidon2;
    use p3_poseidon2::Poseidon2ExternalMatrixGeneral;

    use rand::{thread_rng, Rng};
    use std::time::Instant;

    use sp1_core::{air::MachineAir, utils::uni_stark_verify};
    use sp1_core::{
        stark::StarkGenericConfig,
        utils::{uni_stark_prove, BabyBearPoseidon2},
    };

    use super::*;

    #[test]
    fn generate_trace() {
        let shard = ExecutionRecord::<BabyBear> {
            mul_events: vec![AluEvent {
                opcode: Opcode::Mul,
                a: BabyBear::one(),
                b: BabyBear::one(),
                c: BabyBear::two(),
            }],
            ..Default::default()
        };
        let chip = MulChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::compressed();
        let mut challenger = config.challenger();

        let chip = MulChip::default();

        let test_xs = (1..8).map(BabyBear::from_canonical_u32).collect_vec();

        let test_ys = (1..8).map(BabyBear::from_canonical_u32).collect_vec();

        let mut input_exec = ExecutionRecord::<BabyBear>::default();
        for (x, y) in test_xs.into_iter().cartesian_product(test_ys) {
            input_exec.mul_events.push(AluEvent {
                opcode: Opcode::Mul,
                a: x * y,
                b: x,
                c: y,
            });
        }
        println!("input exec: {:?}", input_exec.mul_events.len());
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());
        println!(
            "trace dims is width: {:?}, height: {:?}",
            trace.width(),
            trace.height()
        );

        let start = Instant::now();
        let proof = uni_stark_prove(&config, &chip, &mut challenger, trace);
        let duration = start.elapsed().as_secs_f64();
        println!("proof duration = {:?}", duration);

        let mut challenger: p3_challenger::DuplexChallenger<
            BabyBear,
            Poseidon2<BabyBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>,
            16,
            8,
        > = config.challenger();
        let start = Instant::now();
        uni_stark_verify(&config, &chip, &mut challenger, &proof)
            .expect("expected proof to be valid");

        let duration = start.elapsed().as_secs_f64();
        println!("verify duration = {:?}", duration);
    }
}
