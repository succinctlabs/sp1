use core::borrow::Borrow;
use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_field::Field;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::AirInteraction;
use sp1_core::air::MachineAir;
use sp1_core::air::MessageBuilder;
use sp1_core::air::SP1AirBuilder;
use sp1_core::lookup::InteractionKind;
use std::marker::PhantomData;
// use sp1_core::runtime::ExecutionRecord;
use sp1_core::runtime::Program;
use sp1_core::utils::pad_rows_fixed;
use sp1_core::utils::pad_to_power_of_two;
use sp1_derive::AlignedBorrow;
use std::borrow::BorrowMut;
use tracing::instrument;

use crate::*;

pub const NUM_FIELD_ALU_COLS: usize = core::mem::size_of::<FieldAluCols<u8>>();
// 14 columns
// pub struct FieldALU<F> {
//     pub in1: F
// }

#[derive(Default)]
pub struct FieldAluChip {}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct FieldAluCols<F: Copy> {
    pub in1: AddressValue<F>,
    pub in2: AddressValue<F>,
    pub sum: F,
    pub diff: F,
    pub product: F,
    pub quotient: F,
    pub out: AddressValue<F>,
    pub is_add: F,
    pub is_sub: F,
    pub is_mul: F,
    pub is_div: F,
    // Consider just duplicating the event instead of having this column?
    // Alternatively, a table explicitly for copying/discarding a value
    pub mult: F,
    pub is_real: F,
}

impl<F: Field> BaseAir<F> for FieldAluChip {
    fn width(&self) -> usize {
        NUM_FIELD_ALU_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for FieldAluChip {
    type Record = ExecutionRecord<F>;

    type Program = crate::RecursionProgram<F>;

    fn name(&self) -> String {
        "Alu".to_string()
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn generate_trace(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let alu_events = input.alu_events.clone();

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let rows = alu_events
            .into_iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_FIELD_ALU_COLS];

                let AluEvent {
                    out,
                    in1,
                    in2,
                    mult,
                    opcode,
                } = event;

                let (v1, v2) = (in1.val, in2.val);

                let cols: &mut FieldAluCols<_> = row.as_mut_slice().borrow_mut();
                *cols = FieldAluCols {
                    in1,
                    in2,
                    sum: v1 + v2,
                    diff: v1 - v2,
                    product: v1 * v2,
                    quotient: v1 * v2.try_inverse().unwrap_or(F::one()),
                    out,
                    is_add: F::from_bool(false),
                    is_sub: F::from_bool(false),
                    is_mul: F::from_bool(false),
                    is_div: F::from_bool(false),
                    mult,
                    is_real: F::from_bool(true),
                };
                let target_flag = match opcode {
                    Opcode::AddF => &mut cols.is_add,
                    Opcode::SubF => &mut cols.is_sub,
                    Opcode::MulF => &mut cols.is_mul,
                    Opcode::DivF => &mut cols.is_div,
                    _ => panic!("Invalid opcode: {:?}", opcode),
                };
                *target_flag = F::from_bool(true);

                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_FIELD_ALU_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_FIELD_ALU_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB> Air<AB> for FieldAluChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let encode = |av: AddressValue<AB::Var>| vec![av.addr.into(), av.val.into()];

        let main = builder.main();
        let local = main.row_slice(0);
        let local: &FieldAluCols<AB::Var> = (*local).borrow();

        let mut when_add = builder.when(local.is_add);
        when_add.assert_eq(local.out.val, local.sum);
        when_add.assert_eq(local.in1.val + local.in2.val, local.sum);

        let mut when_sub = builder.when(local.is_sub);
        when_sub.assert_eq(local.out.val, local.diff);
        when_sub.assert_eq(local.in1.val, local.in2.val + local.diff);

        let mut when_mul = builder.when(local.is_mul);
        when_mul.assert_eq(local.out.val, local.product);
        when_mul.assert_eq(local.in1.val * local.in2.val, local.product);

        let mut when_div = builder.when(local.is_div);
        when_div.assert_eq(local.out.val, local.quotient);
        when_div.assert_eq(local.in1.val, local.in2.val * local.quotient);

        // local.is_real is 0 or 1
        // builder.assert_zero(local.is_real * (AB::Expr::one() - local.is_real));

        builder.receive(AirInteraction::new(
            encode(local.in1),
            local.is_real.into(), // is_real should be 0 or 1
            InteractionKind::Memory,
        ));

        builder.receive(AirInteraction::new(
            encode(local.in2),
            local.is_real.into(), // is_real should be 0 or 1
            InteractionKind::Memory,
        ));

        builder.send(AirInteraction::new(
            encode(local.out),
            local.mult.into(),
            InteractionKind::Memory,
        ));
    }
}

/*

1) make a dummy program for loop 100: x' = x*x + x
2) make add chip and mul chip with 3 columns each that prove a = b + c and a = b * c respectively.
and then also fill in generate_trace and eval and write test (look at add_sub in core for test example).
you will also need to write your own execution record struct but look at recursion-core for how we did that

*/

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
        type F = BabyBear;

        let shard = ExecutionRecord::<F> {
            alu_events: vec![AluEvent {
                out: AddressValue::new(F::zero(), F::one()),
                in1: AddressValue::new(F::zero(), F::one()),
                in2: AddressValue::new(F::zero(), F::one()),
                mult: F::zero(),
                opcode: Opcode::AddF,
            }],
            ..Default::default()
        };
        let chip = FieldAluChip::default();
        let trace: RowMajorMatrix<F> = chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    // #[test]
    // fn prove_babybear() {
    //     let config = BabyBearPoseidon2::compressed();
    //     let mut challenger = config.challenger();

    //     let chip = FieldAlu::default();

    //     let embed = BabyBear::from_canonical_u32;

    //     let test_xs = (1..8)
    //         .map(|x| AddressValue::new(embed(x + 1000), embed(x)))
    //         .collect_vec();

    //     let test_ys = (1..8)
    //         .map(|x| AddressValue::new(embed(x + 2000), embed(x)))
    //         .collect_vec();

    //     let mut input_exec = ExecutionRecord::<BabyBear>::default();
    //     for (x, y) in test_xs.into_iter().cartesian_product(test_ys) {
    //         // let sum = x.val + y.val;
    //         // input_exec.add_events.push(AluEvent {
    //         //     out: AddressValue::new(sum + embed(3000), sum),
    //         //     in1: x,
    //         //     in2: y,
    //         //     mult: embed(0),
    //         //     opcode: Opcode::Add,
    //         // });
    //     }
    //     println!("input exec: {:?}", input_exec.add_events.len());
    //     let trace: RowMajorMatrix<BabyBear> =
    //         chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());
    //     println!(
    //         "trace dims is width: {:?}, height: {:?}",
    //         trace.width(),
    //         trace.height()
    //     );

    //     let start = Instant::now();
    //     let proof = uni_stark_prove(&config, &chip, &mut challenger, trace);
    //     let duration = start.elapsed().as_secs_f64();
    //     println!("proof duration = {:?}", duration);

    //     let mut challenger: p3_challenger::DuplexChallenger<
    //         BabyBear,
    //         Poseidon2<BabyBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>,
    //         16,
    //         8,
    //     > = config.challenger();
    //     let start = Instant::now();
    //     uni_stark_verify(&config, &chip, &mut challenger, &proof)
    //         .expect("expected proof to be valid");

    //     let duration = start.elapsed().as_secs_f64();
    //     println!("verify duration = {:?}", duration);
    // }
}
