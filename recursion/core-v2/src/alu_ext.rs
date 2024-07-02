use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::extension::BinomialExtensionField;
use p3_field::extension::BinomiallyExtendable;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use p3_field::Field;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::ExtensionAirBuilder;
use sp1_core::air::MachineAir;
use sp1_core::utils::pad_to_power_of_two;
use sp1_derive::AlignedBorrow;
use std::borrow::BorrowMut;

use crate::{builder::SP1RecursionAirBuilder, *};

pub const NUM_EXT_ALU_COLS: usize = core::mem::size_of::<ExtAluCols<u8>>();

// 14 columns
// pub struct FieldALU<F> {
//     pub in1:
// }

// 26 columns
// pub struct ExtensionFieldALU {
//     pub in1: AddressValue<A, V>,
//     pub in2: AddressValue<A, V>,
//     pub sum: Extension<F>,
//     pub diff: Extension<F>,
//     pub product: Extension<F>,
//     pub quotient: Extension<F>,
//     pub out: AddressValue<A, V>,
//     pub is_add: Bool<F>,
//     pub is_diff: Bool<F>,
//     pub is_mul: Bool<F>,
//     pub is_div: Bool<F>,
// }

#[derive(Default)]
pub struct ExtAluChip {}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExtAluCols<F: Copy> {
    pub in1: AddressValue<F, Block<F>>,
    pub in2: AddressValue<F, Block<F>>,
    pub out: AddressValue<F, Block<F>>,
    pub sum: Block<F>,
    pub diff: Block<F>,
    pub product: Block<F>,
    pub quotient: Block<F>,
    pub is_add: F,
    pub is_sub: F,
    pub is_mul: F,
    pub is_div: F,
    // Consider just duplicating the event instead of having this column?
    // Alternatively, a table explicitly for copying/discarding a value
    pub mult: F,
    pub is_real: F,
}

impl<F: Field> BaseAir<F> for ExtAluChip {
    fn width(&self) -> usize {
        NUM_EXT_ALU_COLS
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<D>> MachineAir<F> for ExtAluChip {
    type Record = ExecutionRecord<F>;

    type Program = crate::RecursionProgram<F>;

    fn name(&self) -> String {
        "Extension field Alu".to_string()
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn generate_trace(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let ext_alu_events = input.ext_alu_events.clone();

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let rows = ext_alu_events
            .into_iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_EXT_ALU_COLS];

                let ExtAluEvent {
                    out,
                    in1,
                    in2,
                    mult,
                    opcode,
                } = event;

                let (v1, v2) = (
                    BinomialExtensionField::from_base_slice(&in1.val.0),
                    BinomialExtensionField::from_base_slice(&in2.val.0),
                );

                let cols: &mut ExtAluCols<_> = row.as_mut_slice().borrow_mut();
                *cols = ExtAluCols {
                    in1,
                    in2,
                    out,
                    sum: (v1 + v2).as_base_slice().into(),
                    diff: (v1 - v2).as_base_slice().into(),
                    product: (v1 * v2).as_base_slice().into(),
                    quotient: v1
                        .try_div(v2)
                        .unwrap_or(BinomialExtensionField::one())
                        .as_base_slice()
                        .into(),
                    is_add: F::from_bool(false),
                    is_sub: F::from_bool(false),
                    is_mul: F::from_bool(false),
                    is_div: F::from_bool(false),
                    mult,
                    is_real: F::from_bool(true),
                };
                let target_flag = match opcode {
                    Opcode::AddE => &mut cols.is_add,
                    Opcode::SubE => &mut cols.is_sub,
                    Opcode::MulE => &mut cols.is_mul,
                    Opcode::DivE => &mut cols.is_div,
                    _ => panic!("Invalid opcode: {:?}", opcode),
                };
                *target_flag = F::from_bool(true);

                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_EXT_ALU_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_EXT_ALU_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB> Air<AB> for ExtAluChip
where
    AB: SP1RecursionAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &ExtAluCols<AB::Var> = (*local).borrow();

        // Check exactly one flag is enabled.
        builder
            .when(local.is_real)
            .assert_one(local.is_add + local.is_sub + local.is_mul + local.is_div);

        let in1 = local.in1.val.as_extension::<AB>();
        let in2 = local.in2.val.as_extension::<AB>();
        let out = local.out.val.as_extension::<AB>();
        let sum = local.sum.as_extension::<AB>();
        let diff = local.diff.as_extension::<AB>();
        let product = local.product.as_extension::<AB>();
        let quotient = local.quotient.as_extension::<AB>();

        let mut when_add = builder.when(local.is_add);
        when_add.assert_ext_eq(out.clone(), sum.clone());
        when_add.assert_ext_eq(in1.clone() + in2.clone(), sum.clone());

        let mut when_sub = builder.when(local.is_sub);
        when_sub.assert_ext_eq(out.clone(), diff.clone());
        when_sub.assert_ext_eq(in1.clone(), in2.clone() + diff.clone());

        let mut when_mul = builder.when(local.is_mul);
        when_mul.assert_ext_eq(out.clone(), product.clone());
        when_mul.assert_ext_eq(in1.clone() * in2.clone(), product.clone());

        let mut when_div = builder.when(local.is_div);
        when_div.assert_ext_eq(out, quotient.clone());
        when_div.assert_ext_eq(in1, in2 * quotient);

        // local.is_real is 0 or 1
        // builder.assert_zero(local.is_real * (AB::Expr::one() - local.is_real));

        builder.receive_block(local.in1, local.is_real);

        builder.receive_block(local.in2, local.is_real);

        builder.send_block(local.out, local.mult);
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;

    use sp1_core::air::MachineAir;

    use super::*;

    #[test]
    fn generate_trace() {
        type F = BabyBear;

        let shard = ExecutionRecord {
            ext_alu_events: vec![ExtAluEvent {
                out: AddressValue::new(F::zero(), F::one().into()),
                in1: AddressValue::new(F::zero(), F::one().into()),
                in2: AddressValue::new(F::zero(), F::one().into()),
                mult: F::zero(),
                opcode: Opcode::AddE,
            }],
            ..Default::default()
        };
        let chip = ExtAluChip::default();
        let trace: RowMajorMatrix<F> = chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }
}
