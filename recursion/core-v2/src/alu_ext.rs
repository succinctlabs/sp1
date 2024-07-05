use core::borrow::Borrow;
use p3_air::PairBuilder;
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

#[derive(Default)]
pub struct ExtAluChip {}

pub const NUM_EXT_ALU_COLS: usize = core::mem::size_of::<ExtAluCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExtAluCols<F: Copy> {
    pub vals: ExtAluIo<Block<F>>,
    pub sum: Block<F>,
    pub diff: Block<F>,
    pub product: Block<F>,
    pub quotient: Block<F>,
}

pub const NUM_EXT_ALU_PREPROCESSED_COLS: usize = core::mem::size_of::<ExtAluPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExtAluPreprocessedCols<F: Copy> {
    pub addrs: ExtAluIo<Address<F>>,
    pub is_add: F,
    pub is_sub: F,
    pub is_mul: F,
    pub is_div: F,
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

    fn preprocessed_width(&self) -> usize {
        NUM_EXT_ALU_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let rows = program
            .instructions
            .iter()
            .filter_map(|instruction| {
                let Instruction::ExtAlu(ExtAluInstr {
                    opcode,
                    mult,
                    addrs,
                }) = instruction
                else {
                    return None;
                };
                let mult = mult.to_owned();

                let mut row = [F::zero(); NUM_EXT_ALU_PREPROCESSED_COLS];
                let cols: &mut ExtAluPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                *cols = ExtAluPreprocessedCols {
                    addrs: addrs.to_owned(),
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

                Some(row)
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_EXT_ALU_PREPROCESSED_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_EXT_ALU_PREPROCESSED_COLS, F>(&mut trace.values);

        Some(trace)
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn generate_trace(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let ext_alu_events = input.ext_alu_events.clone();

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let rows = ext_alu_events
            .into_iter()
            .map(|vals| {
                let mut row = [F::zero(); NUM_EXT_ALU_COLS];

                let (v1, v2) = (
                    BinomialExtensionField::from_base_slice(&vals.in1.0),
                    BinomialExtensionField::from_base_slice(&vals.in2.0),
                );

                let cols: &mut ExtAluCols<_> = row.as_mut_slice().borrow_mut();
                *cols = ExtAluCols {
                    vals,
                    sum: (v1 + v2).as_base_slice().into(),
                    diff: (v1 - v2).as_base_slice().into(),
                    product: (v1 * v2).as_base_slice().into(),
                    quotient: v1
                        .try_div(v2)
                        .unwrap_or(BinomialExtensionField::one())
                        .as_base_slice()
                        .into(),
                };

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
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &ExtAluCols<AB::Var> = (*local).borrow();
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &ExtAluPreprocessedCols<AB::Var> = (*prep_local).borrow();

        // Check exactly one flag is enabled.
        builder.when(prep_local.is_real).assert_one(
            prep_local.is_add + prep_local.is_sub + prep_local.is_mul + prep_local.is_div,
        );

        let in1 = local.vals.in1.as_extension::<AB>();
        let in2 = local.vals.in2.as_extension::<AB>();
        let out = local.vals.out.as_extension::<AB>();
        let sum = local.sum.as_extension::<AB>();
        let diff = local.diff.as_extension::<AB>();
        let product = local.product.as_extension::<AB>();
        let quotient = local.quotient.as_extension::<AB>();

        let mut when_add = builder.when(prep_local.is_add);
        when_add.assert_ext_eq(out.clone(), sum.clone());
        when_add.assert_ext_eq(in1.clone() + in2.clone(), sum.clone());

        let mut when_sub = builder.when(prep_local.is_sub);
        when_sub.assert_ext_eq(out.clone(), diff.clone());
        when_sub.assert_ext_eq(in1.clone(), in2.clone() + diff.clone());

        let mut when_mul = builder.when(prep_local.is_mul);
        when_mul.assert_ext_eq(out.clone(), product.clone());
        when_mul.assert_ext_eq(in1.clone() * in2.clone(), product.clone());

        let mut when_div = builder.when(prep_local.is_div);
        when_div.assert_ext_eq(out, quotient.clone());
        when_div.assert_ext_eq(in1, in2 * quotient);

        // local.is_real is 0 or 1
        // builder.assert_zero(local.is_real * (AB::Expr::one() - local.is_real));

        builder.receive_block(prep_local.addrs.in1, local.vals.in1, prep_local.is_real);

        builder.receive_block(prep_local.addrs.in2, local.vals.in2, prep_local.is_real);

        builder.send_block(prep_local.addrs.out, local.vals.out, prep_local.mult);
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
            ext_alu_events: vec![ExtAluIo {
                out: F::one().into(),
                in1: F::one().into(),
                in2: F::one().into(),
            }],
            ..Default::default()
        };
        let chip = ExtAluChip::default();
        let trace: RowMajorMatrix<F> = chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }
}
