use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, PairBuilder};
use p3_field::Field;
use p3_matrix::Matrix;

use super::{
    columns::{RangeCheckMultCols, RangeCheckPreprocessedCols, NUM_RANGE_CHECK_MULT_COLS},
    RangeCheckChip, RangeCheckOpcode,
};
use crate::air::SP1RecursionAirBuilder;

impl<F: Field> BaseAir<F> for RangeCheckChip<F> {
    fn width(&self) -> usize {
        NUM_RANGE_CHECK_MULT_COLS
    }
}

impl<AB: SP1RecursionAirBuilder + PairBuilder> Air<AB> for RangeCheckChip<AB::F> {
    /// Eval's the range check chip.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_mult = main.row_slice(0);
        let local_mult: &RangeCheckMultCols<AB::Var> = (*local_mult).borrow();

        let prep = builder.preprocessed();
        let prep = prep.row_slice(0);
        let local: &RangeCheckPreprocessedCols<AB::Var> = (*prep).borrow();

        // Send all the lookups for each operation.
        for (i, opcode) in RangeCheckOpcode::all().iter().enumerate() {
            let field_op = opcode.as_field::<AB::F>();
            let mult = local_mult.multiplicities[i];

            // Ensure that all U12 range check lookups are not outside of the U12 range.
            if *opcode == RangeCheckOpcode::U12 {
                builder.when(local.u12_out_range).assert_zero(mult);
            }

            builder.receive_range_check(field_op, local.value_u16, mult);
        }
    }
}
