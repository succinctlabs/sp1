use std::borrow::Borrow;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_matrix::Matrix;
use sp1_stark::air::SP1AirBuilder;

use crate::syscall::precompiles::blake2f::columns::Blake2fCompressColumns;

use super::columns::NUM_BLAKE2F_COMPRESS_COLS;
use super::Blake2fCompressChip;


impl<F> BaseAir<F> for Blake2fCompressChip {
    fn width(&self) -> usize {
        NUM_BLAKE2F_COMPRESS_COLS
    }
}

impl<AB> Air<AB> for Blake2fCompressChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &Blake2fCompressColumns<AB::Var> = (*local).borrow();
        builder.assert_bool(local.f_flag);
    }
}
