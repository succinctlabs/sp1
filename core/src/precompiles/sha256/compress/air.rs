use p3_air::{Air, AirBuilder, BaseAir};

use super::columns::{ShaCompressCols, NUM_SHA_COMPRESS_COLS};
use super::ShaCompressChip;
use crate::air::CurtaAirBuilder;
use p3_matrix::MatrixRowSlices;
use std::borrow::Borrow;

impl<F> BaseAir<F> for ShaCompressChip {
    fn width(&self) -> usize {
        NUM_SHA_COMPRESS_COLS
    }
}

impl<AB> Air<AB> for ShaCompressChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &ShaCompressCols<AB::Var> = main.row_slice(0).borrow();
        let next: &ShaCompressCols<AB::Var> = main.row_slice(1).borrow();
    }
}
