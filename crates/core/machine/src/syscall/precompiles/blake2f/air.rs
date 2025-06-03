use p3_air::{Air, BaseAir};
use sp1_stark::air::SP1AirBuilder;

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
    fn eval(&self, builder: &mut AB) {}
}
