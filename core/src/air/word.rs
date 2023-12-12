use p3_air::AirBuilder;

use super::AirVariable;

const WORD_LEN: usize = 4;

/// An AIR representation of a 32-bit word.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Word<T>(pub [T; WORD_LEN]);

impl<AB: AirBuilder> AirVariable<AB> for Word<AB::Var> {
    fn size_of() -> usize {
        WORD_LEN
    }

    fn eval_is_valid(&self, _builder: &mut AB) {
        todo!()
    }
}
