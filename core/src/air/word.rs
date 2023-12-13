use p3_air::AirBuilder;

use super::AirVariable;

/// Using a 32-bit word size, we use four field elements to represent a 32-bit word.
pub const WORD_LEN: usize = 4;

/// An AIR representation of a word in the instruction set.
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

impl<T> Word<T> {
    pub fn map<F, U>(self, f: F) -> Word<U>
    where
        F: FnMut(T) -> U,
    {
        Word(self.0.map(f))
    }
}

impl<T> IntoIterator for Word<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, WORD_LEN>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
