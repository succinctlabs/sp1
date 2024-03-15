use p3_field::Field;
use sp1_recursion_compiler::ir::Var;

pub struct Hash<F: Field, const DIGEST_ELEMS: usize> {
    value: [Var<F>; DIGEST_ELEMS],
}
