use sp1_recursion_compiler::ir::{Array, Config};
use sp1_recursion_compiler::prelude::*;

#[derive(DslVariable, Debug, Clone)]
pub struct FriFoldInput<C: Config> {
    values: Array<C, Felt<C::F>>,
}
