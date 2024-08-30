use sp1_recursion_compiler::ir::Builder;

use crate::{BabyBearFriConfigVariable, CircuitConfig};

fn assert_complete<C, SC>(builder: &mut Builder<C>)
where
    SC: BabyBearFriConfigVariable<C>,
    C: CircuitConfig<F = SC::Val, EF = SC::Challenge>,
{
}
