use std::marker::PhantomData;

use sp1_core::stark::StarkGenericConfig;
use sp1_recursion_compiler::ir::Config;

#[derive(Debug, Clone, Copy)]
pub struct StarkVerifierCircuit<C: Config, SC: StarkGenericConfig> {
    _phantom: PhantomData<(C, SC)>,
}
