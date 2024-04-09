use p3_field::AbstractField;
use rand::{thread_rng, Rng};
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_compiler::asm::VmBuilder;
use sp1_recursion_compiler::prelude::*;
use sp1_recursion_core::runtime::Runtime;

#[test]
fn test_compiler_public_values() {
    let mut rng = thread_rng();
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    let mut builder = VmBuilder::<F, EF>::default();

    let a_val = rng.gen::<F>();
    let b_val = rng.gen::<F>();
    let a: Felt<_> = builder.eval(a_val);
    let b: Felt<_> = builder.eval(b_val);

    let dyn_len: Var<_> = builder.eval(F::from_canonical_usize(2));
    let mut var_array = builder.dyn_array::<Felt<_>>(dyn_len);
    builder.set(&mut var_array, 0, a);
    builder.set(&mut var_array, 1, b);
    builder.write_public_values(&var_array);
    builder.commit_public_values();

    let program = builder.compile();

    let config = SC::default();
    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    runtime.run();
}
