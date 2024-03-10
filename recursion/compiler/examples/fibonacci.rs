use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_compiler::prelude::*;
use sp1_recursion_core::runtime::Runtime;

fn main() {
    let mut builder = AsmBuilder::<BabyBear>::new();
    let a: Felt<_> = builder.constant(BabyBear::zero());
    let b: Felt<_> = builder.constant(BabyBear::one());
    let n: Felt<_> = builder.constant(BabyBear::from_canonical_u32(12));

    let start: Felt<_> = builder.constant(BabyBear::zero());
    let end = n;

    builder.range(start, end).for_each(|_, builder| {
        let temp: Felt<_> = builder.uninit();
        builder.assign(temp, b);
        builder.assign(b, a + b);
        builder.assign(a, temp);
    });

    builder.if_eq(a, BabyBear::zero()).then(|builder| {
        builder.assign(a, b);
    });

    let code = builder.code();
    println!("{}", code);

    let program = code.machine_code();

    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;

    let mut runtime = Runtime::<F>::new(&program);
    runtime.run();
}
