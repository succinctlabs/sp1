use p3_field::AbstractField;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_compiler::asm::AsmBuilder;
use sp1_recursion_compiler::ir::{Felt, Var};
use sp1_recursion_core::runtime::Runtime;

fn fibonacci(n: u32) -> u32 {
    if n == 0 {
        0
    } else {
        let mut a = 0;
        let mut b = 1;
        for _ in 0..n {
            let temp = b;
            b += a;
            a = temp;
        }
        a
    }
}

fn main() {
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;

    let n_val = 10;
    let mut builder = AsmBuilder::<F, EF>::default();
    let a: Felt<_> = builder.eval(F::zero());
    let b: Felt<_> = builder.eval(F::one());
    let n: Var<_> = builder.eval(F::from_canonical_u32(n_val));

    let start: Var<_> = builder.eval(F::zero());
    let end = n;

    builder.range(start, end).for_each(|_, builder| {
        let temp: Felt<_> = builder.uninit();
        builder.assign(temp, b);
        builder.assign(b, a + b);
        builder.assign(a, temp);
    });

    let expected_value = F::from_canonical_u32(fibonacci(n_val));
    builder.assert_felt_eq(a, expected_value);

    let code = builder.compile_asm();
    println!("{}", code);

    let program = code.machine_code();
    println!("Program size = {}", program.instructions.len());

    let config = SC::new();
    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    runtime.run();

    // let machine = RecursionAir::machine(config);
    // let (pk, vk) = machine.setup(&program);
    // let mut challenger = machine.config().challenger();

    // let start = Instant::now();
    // let proof = machine.prove::<LocalProver<_, _>>(&pk, runtime.record, &mut challenger);
    // let duration = start.elapsed().as_secs();

    // let mut challenger = machine.config().challenger();
    // machine.verify(&vk, &proof, &mut challenger).unwrap();
    // println!("proving duration = {}", duration);
}
