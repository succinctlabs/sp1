use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use sp1_recursion_compiler::prelude::*;

fn main() {
    let mut builder = AsmBuilder::<BabyBear>::new();
    let a = builder.constant(BabyBear::zero());
    let b = builder.constant(BabyBear::one());
    let n = builder.constant(BabyBear::from_canonical_u32(10));

    let temp = builder.uninit::<Felt<BabyBear>>();
    builder.assign(temp, a + b);
    builder.assign(a, b);
    builder.assign(b, temp);

    // let mut temp = builder.uninit::<F>();

    // builder.for(n).do(|builder, i| {
    //     builder.assign(temp, a + b);
    //     builder.assign(a, b);
    //     builder.assign(b, temp);
    // });

    // Another example with a fixed-size vector instead of a for loop
    // let fib = builder.uninit::<[F; 10]>();
    // builder.assign(fib[0], a);
    // builder.assign(fib[1], b);
    // builder.for(2..10).do(|builder, i| {
    //     builder.assign(fib[i], fib[i - 1] + fib[i - 2]);
    // });

    for (i, block) in builder.basic_blocks.iter().enumerate() {
        println!(".LBB0_{}:", i);
        println!("{}", block);
    }
}
