use p3_baby_bear::BabyBear;
use sp1_recursion_compiler::prelude::*;

fn main() {
    let mut builder = AsmBuilder::<BabyBear>::new();

    let a: Bool = builder.constant(false);
    let b: Bool = builder.constant(true);

    let and: Bool = builder.uninit();
    builder.assign(and, a & b);
    let or: Bool = builder.uninit();
    builder.assign(or, a | b);
    let xor: Bool = builder.uninit();
    builder.assign(xor, a ^ b);
    let not: Bool = builder.uninit();
    builder.assign(not, !a);

    let code = builder.code();
    println!("{}", code);
}
