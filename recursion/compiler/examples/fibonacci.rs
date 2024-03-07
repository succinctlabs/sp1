fn main() {
    // let mut builder = AsmBuilder::new();
    // let a = builder.constant::<F>(0);
    // let b = builder.constant::<F>(1);
    // let n = builder.constant::<F>(10);

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
}
