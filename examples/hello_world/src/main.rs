succinct_zkvm::entrypoint!(main);

pub fn main() {
    let mut a = 1;
    let mut b = 1;

    let fibonacci_results = Vec::new();

    for _ in 0..10 {
        let c = a + b;
        fibonacci_results.push(c);
        a = b;
        b = c;
    }

    let final_result = fibonacci_results[9];

    // TODO: HALT using our HALT syscall
}
