use serde::{Deserialize, Serialize};
use succinct_core::{utils, SuccinctProver};

const IO_ELF: &[u8] = include_bytes!("../../../programs/io/elf/riscv32im-succinct-zkvm-elf");

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct MyPointUnaligned {
    pub x: usize,
    pub y: usize,
    pub b: bool,
}

fn main() {
    std::env::set_var("RUST_LOG", "info");
    utils::setup_logger();
    let p1 = MyPointUnaligned {
        x: 3,
        y: 5,
        b: true,
    };
    let p2 = MyPointUnaligned {
        x: 8,
        y: 19,
        b: true,
    };
    let mut prover = SuccinctProver::new();
    prover.write_stdin::<MyPointUnaligned>(&p1);
    prover.write_stdin::<MyPointUnaligned>(&p2);
    prover.run_and_prove(IO_ELF);
}
