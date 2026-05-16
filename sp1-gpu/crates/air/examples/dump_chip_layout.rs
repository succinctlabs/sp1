#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::vec_init_then_push,
    clippy::useless_vec,
    clippy::manual_div_ceil,
    clippy::doc_lazy_continuation
)]
//! Dump every `RiscvAir` chip as a JSON layout entry (height 0). Feed the
//! output into the zerocheck bench's JSON layout source, with heights edited
//! to whatever distribution you want to test.
//!
//! Run with: cargo run --release --example dump_chip_layout -p sp1-gpu-air

use slop_air::BaseAir;
use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_air::F;
use sp1_hypercube::air::MachineAir;

fn main() {
    let machine = RiscvAir::<F>::machine();
    let chips: Vec<_> = machine.chips().iter().collect();
    println!("[");
    for (i, chip) in chips.iter().enumerate() {
        let comma = if i + 1 < chips.len() { "," } else { "" };
        println!(
            "  {{\"name\": \"{}\", \"preprocessed_width\": {}, \"main_width\": {}, \"height\": 0}}{}",
            chip.name(),
            chip.preprocessed_width(),
            chip.width(),
            comma,
        );
    }
    println!("]");
}
