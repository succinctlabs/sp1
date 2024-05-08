#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

use sp1_prover::install;

pub fn main() {
    install::install_groth16_artifacts();
}
