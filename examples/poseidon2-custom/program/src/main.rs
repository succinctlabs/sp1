#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::io;
use p3_field::{AbstractField, PrimeField64};
use p3_goldilocks::Goldilocks;

type F = Goldilocks;
const WIDTH: usize = 8;
const ROUNDS: usize = 20;

struct Poseidon2Engine;

impl Poseidon2Engine {
    fn sbox(state: &mut [F; WIDTH]) {
        for x in state.iter_mut() {
            let val = *x;
            let x2 = val * val;
            let x4 = x2 * x2;
            *x = x4 * x2 * val;
        }
    }

    fn linear_layer(state: &mut [F; WIDTH]) {
        let mut new_state = [F::zero(); WIDTH];
        let sum: F = state.iter().copied().sum();

        for i in 0..WIDTH {
            let mixing_constant = F::from_canonical_u64((i as u64) + 42); 
            new_state[i] = state[i] + (sum * mixing_constant);
        }
        *state = new_state;
    }

    fn add_constants(state: &mut [F; WIDTH], round: usize) {
        for (i, x) in state.iter_mut().enumerate() {
            let c = F::from_canonical_u64((round * WIDTH + i) as u64);
            *x += c;
        }
    }

    pub fn permute(state: &mut [F; WIDTH]) {
        for r in 0..ROUNDS {
            Self::add_constants(state, r);
            Self::sbox(state);
            Self::linear_layer(state);
        }
    }
}

pub fn main() {
    let input = io::read::<u64>();
    let mut state = [F::zero(); WIDTH];
    state[0] = F::from_canonical_u64(input);

    Poseidon2Engine::permute(&mut state);

    let hash_output = state[0].as_canonical_u64();
    io::commit(&hash_output);
}
