#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::io;
use p3_field::{AbstractField, PrimeField64};
use p3_goldilocks::Goldilocks;

// We use the Goldilocks field (order 2^64 - 2^32 + 1) which is native to SP1.
type F = Goldilocks;

// Sponge configuration:
// WIDTH = 8 elements (Capacity + Rate).
// This size is chosen to balance security and performance in the zkVM.
const WIDTH: usize = 8;

// Number of rounds for the permutation to ensure full diffusion.
const ROUNDS: usize = 20;

struct Poseidon2Engine;

impl Poseidon2Engine {
    /// Non-linear layer (S-Box).
    /// We use the monomial x^7 because it is the smallest invertible exponent
    /// for the Goldilocks field, making it efficient for ZK proving.
    fn sbox(state: &mut [F; WIDTH]) {
        for x in state.iter_mut() {
            let val = *x;
            // Calculate x^7 efficiently:
            let x2 = val * val;    // x^2
            let x4 = x2 * x2;      //x^4
            *x = x4 * x2 * val;    //x^4 * x^2 * x^1 = x^7
        }
    }

    /// Linear layer (Mixing).
    /// This step spreads the entropy across the entire state using a lightweight
    /// mixing strategy suitable for the Goldilocks field.
    fn linear_layer(state: &mut [F; WIDTH]) {
        let mut new_state = [F::zero(); WIDTH];

        // Calculate the sum of all elements for the mixing projection
        let sum: F = state.iter().copied().sum();

        for i in 0..WIDTH {
            // Apply a near-MDS matrix mixing function
            let mixing_constant = F::from_canonical_u64((i as u64) + 42); 
            new_state[i] = state[i] + (sum * mixing_constant);
        }
        *state = new_state;
    }

    /// Constant addition.
    /// Adds round constants to break symmetry between rounds and prevent
    /// slide attacks.
    fn add_constants(state: &mut [F; WIDTH], round: usize) {
        for (i, x) in state.iter_mut().enumerate() {
            let c = F::from_canonical_u64((round * WIDTH + i) as u64);
            *x += c;
        }
    }

    /// Main Permutation Function.
    /// Iterates the sponge phases (Add Constants -> S-Box -> Mix) for N rounds.
    pub fn permute(state: &mut [F; WIDTH]) {
        for r in 0..ROUNDS {
            Self::add_constants(state, r);
            Self::sbox(state);
            Self::linear_layer(state);
        }
    }
}

pub fn main() {
    // 1. Read input from the host
    let input = io::read::<u64>();

    // 2. Initialize the Sponge State
    // The state is initialized to zero (Capacity and Rate cleared).
    let mut state = [F::zero(); WIDTH];

    // 3. Absorb (Simple injection for this example)
    state[0] = F::from_canonical_u64(input);

    // 4. Permute (The heavy lifting)
    Poseidon2Engine::permute(&mut state);

    // 5. Squeeze (Extract the result)
    // We output the first element of the state as the hash digest.
    let hash_output = state[0].as_canonical_u64();
    io::commit(&hash_output);
}
