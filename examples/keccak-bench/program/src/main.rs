#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let use_manual_precompile = sp1_zkvm::io::read::<bool>();
    let num_hashes = sp1_zkvm::io::read::<usize>();
    let mut state = sp1_zkvm::io::read::<Vec<u8>>();

    if use_manual_precompile {
        for _ in 0..num_hashes {
            manual_precompile::hash(&mut state);
        }
    } else {
        for _ in 0..num_hashes {
            software::hash(&mut state);
        }
    }

    sp1_zkvm::io::commit(&state);
}

mod manual_precompile {
    use tiny_keccak::{Hasher, Keccak};

    pub fn hash(state: &mut Vec<u8>) {
        let mut hasher = Keccak::v256();
        hasher.update(&state);
        hasher.finalize(state);
    }
}

mod software {
    use tiny_keccak_software::{Hasher, Keccak};

    pub fn hash(state: &mut Vec<u8>) {
        let mut hasher = Keccak::v256();
        hasher.update(&state);
        hasher.finalize(state);
    }
}
