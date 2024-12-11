#![no_main]
sp1_zkvm::entrypoint!(main);

use hex_literal::hex;

use ed25519_consensus::{
    Signature as Ed25519ConsensusSignature, VerificationKey as Ed25519ConsensusVerificationKey,
};

/// Emits ED_ADD and ED_DECOMPRESS syscalls.
pub fn main() {
    // Example signature and message.
    let vk = hex!("9194c3ead03f5848111db696fe1196fbbeffc69342d51c7cf5e91c502de91eb4");
    let msg = hex!("656432353531392d636f6e73656e7375732074657374206d657373616765");
    let sig = hex!("69261ea5df799b20fc6eeb49aa79f572c8f1e2ba88b37dff184cc55d4e3653d876419bffcc47e5343cdd5fd78121bb32f1c377a5ed505106ad37f19980218f0d");

    let vk: Ed25519ConsensusVerificationKey = vk.try_into().unwrap();
    let sig: Ed25519ConsensusSignature = sig.into();

    println!("cycle-tracker-start: ed25519-consensus verify");
    vk.verify(&sig, &msg).unwrap();
    println!("cycle-tracker-end: ed25519-consensus verify");
}
