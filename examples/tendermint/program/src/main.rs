#![no_main]
sp1_zkvm::entrypoint!(main);

use core::time::Duration;
use tendermint_light_client_verifier::{
    options::Options, types::LightBlock, ProdVerifier, Verdict, Verifier,
};

fn main() {
    // Normally we could just do this to read in the LightBlocks, but bincode doesn't work with LightBlock.
    // This is likely a bug in tendermint-rs.
    // let light_block_1 = sp1_zkvm::io::read::<LightBlock>();
    // let light_block_2 = sp1_zkvm::io::read::<LightBlock>();
    println!("cycle-tracker-start: io");
    println!("cycle-tracker-start: reading bytes");
    let encoded_1 = sp1_zkvm::io::read::<Vec<u8>>();
    let encoded_2 = sp1_zkvm::io::read::<Vec<u8>>();
    println!("cycle-tracker-end: reading bytes");

    println!("cycle-tracker-start: serde");
    let light_block_1: LightBlock = serde_cbor::from_slice(&encoded_1).unwrap();
    let light_block_2: LightBlock = serde_cbor::from_slice(&encoded_2).unwrap();
    println!("cycle-tracker-end: serde");
    println!("cycle-tracker-end: io");
    for i in 0..10 {
        println!(
            "LightBlock1 number of validators: {}",
            light_block_1.validators.validators().len()
        );
        println!(
            "LightBlock2 number of validators: {}",
            light_block_2.validators.validators().len()
        );

        println!("cycle-tracker-start: verify");
        let vp = ProdVerifier::default();
        let opt = Options {
            trust_threshold: Default::default(),
            trusting_period: Duration::from_secs(500),
            clock_drift: Default::default(),
        };
        let verify_time = light_block_2.time() + Duration::from_secs(20);
        let verdict = vp.verify_update_header(
            light_block_2.as_untrusted_state(),
            light_block_1.as_trusted_state(),
            &opt,
            verify_time.unwrap(),
        );
        println!("cycle-tracker-end: verify");

        match verdict {
            Verdict::Success => {
                println!("success");
            }
            v => panic!("expected success, got: {:?}", v),
        }
    }
}
