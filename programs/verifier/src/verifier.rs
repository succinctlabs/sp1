use succinct_core::runtime::Runtime;
use succinct_core::stark::types::SegmentProof;
use succinct_core::utils;
use succinct_core::utils::BabyBearPoseidon2;
use succinct_core::utils::StarkUtils;

fn main() {
    utils::setup_logger();

    let segment_proofs_bytes = include_bytes!("../data/proofs/segment_proofs.bytes");
    let segment_proofs: Vec<SegmentProof<BabyBearPoseidon2>> =
        bincode::deserialize(&segment_proofs_bytes[..]).unwrap();

    let global_proof_bytes = include_bytes!("../data/proofs/global_proof.bytes");
    let global_proof: SegmentProof<BabyBearPoseidon2> =
        bincode::deserialize(&global_proof_bytes[..]).unwrap();

    let config = BabyBearPoseidon2::new();
    let mut challenger = config.challenger();
    let mut runtime = Runtime::default();

    runtime
        .verify::<_, _, BabyBearPoseidon2>(&config, &mut challenger, &segment_proofs, &global_proof)
        .unwrap();
}
