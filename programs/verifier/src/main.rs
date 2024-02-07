#![no_main]

extern crate succinct_zkvm;

use std::hint::black_box;

use p3_commit::Pcs;
use p3_field::{ExtensionField, PrimeField, PrimeField32, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;

use succinct_core::runtime::Runtime;
use succinct_core::stark::types::SegmentProof;
use succinct_core::stark::StarkConfig;
use succinct_core::utils::BabyBearPoseidon2;
use succinct_core::utils::StarkUtils;

succinct_zkvm::entrypoint!(main);

fn verify<F, EF, SC>(
    runtime: &mut Runtime,
    config: &SC,
    challenger: &mut SC::Challenger,
    segment_proofs: &[SegmentProof<SC>],
    global_proof: &SegmentProof<SC>,
) where
    F: PrimeField + TwoAdicField + PrimeField32,
    EF: ExtensionField<F>,
    SC: StarkConfig<Val = F, Challenge = EF> + Send + Sync,
    SC::Challenger: Clone,
    <SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::Commitment: Send + Sync,
    <SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::ProverData: Send + Sync,
{
    println!("cycle-tracker-start: verify");
    runtime
        .verify::<_, _, SC>(config, challenger, segment_proofs, global_proof)
        .unwrap();
    println!("cycle-tracker-end: verify");
}

fn main() {
    let segment_proofs_bytes = include_bytes!("./fib_proofs/segment_proofs.bytes");
    let segment_proofs: Vec<SegmentProof<BabyBearPoseidon2>> =
        bincode::deserialize(&segment_proofs_bytes[..]).unwrap();

    let global_proof_bytes = include_bytes!("./fib_proofs/global_proof.bytes");
    let global_proof: SegmentProof<BabyBearPoseidon2> =
        bincode::deserialize(&global_proof_bytes[..]).unwrap();

    let config = BabyBearPoseidon2::new();
    let mut challenger = config.challenger();

    let mut runtime = Runtime::default();

    black_box(verify::<_, _, BabyBearPoseidon2>(
        black_box(&mut runtime),
        black_box(&config),
        black_box(&mut challenger),
        black_box(&segment_proofs),
        black_box(&global_proof),
    ));
}
