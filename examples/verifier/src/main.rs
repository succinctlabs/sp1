use succinct_core::runtime::Program;
use succinct_core::runtime::Runtime;
use succinct_core::utils::BabyBearPoseidon2;
use succinct_core::utils::StarkUtils;

fn main() {
    let program = Program::from_elf("../programs/fibonacci");

    let mut runtime = Runtime::new(program);
    runtime.add_input_slice(&[1, 2]);
    runtime.run();

    let config = BabyBearPoseidon2::new(&mut rand::thread_rng());
    let mut challenger = config.challenger();

    // Prove the program.
    let (segment_proofs, global_proof) =
        runtime.prove::<_, _, BabyBearPoseidon2>(&config, &mut challenger);

    // Verify the proof.
    let mut challenger = config.challenger();
    runtime
        .verify::<_, _, BabyBearPoseidon2>(&config, &mut challenger, &segment_proofs, &global_proof)
        .unwrap();
}
