#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![allow(deprecated)]
use p3_baby_bear::BabyBear;
use p3_challenger::CanObserve;
use p3_commit::TwoAdicMultiplicativeCoset;
use sp1_core::{
    air::{MachineAir, PublicValues, Word},
    runtime::Program,
    stark::{LocalProver, Proof, RiscvAir, ShardProof, StarkGenericConfig, VerifyingKey},
    utils::{run_and_prove, BabyBearPoseidon2},
    SP1Stdin,
};
use sp1_recursion_core::{runtime::Runtime, stark::RecursionAir};
use sp1_recursion_program::{
    fri::TwoAdicMultiplicativeCosetVariable, hints::Hintable, reduce::build_reduce, stark::EMPTY,
};
use std::time::Instant;
type InnerSC = BabyBearPoseidon2;
type InnerF = <InnerSC as StarkGenericConfig>::Val;
type InnerEF = <InnerSC as StarkGenericConfig>::Challenge;
type InnerA = RiscvAir<InnerF>;

pub struct SP1ProverImpl;

impl SP1ProverImpl {
    pub fn prove(elf: &[u8], stdin: &[Vec<u8>]) -> Proof<InnerSC> {
        let config = InnerSC::default();
        let machine = RiscvAir::machine(config.clone());
        let program = Program::from(elf);
        let (_, vk) = machine.setup(&program);
        let (proof, _) = run_and_prove(program, stdin, config);
        let mut challenger_ver = machine.config().challenger();
        machine.verify(&vk, &proof, &mut challenger_ver).unwrap();
        proof
    }

    fn compress(elf: &[u8], proof: Proof<InnerSC>) -> Vec<ShardProof<InnerSC>> {
        let config = InnerSC::default();
        let machine = RiscvAir::machine(config.clone());
        let program = Program::from(elf);
        let (_, vk) = machine.setup(&program);
        let reduce_program = build_reduce(vk.chip_information.clone());
        println!("nb_shards {}", proof.shard_proofs.len());
        let config = InnerSC::default();

        let mut witness_stream = Vec::new();
        witness_stream.extend(proof.shard_proofs.write());
        let is_recursive_flags: Vec<usize> = proof.shard_proofs.iter().map(|_| 0).collect();
        witness_stream.extend(is_recursive_flags.write());
        let sorted_indices: Vec<Vec<usize>> = proof
            .shard_proofs
            .iter()
            .map(|p| {
                machine
                    .chips_sorted_indices(p)
                    .into_iter()
                    .map(|x| match x {
                        Some(x) => x,
                        None => EMPTY,
                    })
                    .collect()
            })
            .collect();
        witness_stream.extend(sorted_indices.write());

        let mut challenger = machine.config().challenger();
        challenger.observe(vk.commit);
        let reconstruct_challenger = challenger.clone();
        for proof in proof.shard_proofs.iter() {
            challenger.observe(proof.commitment.main_commit);
            let public_values = PublicValues::<Word<BabyBear>, BabyBear>::new(proof.public_values);
            challenger.observe_slice(&public_values.to_vec());
        }
        // Write current_challenger
        witness_stream.extend(challenger.write());
        // Write reconstruct_challenger
        witness_stream.extend(reconstruct_challenger.write());

        let ordering = vk.chip_ordering.clone();
        let chips = machine.chips();
        let (prep_sorted_indices, prep_domains): (
            Vec<usize>,
            Vec<TwoAdicMultiplicativeCoset<BabyBear>>,
        ) = machine
            .preprocessed_chip_ids()
            .into_iter()
            .map(|chip_idx| {
                let name = chips[chip_idx].name().clone();
                let prep_sorted_idx = ordering[&name];
                (prep_sorted_idx, vk.chip_information[prep_sorted_idx].1)
            })
            .unzip();
        // let prep_domains:
        //     Vec<TwoAdicMultiplicativeCoset<BabyBear>> = vk.chip_information[vk.chip_ordering.g]
        println!("prep_sorted_indices {:?}", prep_sorted_indices);
        // Write prep_sorted_indices
        witness_stream.extend(prep_sorted_indices.write());
        // Write prep_domains
        witness_stream.extend(prep_domains.write());
        // Write sp1_vk
        witness_stream.extend(vk.write());
        // Write recursion_vk
        // TODO: real recursion_vk
        witness_stream.extend(vk.write());

        let machine = InnerA::machine(config);
        let mut runtime =
            Runtime::<InnerF, InnerEF, _>::new(&reduce_program, machine.config().perm.clone());

        runtime.witness_stream = witness_stream;
        let time = Instant::now();
        runtime.run();
        let elapsed = time.elapsed();
        runtime.print_stats();
        println!("Execution took: {:?}", elapsed);
        let config = BabyBearPoseidon2::new();
        let machine = RecursionAir::machine(config);
        let (pk, vk) = machine.setup(&reduce_program);
        let mut challenger = machine.config().challenger();
        let record_clone = runtime.record.clone();
        machine.debug_constraints(&pk, record_clone, &mut challenger);
        let start = Instant::now();
        let mut challenger = machine.config().challenger();
        let proof = machine.prove::<LocalProver<_, _>>(&pk, runtime.record, &mut challenger);
        let duration = start.elapsed().as_secs();
        // let mut challenger = machine.config().challenger();
        // machine.verify(&vk, &proof, &mut challenger).unwrap();
        println!("proving duration = {}", duration);
        proof.shard_proofs
    }

    fn reduce(proofs: Vec<ShardProof<InnerSC>>) -> ShardProof<InnerSC> {
        todo!()
    }
}
pub fn prove_sp1() -> (Proof<InnerSC>, VerifyingKey<InnerSC>) {
    let elf = include_bytes!("../../examples/fibonacci-io/program/elf/riscv32im-succinct-zkvm-elf");
    let config = InnerSC::default();
    let machine = RiscvAir::machine(config.clone());
    let program = Program::from(elf);
    let stdin = [bincode::serialize::<u32>(&6).unwrap()];
    let (_, vk) = machine.setup(&program);
    let (proof, _) = run_and_prove(program, &stdin, config);
    let mut challenger_ver = machine.config().challenger();
    machine.verify(&vk, &proof, &mut challenger_ver).unwrap();
    println!("Proof generated successfully");
    (proof, vk)
}
pub fn prove_compress(sp1_proof: Proof<InnerSC>, vk: VerifyingKey<InnerSC>) {
    let program = build_reduce(vk.chip_information.clone());
    todo!()
    // let config = InnerSC::default();
    // let machine = InnerA::machine(config);
    // let mut runtime = Runtime::<InnerF, InnerEF, _>::new(&program, machine.config().perm.clone());
    // runtime.witness_stream = witness_stream;
    // let time = Instant::now();
    // runtime.run();
    // let elapsed = time.elapsed();
    // runtime.print_stats();
    // println!("Execution took: {:?}", elapsed);
    // let config = BabyBearPoseidon2::new();
    // let machine = RecursionAir::machine(config);
    // let (pk, vk) = machine.setup(&program);
    // let mut challenger = machine.config().challenger();
    // let record_clone = runtime.record.clone();
    // machine.debug_constraints(&pk, record_clone, &mut challenger);
    // let start = Instant::now();
    // let mut challenger = machine.config().challenger();
    // let proof = machine.prove::<LocalProver<_, _>>(&pk, runtime.record, &mut challenger);
    // let duration = start.elapsed().as_secs();
    // let mut challenger = machine.config().challenger();
    // machine.verify(&vk, &proof, &mut challenger).unwrap();
    // println!("proving duration = {}", duration);
}
pub fn prove_reduce() {}
pub fn prove_snark() {}
#[cfg(test)]
mod tests {
    use super::*;
    use sp1_core::utils::setup_logger;
    #[test]
    fn test_prove_sp1() {
        setup_logger();
        let elf =
            include_bytes!("../../examples/fibonacci-io/program/elf/riscv32im-succinct-zkvm-elf");
        let stdin = [bincode::serialize::<u32>(&6).unwrap()];
        let proof = SP1ProverImpl::prove(elf, &stdin);
        let compressed_proof = SP1ProverImpl::compress(elf, proof);
    }
}
