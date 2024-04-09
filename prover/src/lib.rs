#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![allow(deprecated)]
use sp1_core::{
    runtime::Program,
    stark::{LocalProver, Proof, RiscvAir, ShardProof, StarkGenericConfig, VerifyingKey},
    utils::{run_and_prove, BabyBearPoseidon2},
    SP1Stdin,
};
use sp1_recursion_core::{runtime::Runtime, stark::RecursionAir};
use sp1_recursion_program::compress::build_compress;
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
        println!("nb_shards {}", proof.shard_proofs.len());
        let (program, witness_stream) = build_compress(proof, vk);
        let config = InnerSC::default();
        let machine = InnerA::machine(config);
        let mut runtime =
            Runtime::<InnerF, InnerEF, _>::new(&program, machine.config().perm.clone());
        runtime.witness_stream = witness_stream;
        let time = Instant::now();
        runtime.run();
        let elapsed = time.elapsed();
        runtime.print_stats();
        println!("Execution took: {:?}", elapsed);
        let config = BabyBearPoseidon2::new();
        let machine = RecursionAir::machine(config);
        let (pk, vk) = machine.setup(&program);
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
    let (program, witness_stream) = build_compress(sp1_proof, vk);
    let config = InnerSC::default();
    let machine = InnerA::machine(config);
    let mut runtime = Runtime::<InnerF, InnerEF, _>::new(&program, machine.config().perm.clone());
    runtime.witness_stream = witness_stream;
    let time = Instant::now();
    runtime.run();
    let elapsed = time.elapsed();
    runtime.print_stats();
    println!("Execution took: {:?}", elapsed);
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
