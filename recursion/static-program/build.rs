use std::path::Path;

use p3_baby_bear::BabyBear;
use sp1_core::{
    stark::{DefaultProver, MachineProver, RiscvAir, StarkProvingKey, StarkVerifyingKey},
    utils::BabyBearPoseidon2,
};
use sp1_primitives::types::RecursionProgramType;
use sp1_recursion_compiler::config::InnerConfig;
use sp1_recursion_core::stark::RecursionAir;
use sp1_recursion_core::{runtime::RecursionProgram, stark::config::BabyBearPoseidon2Outer};
use sp1_recursion_program::machine::{
    SP1CompressVerifier, SP1DeferredVerifier, SP1RecursiveVerifier, SP1RootVerifier,
};

/// The configuration for the core prover.
type CoreSC = BabyBearPoseidon2;

/// The configuration for the inner prover.
type InnerSC = BabyBearPoseidon2;

/// The configuration for the outer prover.
type OuterSC = BabyBearPoseidon2Outer;

const REDUCE_DEGREE: usize = 3;
const COMPRESS_DEGREE: usize = 9;
const WRAP_DEGREE: usize = 17;

type ReduceAir<F> = RecursionAir<F, REDUCE_DEGREE>;
type CompressAir<F> = RecursionAir<F, COMPRESS_DEGREE>;
type WrapAir<F> = RecursionAir<F, WRAP_DEGREE>;

fn build_programs() -> (
    RecursionProgram<BabyBear>,
    StarkProvingKey<BabyBearPoseidon2>,
    StarkVerifyingKey<BabyBearPoseidon2>,
    RecursionProgram<BabyBear>,
    StarkProvingKey<BabyBearPoseidon2>,
    StarkVerifyingKey<BabyBearPoseidon2>,
    RecursionProgram<BabyBear>,
    StarkProvingKey<BabyBearPoseidon2>,
    StarkVerifyingKey<BabyBearPoseidon2>,
    RecursionProgram<BabyBear>,
    StarkProvingKey<BabyBearPoseidon2>,
    StarkVerifyingKey<BabyBearPoseidon2>,
    RecursionProgram<BabyBear>,
    StarkProvingKey<BabyBearPoseidon2Outer>,
    StarkVerifyingKey<BabyBearPoseidon2Outer>,
) {
    let core_machine = RiscvAir::machine(CoreSC::default());
    let core_prover = DefaultProver::new(core_machine);

    // Get the recursive verifier and setup the proving and verifying keys.
    let recursion_program = SP1RecursiveVerifier::<InnerConfig, _>::build(core_prover.machine());
    let compress_machine = ReduceAir::machine(InnerSC::default());
    let compress_prover = DefaultProver::new(compress_machine);
    let (rec_pk, rec_vk) = compress_prover.setup(&recursion_program);

    // Get the deferred program and keys.
    let deferred_program =
        SP1DeferredVerifier::<InnerConfig, _, _>::build(compress_prover.machine());
    let (deferred_pk, deferred_vk) = compress_prover.setup(&deferred_program);

    // Make the reduce program and keys.
    let compress_program = SP1CompressVerifier::<InnerConfig, _, _>::build(
        compress_prover.machine(),
        &rec_vk,
        &deferred_vk,
    );
    let (compress_pk, compress_vk) = compress_prover.setup(&compress_program);

    // Get the compress program, machine, and keys.
    let shrink_program = SP1RootVerifier::<InnerConfig, _, _>::build(
        compress_prover.machine(),
        &compress_vk,
        RecursionProgramType::Shrink,
    );
    let shrink_machine = CompressAir::wrap_machine_dyn(InnerSC::compressed());
    let shrink_prover = DefaultProver::new(shrink_machine);
    let (shrink_pk, shrink_vk) = shrink_prover.setup(&shrink_program);

    // Get the wrap program, machine, and keys.
    let wrap_program = SP1RootVerifier::<InnerConfig, _, _>::build(
        shrink_prover.machine(),
        &shrink_vk,
        RecursionProgramType::Wrap,
    );
    let wrap_machine = WrapAir::wrap_machine(OuterSC::default());
    let wrap_prover = DefaultProver::new(wrap_machine);
    let (wrap_pk, wrap_vk) = wrap_prover.setup(&wrap_program);

    (
        recursion_program,
        rec_pk,
        rec_vk,
        deferred_program,
        deferred_pk,
        deferred_vk,
        compress_program,
        compress_pk,
        compress_vk,
        shrink_program,
        shrink_pk,
        shrink_vk,
        wrap_program,
        wrap_pk,
        wrap_vk,
    )
}

fn main() {
    let (
        recursion_program,
        rec_pk,
        rec_vk,
        deferred_program,
        deferred_pk,
        deferred_vk,
        compress_program,
        compress_pk,
        compress_vk,
        shrink_program,
        shrink_pk,
        shrink_vk,
        wrap_program,
        wrap_pk,
        wrap_vk,
    ) = build_programs();

    // Write the programs to files.
    let output_dir = std::env::var("OUT_DIR").unwrap();
    let recursion_program_path = Path::new(&output_dir).join("RECURSION_program.bin");
    let rec_pk_path = Path::new(&output_dir).join("RECURSION_pk.bin");
    let rec_vk_path = Path::new(&output_dir).join("RECURSION_vk.bin");
    let deferred_program_path = Path::new(&output_dir).join("DEFERRED_program.bin");
    let deferred_pk_path = Path::new(&output_dir).join("DEFERRED_pk.bin");
    let deferred_vk_path = Path::new(&output_dir).join("DEFERRED_vk.bin");
    let compress_program_path = Path::new(&output_dir).join("COMPRESS_program.bin");
    let compress_pk_path = Path::new(&output_dir).join("COMPRESS_pk.bin");
    let compress_vk_path = Path::new(&output_dir).join("COMPRESS_vk.bin");
    let shrink_program_path = Path::new(&output_dir).join("SHRINK_program.bin");
    let shrink_pk_path = Path::new(&output_dir).join("SHRINK_pk.bin");
    let shrink_vk_path = Path::new(&output_dir).join("SHRINK_vk.bin");
    let wrap_program_path = Path::new(&output_dir).join("WRAP_program.bin");
    let wrap_pk_path = Path::new(&output_dir).join("WRAP_pk.bin");
    let wrap_vk_path = Path::new(&output_dir).join("WRAP_vk.bin");

    std::fs::write(
        recursion_program_path,
        bincode::serialize(&recursion_program).unwrap(),
    )
    .unwrap();
    std::fs::write(rec_pk_path, bincode::serialize(&rec_pk).unwrap()).unwrap();
    std::fs::write(rec_vk_path, bincode::serialize(&rec_vk).unwrap()).unwrap();
    std::fs::write(
        deferred_program_path,
        bincode::serialize(&deferred_program).unwrap(),
    )
    .unwrap();
    std::fs::write(deferred_pk_path, bincode::serialize(&deferred_pk).unwrap()).unwrap();
    std::fs::write(deferred_vk_path, bincode::serialize(&deferred_vk).unwrap()).unwrap();
    std::fs::write(
        compress_program_path,
        bincode::serialize(&compress_program).unwrap(),
    )
    .unwrap();
    std::fs::write(compress_pk_path, bincode::serialize(&compress_pk).unwrap()).unwrap();
    std::fs::write(compress_vk_path, bincode::serialize(&compress_vk).unwrap()).unwrap();
    std::fs::write(
        shrink_program_path,
        bincode::serialize(&shrink_program).unwrap(),
    )
    .unwrap();
    std::fs::write(shrink_pk_path, bincode::serialize(&shrink_pk).unwrap()).unwrap();
    std::fs::write(shrink_vk_path, bincode::serialize(&shrink_vk).unwrap()).unwrap();
    std::fs::write(
        wrap_program_path,
        bincode::serialize(&wrap_program).unwrap(),
    )
    .unwrap();
    std::fs::write(wrap_pk_path, bincode::serialize(&wrap_pk).unwrap()).unwrap();
    std::fs::write(wrap_vk_path, bincode::serialize(&wrap_vk).unwrap()).unwrap();
}
