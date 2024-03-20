use std::marker::PhantomData;

use p3_air::Air;
use p3_field::AbstractField;
use p3_field::Field;
use rand::thread_rng;
use rand::Rng;
use sp1_core::air::MachineAir;
use sp1_core::stark::ChipOpenedValues;
use sp1_core::stark::MachineChip;
use sp1_core::stark::RiscvAir;
use sp1_core::stark::StarkAir;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::stark::VerifierConstraintFolder;
use sp1_core::utils;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_core::SP1Prover;
use sp1_core::SP1Stdin;
use sp1_recursion_compiler::asm::VmBuilder;
use sp1_recursion_compiler::ir::ExtConst;
use sp1_recursion_compiler::ir::{Ext, Felt};
use sp1_recursion_core::runtime::Runtime;

pub fn eval_constraints<SC, A>(
    chip: &MachineChip<SC, A>,
    opening: &ChipOpenedValues<SC::Challenge>,
    g: SC::Val,
    zeta: SC::Challenge,
    alpha: SC::Challenge,
) -> SC::Challenge
where
    SC: StarkGenericConfig,
    A: MachineAir<SC::Val> + StarkAir<SC>,
{
    let g_inv = g.inverse();
    let z_h = zeta.exp_power_of_2(opening.log_degree);
    let one = SC::Val::one();
    let is_first_row = z_h / (zeta - one);
    let is_last_row = z_h / (zeta - g_inv);
    let is_transition = zeta - g_inv;

    let mut folder = VerifierConstraintFolder::<SC> {
        preprocessed: opening.preprocessed.view(),
        main: opening.main.view(),
        perm: opening.permutation.view(),
        perm_challenges: &[SC::Challenge::one(), SC::Challenge::one()],
        cumulative_sum: SC::Challenge::zero(),
        is_first_row,
        is_last_row,
        is_transition,
        alpha,
        accumulator: SC::Challenge::zero(),
        _marker: PhantomData,
    };

    // let monomials = (0..SC::Challenge::D)
    //     .map(SC::Challenge::monomial)
    //     .collect::<Vec<_>>();

    chip.eval(&mut folder);
    folder.accumulator
}

fn main() {
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;

    let mut rng = thread_rng();

    // Generate a dummy proof.
    utils::setup_logger();
    let elf =
        include_bytes!("../../../examples/cycle-tracking/program/elf/riscv32im-succinct-zkvm-elf");
    let proofs = SP1Prover::prove(elf, SP1Stdin::new())
        .unwrap()
        .proof
        .shard_proofs;
    let proof = &proofs[0];

    // Extract verification metadata.
    let machine = RiscvAir::machine(SC::new());
    let chips = machine
        .chips()
        .iter()
        .filter(|chip| proof.chip_ids.contains(&chip.name()))
        .collect::<Vec<_>>();
    let chip = chips[0];
    let opened_values = &proof.opened_values.chips[0];

    // Run the verify inside the DSL.
    let mut builder = VmBuilder::<F, EF>::default();
    let g_val = F::one();

    let zeta_val = rng.gen::<EF>();
    let alpha_val = rng.gen::<EF>();
    // let constraint_eval =
    //     eval_constraints::<SC, _>(chip, opened_values, g_val, zeta_val, alpha_val);

    let g: Felt<F> = builder.eval(F::one());

    let zeta: Ext<F, EF> = builder.eval(zeta_val.cons());
    let alpha: Ext<F, EF> = builder.eval(alpha_val.cons());

    builder.eval_constraints_test::<SC, _>(chip, opened_values, g_val, zeta_val, alpha_val);

    // builder.assert_ext_eq(constraint_eval.cons(), vm_value);

    let program = builder.compile();
    println!("Program size = {}", program.instructions.len());

    let mut runtime = Runtime::<F, EF>::new(&program);
    runtime.run();
}
