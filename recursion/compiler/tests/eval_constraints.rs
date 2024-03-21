use std::marker::PhantomData;

use sp1_core::stark::VerifierConstraintFolder;
use sp1_recursion_compiler::ir::Ext;
use sp1_recursion_compiler::ir::Felt;
use sp1_recursion_compiler::prelude::Builder;

use p3_air::Air;
use p3_field::AbstractField;
use p3_field::Field;
use p3_field::PrimeField32;
use rand::thread_rng;
use rand::Rng;
use sp1_core::air::MachineAir;
use sp1_core::stark::ChipOpenedValues;
use sp1_core::stark::MachineChip;
use sp1_core::stark::RiscvAir;
use sp1_core::stark::StarkAir;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_core::SP1Prover;
use sp1_core::SP1Stdin;
use sp1_recursion_compiler::asm::VmBuilder;
use sp1_recursion_compiler::ir::Config;
use sp1_recursion_compiler::ir::ExtConst;
use sp1_recursion_compiler::verifier::folder::RecursiveVerifierConstraintFolder;
use sp1_recursion_core::runtime::Runtime;

pub fn eval_constraints_test<C, SC, A>(
    builder: &mut Builder<C>,
    chip: &MachineChip<SC, A>,
    opening: &ChipOpenedValues<SC::Challenge>,
    g_val: SC::Val,
    zeta_val: SC::Challenge,
    alpha_val: SC::Challenge,
) where
    SC: StarkGenericConfig,
    C: Config<F = SC::Val, EF = SC::Challenge>,
    A: MachineAir<SC::Val> + StarkAir<SC> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
{
    let g_inv_val = g_val.inverse();
    let g: Felt<_> = builder.eval(g_val);
    let g_inv: Felt<SC::Val> = builder.eval(g.inverse());
    builder.assert_felt_eq(g_inv, g_inv_val);

    let z_h_val = zeta_val.exp_power_of_2(opening.log_degree);
    let zeta: Ext<C::F, C::EF> = builder.eval(zeta_val.cons());
    let z_h: Ext<SC::Val, SC::Challenge> = builder.exp_power_of_2(zeta, opening.log_degree);
    builder.assert_ext_eq(z_h, z_h_val.cons());
    let one: Ext<SC::Val, SC::Challenge> = builder.eval(SC::Val::one());
    let is_first_row: Ext<_, _> = builder.eval(z_h / (zeta - one));
    let is_last_row: Ext<_, _> = builder.eval(z_h / (zeta - g_inv));
    let is_transition: Ext<_, _> = builder.eval(zeta - g_inv);

    let is_first_row_val = z_h_val / (zeta_val - SC::Challenge::one());
    let is_last_row_val = z_h_val / (zeta_val - g_inv_val);
    let is_transition_val = zeta_val - g_inv_val;

    builder.assert_ext_eq(is_first_row, is_first_row_val.cons());
    builder.assert_ext_eq(is_last_row, is_last_row_val.cons());
    builder.assert_ext_eq(is_transition, is_transition_val.cons());

    let preprocessed = builder.const_opened_values(&opening.preprocessed);
    let main = builder.const_opened_values(&opening.main);
    let perm = builder.const_opened_values(&opening.permutation);

    let zero: Ext<SC::Val, SC::Challenge> = builder.eval(SC::Val::zero());
    let cumulative_sum = builder.eval(SC::Val::zero());
    let alpha = builder.eval(alpha_val.cons());
    let mut folder = RecursiveVerifierConstraintFolder {
        builder,
        preprocessed: preprocessed.view(),
        main: main.view(),
        perm: perm.view(),
        perm_challenges: &[SC::Challenge::one(), SC::Challenge::one()],
        cumulative_sum,
        is_first_row,
        is_last_row,
        is_transition,
        alpha,
        accumulator: zero,
    };

    chip.eval(&mut folder);
    let folded_constraints = folder.accumulator;

    let mut test_folder = VerifierConstraintFolder::<SC> {
        preprocessed: opening.preprocessed.view(),
        main: opening.main.view(),
        perm: opening.permutation.view(),
        perm_challenges: &[SC::Challenge::one(), SC::Challenge::one()],
        cumulative_sum: SC::Challenge::zero(),
        is_first_row: is_first_row_val,
        is_last_row: is_last_row_val,
        is_transition: is_transition_val,
        alpha: alpha_val,
        accumulator: SC::Challenge::zero(),
        _marker: PhantomData,
    };

    chip.eval(&mut test_folder);
    let folded_constraints_val = test_folder.accumulator;

    builder.assert_ext_eq(folded_constraints, folded_constraints_val.cons());
}

#[test]
fn test_compiler_eval_constraints() {
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;

    let mut rng = thread_rng();

    // Generate a dummy proof.
    utils::setup_logger();
    let elf = include_bytes!("../../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    let proofs = SP1Prover::prove(elf, SP1Stdin::new())
        .unwrap()
        .proof
        .shard_proofs;

    println!("Proof generated successfully");

    // Extract verification metadata.
    let machine = RiscvAir::machine(SC::new());

    // Run the verify inside the DSL.
    let mut builder = VmBuilder::<F, EF>::default();
    let g_val = F::one();

    let zeta_val = rng.gen::<EF>();
    let alpha_val = rng.gen::<EF>();

    for shard_proof in proofs.into_iter().take(1) {
        let chips = machine
            .chips()
            .iter()
            .filter(|chip| shard_proof.chip_ids.contains(&chip.name()))
            .collect::<Vec<_>>();
        for (chip, values) in chips
            .into_iter()
            .zip(shard_proof.opened_values.chips.iter())
        {
            eval_constraints_test::<_, SC, _>(
                &mut builder,
                chip,
                values,
                g_val,
                zeta_val,
                alpha_val,
            )
        }
    }

    let program = builder.compile();

    let mut runtime = Runtime::<F, EF>::new(&program);
    runtime.run();
    println!(
        "The program executed successfully, number of cycles: {}",
        runtime.clk.as_canonical_u32() / 4
    );
}
