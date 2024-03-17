use std::fs::File;
use std::marker::PhantomData;

use p3_air::Air;
use p3_air::TwoRowMatrixView;
use p3_baby_bear::BabyBear;
use p3_field::extension::BinomialExtensionField;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use sp1_core::air::MachineAir;
use sp1_core::stark::AirOpenedValues;
use sp1_core::stark::ChipOpenedValues;
use sp1_core::stark::RiscvAir;
use sp1_core::stark::{GenericVerifierConstraintFolder, MachineChip, StarkGenericConfig};
use sp1_core::utils;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_core::SP1Prover;
use sp1_core::SP1Stdin;
use sp1_recursion_compiler::asm::AsmConfig;
use sp1_recursion_compiler::asm::VmBuilder;
use sp1_recursion_compiler::gnark::GnarkBackend;
use sp1_recursion_compiler::ir::{Ext, Felt, SymbolicExt};
use sp1_recursion_compiler::prelude::Config;
use std::collections::HashMap;
use std::io::Write;

#[allow(clippy::type_complexity)]
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
#[allow(unused_variables)]
fn verify_constraints<SC: StarkGenericConfig, A: MachineAir<SC::Val>>(
    builder: &mut VmBuilder<SC::Val, SC::Challenge>,
    chip: &MachineChip<SC, A>,
    opening: &ChipOpenedValues<SC::Challenge>,
    g: Felt<SC::Val>,
    zeta: Ext<SC::Val, SC::Challenge>,
    alpha: Ext<SC::Val, SC::Challenge>,
    permutation_challenges: &[Ext<SC::Val, SC::Challenge>],
) where
    A: for<'a> Air<
        GenericVerifierConstraintFolder<
            'a,
            SC::Val,
            SC::Challenge,
            Ext<SC::Val, SC::Challenge>,
            SymbolicExt<SC::Val, SC::Challenge>,
        >,
    >,
{
    println!("got here 1");
    let g_inv: Felt<SC::Val> = builder.eval(g / SC::Val::one());
    println!("got here 2");
    let z_h: Ext<SC::Val, SC::Challenge> = builder.exp_power_of_2(zeta, opening.log_degree);
    println!("got here 3");
    let one: Ext<SC::Val, SC::Challenge> = builder.eval(SC::Val::one());
    let is_first_row = builder.eval(z_h / (zeta - one));
    println!("got here 4");
    let is_last_row = builder.eval(z_h / (zeta - g_inv));
    let is_transition = builder.eval(zeta - g_inv);

    println!("got here 2");

    let preprocessed = AirOpenedValues::<Ext<SC::Val, SC::Challenge>> {
        local: opening
            .preprocessed
            .local
            .iter()
            .map(|s| {
                let t: Ext<SC::Val, SC::Challenge> = builder.uninit();
                builder.assign(t, SymbolicExt::Const(*s));
                t
            })
            .collect::<Vec<_>>(),
        next: opening
            .preprocessed
            .next
            .iter()
            .map(|s| {
                let t: Ext<SC::Val, SC::Challenge> = builder.uninit();
                builder.assign(t, SymbolicExt::Const(*s));
                t
            })
            .collect::<Vec<_>>(),
    };
    let main = AirOpenedValues::<Ext<SC::Val, SC::Challenge>> {
        local: opening
            .main
            .local
            .iter()
            .map(|s| {
                let t: Ext<SC::Val, SC::Challenge> = builder.uninit();
                builder.assign(t, SymbolicExt::Const(*s));
                t
            })
            .collect::<Vec<_>>(),
        next: opening
            .main
            .next
            .iter()
            .map(|s| {
                let t: Ext<SC::Val, SC::Challenge> = builder.uninit();
                builder.assign(t, SymbolicExt::Const(*s));
                t
            })
            .collect::<Vec<_>>(),
    };
    let perm = AirOpenedValues::<Ext<SC::Val, SC::Challenge>> {
        local: opening
            .permutation
            .local
            .iter()
            .map(|s| {
                let t: Ext<SC::Val, SC::Challenge> = builder.uninit();
                builder.assign(t, SymbolicExt::Const(*s));
                t
            })
            .collect::<Vec<_>>(),
        next: opening
            .permutation
            .next
            .iter()
            .map(|s| {
                let t: Ext<SC::Val, SC::Challenge> = builder.uninit();
                builder.assign(t, SymbolicExt::Const(*s));
                t
            })
            .collect::<Vec<_>>(),
    };

    let zero: Ext<SC::Val, SC::Challenge> = builder.eval(SC::Val::zero());
    let zero_expr: SymbolicExt<SC::Val, SC::Challenge> = zero.into();
    let mut folder = GenericVerifierConstraintFolder::<
        SC::Val,
        SC::Challenge,
        Ext<SC::Val, SC::Challenge>,
        SymbolicExt<SC::Val, SC::Challenge>,
    > {
        preprocessed: preprocessed.view(),
        main: main.view(),
        perm: perm.view(),
        perm_challenges: &[SC::Challenge::zero(), SC::Challenge::zero()],
        cumulative_sum: builder.eval(SC::Val::zero()),
        is_first_row,
        is_last_row,
        is_transition,
        alpha,
        accumulator: zero_expr,
        _marker: PhantomData,
    };
    folder.is_first_row = is_first_row;
    folder.is_last_row = is_last_row;
    folder.is_transition = is_transition;

    println!("got here 3");
    let monomials = (0..SC::Challenge::D)
        .map(SC::Challenge::monomial)
        .collect::<Vec<_>>();
    println!("{}", monomials.len());

    println!("got here 4");
    let quotient_parts = opening
        .quotient
        .chunks_exact(SC::Challenge::D)
        .map(|chunk| {
            chunk
                .iter()
                .zip(monomials.iter())
                .map(|(x, m)| *x * *m)
                .sum()
        })
        .collect::<Vec<SC::Challenge>>();

    println!("wtf");
    let mut zeta_powers = zeta;
    let quotient: Ext<SC::Val, SC::Challenge> = builder.eval(SC::Val::zero());
    let quotient_expr: SymbolicExt<SC::Val, SC::Challenge> = quotient.into();
    for quotient_part in quotient_parts {
        zeta_powers = builder.eval(zeta_powers * zeta);
        builder.assign(quotient, zeta_powers * quotient_part);
    }
    let quotient: Ext<SC::Val, SC::Challenge> = builder.eval(quotient_expr);
    folder.alpha = alpha;

    chip.eval(&mut folder);
    let folded_constraints = folder.accumulator;
    let expected_folded_constraints = z_h * quotient;
    builder.assert_ext_eq(folded_constraints, expected_folded_constraints);
}

fn main() {
    utils::setup_logger();
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    let elf =
        include_bytes!("../../../examples/cycle-tracking/program/elf/riscv32im-succinct-zkvm-elf");
    let proofs = SP1Prover::prove(elf, SP1Stdin::new())
        .unwrap()
        .proof
        .shard_proofs;
    let proof = &proofs[0];
    let machine = RiscvAir::machine(SC::new());
    let chips = machine
        .chips()
        .iter()
        .filter(|chip| proof.chip_ids.contains(&chip.name()))
        .collect::<Vec<_>>();
    let chip = chips[0];
    let opened_values = &proof.opened_values.chips[0];
    let mut builder = VmBuilder::<F, EF>::default();

    let g: Felt<F> = builder.eval(F::one());
    let zeta: Ext<F, EF> = builder.eval(F::one());
    let alpha: Ext<F, EF> = builder.eval(F::one());

    println!("broo");
    verify_constraints::<SC, _>(&mut builder, chip, opened_values, g, zeta, alpha, &[]);

    #[derive(Clone)]
    struct BabyBearConfig;

    impl Config for BabyBearConfig {
        type N = BabyBear;
        type F = BabyBear;
        type EF = BinomialExtensionField<BabyBear, 4>;
    }

    let mut backend = GnarkBackend::<AsmConfig<F, EF>> {
        nb_backend_vars: 0,
        used: HashMap::new(),
        phantom: PhantomData,
    };
    let result = backend.compile(builder.operations);
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{}/src/gnark/lib/main.go", manifest_dir);
    let mut file = File::create(path).unwrap();
    file.write_all(result.as_bytes()).unwrap();
}
