// use p3_air::Air;
// use p3_field::extension::BinomialExtensionField;
// use p3_field::{AbstractExtensionField, AbstractField};
// use sp1_core::air::MachineAir;
// use sp1_core::stark::{MachineChip, StarkGenericConfig, VerifierConstraintFolder};
// use sp1_core::utils::BabyBearPoseidon2;
// use sp1_recursion_compiler::asm::VmBuilder;
// use sp1_recursion_compiler::ir::{Ext, Felt, SymbolicExt, SymbolicFelt};
// use sp1_recursion_core::runtime::Runtime;
// use std::marker::PhantomData;

// pub struct ChipOpenedValues<F, EF> {
//     pub quotient: Vec<Ext<F, EF>>,
// }

// fn f<SC: StarkGenericConfig, A: MachineAir<SC::Val>>(chip: MachineChip<SC, A>)
// where
//     A: for<'a> Air<VerifierConstraintFolder<'a, SC::Val, SymbolicExt<SC::Val, SC::Challenge>>>,
// {
//     let mut builder = VmBuilder::<SC::Val, SC::Challenge>::default();

//     let opening = ChipOpenedValues::<SC::Val, SC::Challenge> { quotient: vec![] };

//     let g: Felt<_> = builder.uninit();
//     let zeta: Ext<_, _> = builder.uninit();
//     let alpha: Ext<_, _> = builder.uninit();
//     let permutation_challenges: Vec<Ext<_, _>> = vec![
//         builder.uninit(),
//         builder.uninit(),
//         builder.uninit(),
//         builder.uninit(),
//     ];

//     let one: Felt<_> = builder.eval(SC::Val::one());
//     let g_inv = one / g;
//     let g_inv_ext: SymbolicExt<SC::Val, SC::Challenge> = SymbolicExt::Base(g_inv.into());
//     let z_h: Ext<_, _> = builder.eval(zeta - SC::Challenge::one());
//     let is_first_row: Ext<_, _> = builder.eval(z_h / (zeta - SC::Challenge::one()));
//     let is_last_row: Ext<_, _> = builder.eval(z_h / zeta);

//     let monomials: Vec<Ext<_, _>> = (0..SC::Challenge::D)
//         .map(|i| builder.eval(<SC::Challenge as AbstractExtensionField<SC::Val>>::monomial(i)))
//         .collect::<Vec<_>>();

//     let zero: Ext<_, _> = builder.eval(SC::Challenge::zero());
//     let zero: SymbolicExt<SC::Val, SC::Challenge> = zero.into();
//     let quotient_parts = opening
//         .quotient
//         .chunks_exact(SC::Challenge::D)
//         .map(|chunk| {
//             chunk
//                 .iter()
//                 .zip(monomials.iter())
//                 .map(|(x, m)| *x * *m)
//                 .fold(zero.clone(), |acc, x| x + acc)
//         })
//         .collect::<Vec<_>>();

//     let zeta_pow: Ext<_, _> = builder.eval(SC::Challenge::one());
//     let mut zeta_pow: SymbolicExt<SC::Val, SC::Challenge> = zeta_pow.into();
//     let quotient = quotient_parts
//         .into_iter()
//         .map(|qp| {
//             let res = zeta_pow.clone() * qp;
//             zeta_pow = zeta_pow.clone() * zeta;
//             res
//         })
//         .fold(zero.clone(), |acc, x| x + acc);

//     let mut folder: VerifierConstraintFolder<SC::Val, SymbolicExt<SC::Val, SC::Challenge>>;
//     // chip.eval(&mut folder);
// }

fn main() {
    println!("Hello, world!");
}
