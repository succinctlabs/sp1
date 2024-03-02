extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;

mod baby_bear;
mod chip;
mod config;
mod field;
mod interaction;
mod riscv_air;
mod virtual_column;

use chip::*;
use config::*;
use field::*;
use interaction::*;
use riscv_air::*;
use virtual_column::*;

use proc_macro2::Ident;

use sp1_recursion::baby_bear::BabyBear;

use sp1_recursion::air::MachineAir;
use sp1_recursion::stark::{Chip, RiscvAir};
use sp1_recursion::utils::BabyBearBlake3;

#[proc_macro]
pub fn const_riscv_stark(_input: TokenStream) -> TokenStream {
    type F = BabyBear;
    let mut tokens = TokenStream2::new();

    let airs = RiscvAir::<F>::get_all();

    // Add a constant for each chip, and collect tokens for putting them in a slice.
    let air_type = riscv_air_type::<F>();
    let mut chip_tokens = vec![];
    for (i, air) in airs.into_iter().enumerate() {
        let air_token = quote! {crate::stark::RiscvAir::get_air_at_index(#i) };
        let chip = Chip::<F, _>::new(air);

        let name = chip.name().to_uppercase();
        let chip_ident = Ident::new(&name, proc_macro2::Span::call_site());
        chip_token(
            &chip_ident,
            &air_token,
            &air_type,
            chip.sends(),
            chip.receives(),
            chip.log_quotient_degree(),
            &mut tokens,
        );
        chip_tokens.push(quote! { #chip_ident });
    }

    // Generate a constant for the slice of chips
    let chips_ident = Ident::new("RISCV_CHIPS", proc_macro2::Span::call_site());
    let field = F::get_type();
    tokens.extend(quote! {
        pub const #chips_ident : &[crate::stark::Chip< #field, #air_type >] = &[#(#chip_tokens),*];
    });

    // get the const tokens for making the config
    type SC = BabyBearBlake3;
    let config_type = SC::get_type();
    let config = BabyBearBlake3::new();
    let config_token = config.as_token();

    // Generate a constant machine from the config and chip slice
    let machine_ident = Ident::new("RISCV_STARK", proc_macro2::Span::call_site());
    tokens.extend(quote! {
        pub const #machine_ident : crate::stark::RiscvStark< #config_type > =
            crate::stark::RiscvStark::from_chip_slice(#config_token, #chips_ident);
    });

    tokens.into()
}
