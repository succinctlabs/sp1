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

use p3_air::PairCol;
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;

use sp1_core::air::MachineAir;
use sp1_core::alu::AddChip;
use sp1_core::stark::{Chip, RiscvAir};

#[proc_macro]
pub fn const_riscv_stark(_input: TokenStream) -> TokenStream {
    let mut tokens = TokenStream2::new();

    let values = vec![1u32, 2, 4, 5, 6]
        .into_iter()
        .map(BabyBear::from_canonical_u32)
        .map(|x| x.as_token())
        .collect::<Vec<_>>();

    let chip = Chip::<BabyBear, _>::new(RiscvAir::Add(AddChip));

    let air_type = riscv_air_type::<BabyBear>();
    let air_token = quote! { crate::stark::RiscvAir::Add(crate::stark::AddChip) };

    let chip_name = chip.name().to_uppercase();
    let chip_ident = Ident::new(&chip_name, proc_macro2::Span::call_site());
    chip_token(
        &chip_ident,
        &air_token,
        &air_type,
        chip.sends(),
        chip.receives(),
        chip.log_quotient_degree(),
        &mut tokens,
    );

    let sends = chip.sends();

    let interaction = &sends[0];

    let interaction_ident = Ident::new("SEND_INTERACTION", proc_macro2::Span::call_site());

    interaction_token(interaction, &interaction_ident, &mut tokens);

    let pair_col = pair_col_token(&PairCol::Main(3));

    // Let's try to make a const slice from the values vector, making it general for any such
    // vector
    let test_consts = quote! {
        pub const VALUES: &[p3_baby_bear::BabyBear] = &[#(#values),*];

        pub const PAIR_COL : p3_air::PairCol = #pair_col;
    };

    tokens.extend(test_consts);

    tokens.into()
}
