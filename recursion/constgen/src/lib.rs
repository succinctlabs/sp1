// The `aligned_borrow_derive` macro is taken from valida-xyz/valida under MIT license
//
// The MIT License (MIT)
//
// Copyright (c) 2023 The Valida Authors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;

mod baby_bear;
mod field;
mod interaction;
mod virtual_column;

use baby_bear::*;
use field::*;
use interaction::*;
use sp1_core::lookup::Interaction;
use virtual_column::*;

use proc_macro2::Ident;

use p3_air::PairCol;
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;

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
