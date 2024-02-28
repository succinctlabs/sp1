use proc_macro2::TokenStream;
use quote::quote;

use crate::FieldToken;

pub fn riscv_air_type<F: FieldToken>() -> TokenStream {
    let field = F::get_type();
    quote! { crate::stark::RiscvAir::< #field > }
}
