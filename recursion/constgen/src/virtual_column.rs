use super::FieldToken;
use proc_macro2::TokenStream;

use quote::quote;

use p3_air::{PairCol, VirtualPairCol};
use syn::Ident;

pub fn pair_col_token(value: &PairCol) -> TokenStream {
    match value {
        PairCol::Preprocessed(v) => quote! { p3_air::PairCol::Virtual(#v) },
        PairCol::Main(v) => quote! { p3_air::PairCol::Main(#v) },
    }
}

pub fn virtual_pair_col_token<F: FieldToken>(
    value: &VirtualPairCol<F>,
    name: &Ident,
    stream: &mut TokenStream,
) {
    let field = F::get_type();
    let constant = value.get_constant().as_token();

    let column_weights = value.get_column_weights().iter().map(|(col, val)| {
        let col = pair_col_token(col);
        let val = val.as_token();
        quote! { (#col, #val) }
    });

    let column_weights_ident = Ident::new(
        &format!("COLUMN_WEIGHTS_{}", name),
        proc_macro2::Span::call_site(),
    );

    let column_weights = quote! { pub const #column_weights_ident : &[(p3_air::PairCol, #field )]
    =  &[#(#column_weights),*]; };

    stream.extend(column_weights);

    let virtual_col = quote! {
    pub const #name : p3_air::VirtualPairCol< #field > =
        p3_air::VirtualPairCol::new_borrowed(#column_weights_ident, #constant ); };

    stream.extend(virtual_col);
}
