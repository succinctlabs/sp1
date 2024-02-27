use super::FieldToken;
use proc_macro2::TokenStream;

use crate::virtual_pair_col_token;
use quote::quote;
use sp1_core::lookup::{Interaction, InteractionKind};
use syn::Ident;

pub fn kind_token(value: &InteractionKind) -> TokenStream {
    match value {
        InteractionKind::Memory => quote! { crate::lookup::InteractionKind::Memory },
        InteractionKind::Program => quote! { crate::lookup::InteractionKind::Program },
        InteractionKind::Instruction => quote! { crate::lookup::InteractionKind::Instruction },
        InteractionKind::Alu => quote! { crate::lookup::InteractionKind::Alu },
        InteractionKind::Byte => quote! { crate::lookup::InteractionKind::Byte },
        InteractionKind::Range => quote! { crate::lookup::InteractionKind::Range },
        InteractionKind::Field => quote! { crate::lookup::InteractionKind::Field },
    }
}

pub fn interaction_token<F: FieldToken>(
    value: &Interaction<F>,
    name: &Ident,
    stream: &mut TokenStream,
) {
    // Add constants for the multiplicity
    let mult_ident = Ident::new(&format!("MULT_{}", name), proc_macro2::Span::call_site());
    virtual_pair_col_token(&value.multiplicity, &mult_ident, stream);

    // Add constants for the values, and collect tokens for putting them in a slice.
    let mut values = vec![];
    for (i, value) in value.values.iter().enumerate() {
        let value_ident = Ident::new(
            &format!("VALUE_{}_{}", i, name),
            proc_macro2::Span::call_site(),
        );
        virtual_pair_col_token(value, &value_ident, stream);
        values.push(quote! { #value_ident });
    }
    // Generate a constant for the slice of values
    let values_ident = Ident::new(&format!("VALUES_{}", name), proc_macro2::Span::call_site());
    let field = F::get_type();
    stream.extend(
        quote! { pub const #values_ident : &[p3_air::VirtualPairCol< #field >] = &[#(#values),*]; },
    );

    // Get token for the kind
    let kind = kind_token(&value.kind);

    // Finally, generate a constant for the interaction
    stream.extend(quote! {
        pub const #name : crate::lookup::Interaction< #field > =
            crate::lookup::Interaction {
                values: alloc::borrow::Cow::Borrowed(#values_ident),
                multiplicity: #mult_ident,
                kind: #kind,
            };
    });
}
