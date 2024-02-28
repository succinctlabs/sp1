use super::FieldToken;
use proc_macro2::TokenStream;
use sp1_core::lookup::Interaction;

use crate::interaction_token;
use quote::quote;
use sp1_core::air::MachineAir;
use sp1_core::stark::Chip;
use syn::Ident;
use syn::Path;

pub fn chip_token<F: FieldToken>(
    name: &Ident,
    air: &TokenStream,
    air_type: &TokenStream,
    sends: &[Interaction<F>],
    receives: &[Interaction<F>],
    log_quotient_degree: usize,
    stream: &mut TokenStream,
) {
    let field = F::get_type();
    // Generate constants for the sends
    let mut send_tokens = vec![];
    for (i, send) in sends.iter().enumerate() {
        let send_ident = Ident::new(
            &format!("SEND_{}_{}", i, name),
            proc_macro2::Span::call_site(),
        );
        interaction_token(send, &send_ident, stream);
        send_tokens.push(quote! { #send_ident });
    }
    // Generate a constant for the slice of sends
    let sends_ident = Ident::new(&format!("SENDS_{}", name), proc_macro2::Span::call_site());
    stream.extend(quote! {
        pub const #sends_ident : &[crate::lookup::Interaction< #field >] = &[#(#send_tokens),*];
    });

    // Generate constants for the receives
    let mut receive_tokens = vec![];
    for (i, receive) in receives.iter().enumerate() {
        let receive_ident = Ident::new(
            &format!("RECEIVE_{}_{}", i, name),
            proc_macro2::Span::call_site(),
        );
        interaction_token(receive, &receive_ident, stream);
        receive_tokens.push(quote! { #receive_ident });
    }
    // Generate a constant for the slice of receives
    let receives_ident = Ident::new(
        &format!("RECEIVES_{}", name),
        proc_macro2::Span::call_site(),
    );
    stream.extend(quote! {
        pub const #receives_ident : &[crate::lookup::Interaction< #field >] = &[#(#receive_tokens),*];
    });

    // Finally, generate a constant for the chip
    stream.extend(quote! {
        pub const #name : crate::stark::Chip< #field, #air_type > =
            crate::stark::Chip::from_parts_borrowed(
                #air,
                #sends_ident,
                #receives_ident,
                #log_quotient_degree,
            );
    });
}
