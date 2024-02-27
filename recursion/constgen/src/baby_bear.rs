use crate::field::FieldToken;
use p3_baby_bear::BabyBear;
use proc_macro2::TokenStream;
use syn::Path;

use quote::quote;

use p3_field::PrimeField32;

impl FieldToken for BabyBear {
    fn get_type() -> Path {
        syn::parse_str("p3_baby_bear::BabyBear").expect("Failed to parse type path")
    }

    fn as_token(&self) -> TokenStream {
        let value = self.as_canonical_u32();
        quote! { p3_baby_bear::BabyBear::new(#value) }
    }
}
