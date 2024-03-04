use super::ConfigToken;
use crate::field::FieldToken;
use p3_baby_bear::BabyBear;
use proc_macro2::TokenStream;
use sp1_recursion_pcs::BabyBearBlake3Recursion;
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

impl ConfigToken for BabyBearBlake3Recursion {
    fn get_type() -> Path {
        syn::parse_str("sp1_recursion_pcs::BabyBearBlake3Recursion")
            .expect("Failed to parse type path")
    }

    fn as_token(&self) -> TokenStream {
        quote! { crate::BabyBearBlake3Recursion::new() }
    }
}
