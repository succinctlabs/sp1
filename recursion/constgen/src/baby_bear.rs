use super::ConfigToken;
use crate::field::FieldToken;
use proc_macro2::TokenStream;
use sp1_recursion::baby_bear::BabyBear;
use sp1_recursion::utils::BabyBearBlake3;
use syn::Path;

use quote::quote;

use p3_field::PrimeField32;

impl FieldToken for BabyBear {
    fn get_type() -> Path {
        syn::parse_str("sp1_recursion::baby_bear::BabyBear").expect("Failed to parse type path")
    }

    fn as_token(&self) -> TokenStream {
        let value = self.as_canonical_u32();
        quote! { sp1_recursion::baby_bear::BabyBear::new(#value) }
    }
}

impl ConfigToken for BabyBearBlake3 {
    fn get_type() -> Path {
        syn::parse_str("sp1_recursion::utils::BabyBearBlake3").expect("Failed to parse type path")
    }

    fn as_token(&self) -> TokenStream {
        quote! { crate::utils::BabyBearBlake3::new() }
    }
}
