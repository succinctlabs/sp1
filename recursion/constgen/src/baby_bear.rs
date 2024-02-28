use super::ConfigToken;
use crate::field::FieldToken;
use p3_baby_bear::BabyBear;
use proc_macro2::TokenStream;
use sp1_core::utils::BabyBearBlake3;
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

impl ConfigToken for BabyBearBlake3 {
    fn get_type() -> Path {
        syn::parse_str("crate::utils::BabyBearBlake3").expect("Failed to parse type path")
    }

    fn as_token(&self) -> TokenStream {
        quote! { p3_baby_bear::BabyBearBlake3::new() }
    }
}
