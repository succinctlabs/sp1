use proc_macro2::TokenStream;
use sp1_core::stark::StarkGenericConfig;
use syn::Path;
pub trait ConfigToken: StarkGenericConfig {
    fn get_type() -> Path;
    
    fn as_token(&self) -> TokenStream;
}
