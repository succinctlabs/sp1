use proc_macro2::TokenStream;
use syn::Path;

use p3_field::Field;

pub trait FieldToken: Field {
    fn get_type() -> Path;

    fn as_token(&self) -> TokenStream;
}
