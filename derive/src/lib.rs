use syn::parse_macro_input;

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemEnum, ItemFn};

#[proc_macro_attribute]
pub fn cycle_tracker(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);
    let visibility = &input.vis;
    let name = &input.sig.ident;
    let inputs = &input.sig.inputs;
    let output = &input.sig.output;
    let block = &input.block;
    let generics = &input.sig.generics;
    let where_clause = &input.sig.generics.where_clause;

    let result = quote! {
        #visibility fn #name #generics (#inputs) #output #where_clause {
            println!("cycle-tracker-start: {}", stringify!(#name));
            let result = (|| #block)();
            println!("cycle-tracker-end: {}", stringify!(#name));
            result
        }
    };

    result.into()
}

#[proc_macro_attribute]
pub fn chip_type_methods(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemEnum);
    let visibility = &input.vis;
    let name = &input.ident;
    let generics = &input.generics;
    let variants = &input.variants;

    let mut all_variants = variants.into_iter().map(|v| v.ident.clone());
    let all_variants_copy = all_variants.clone();

    let mut all_variant_types = variants
        .into_iter()
        .map(|v| match v.fields {
            syn::Fields::Unnamed(ref fields) => {
                let field = fields.unnamed.first().unwrap();
                field.ty.clone()
            }
            _ => panic!("Only unnamed fields are supported"),
        })
        .collect::<Vec<_>>();
    let all_variant_types_copy = all_variant_types.clone();

    let mut result = quote! {
        #visibility enum #name #generics {
            #variants
        }

        impl<F: PrimeField32> #name<F> {
            pub fn all_interactions(&self) -> Vec<Interaction<F>>
            {
                match &self {
                    #(#name::#all_variants(chip) => chip.all_interactions()),*
                }
            }
        }
    };

    all_variants = all_variants_copy.clone();
    result = quote! {
        #result

        impl<F: PrimeField32> #name<F> {
            pub fn sends(&self) -> Vec<Interaction<F>>
            {
                match &self {
                    #(#name::#all_variants(chip) => chip.sends()),*
                }
            }
        }
    };

    all_variants = all_variants_copy.clone();
    result = quote! {
        #result

        impl<F: PrimeField32> #name<F> {
            pub fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F>
            {
                match &self {
                    #(#name::#all_variants(chip) => chip.generate_trace(segment)),*
                }
            }
        }
    };

    all_variants = all_variants_copy.clone();
    result = quote! {
        #result

        impl<F: PrimeField32> #name<F> {
            pub fn name(&self) -> String
            {
                match &self {
                    #(#name::#all_variants(chip) => <#all_variant_types as Chip<F>>::name(chip)),*
                }
            }
        }
    };

    all_variants = all_variants_copy.clone();
    result = quote! {
        #result

        impl<F: PrimeField32> #name<F> {
            pub fn eval<AB: CurtaAirBuilder>(&self, builder: &mut AB)
            where
                 AB::F: ExtensionField<F>,
            {
                match &self {
                    #(#name::#all_variants(chip) => chip.eval(builder)),*
                }
            }
        }
    };

    all_variants = all_variants_copy.clone();
    all_variant_types = all_variant_types_copy.clone();
    result = quote! {
        #result

        impl<F: PrimeField32> #name<F> {
            pub fn air_width(&self) -> usize
            {
                match &self {
                    #(#name::#all_variants(chip) => <#all_variant_types as BaseAir<F>>::width(chip)),*
                }
            }
        }
    };

    all_variants = all_variants_copy.clone();
    result = quote! {
        #result

        impl<F: PrimeField32> #name<F> {
            pub fn preprocessed_trace(&self) ->  Option<RowMajorMatrix<F>>
            {
                match &self {
                    #(#name::#all_variants(chip) => chip.preprocessed_trace()),*
                }
            }
        }
    };

    result.into()
}
