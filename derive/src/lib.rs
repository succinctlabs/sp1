// The `aligned_borrow_derive` macro is taken from valida-xyz/valida under MIT license
//
// The MIT License (MIT)
//
// Copyright (c) 2023 The Valida Authors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::parse_macro_input;
use syn::ItemFn;

#[proc_macro_derive(AlignedBorrow)]
pub fn aligned_borrow_derive(input: TokenStream) -> TokenStream {
    let ast: syn::DeriveInput = syn::parse(input).unwrap();

    // Get struct name from ast
    let name = &ast.ident;
    let methods = quote! {
        impl<T> Borrow<#name<T>> for [T] {
            fn borrow(&self) -> &#name<T> {
                debug_assert_eq!(self.len(), size_of::<#name<u8>>());
                let (prefix, shorts, _suffix) = unsafe { self.align_to::<#name<T>>() };
                debug_assert!(prefix.is_empty(), "Alignment should match");
                debug_assert_eq!(shorts.len(), 1);
                &shorts[0]
            }
        }

        impl<T> BorrowMut<#name<T>> for [T] {
            fn borrow_mut(&mut self) -> &mut #name<T> {
                debug_assert_eq!(self.len(), size_of::<#name<u8>>());
                let (prefix, shorts, _suffix) = unsafe { self.align_to_mut::<#name<T>>() };
                debug_assert!(prefix.is_empty(), "Alignment should match");
                debug_assert_eq!(shorts.len(), 1);
                &mut shorts[0]
            }
        }
    };
    methods.into()
}

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
