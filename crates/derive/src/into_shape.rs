use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::{parse_macro_input, Data, DeriveInput, GenericParam};

/// Derive macro for generating `Into<Shape<ExprRef<F>, ExprExtRef<EF>>>` implementations.
///
/// This macro generates an implementation that converts a struct into a Shape::Struct variant,
/// including all fields that have a `Word` type or are the generic type parameter itself.
///
/// # One type parameter
/// ```compile_fail
/// #[derive(IntoShape)]
/// struct AddOperation<T> { value: Word<T> }
/// ```
/// generates `impl<F, EF> Into<Shape<…>> for AddOperation<ExprRef<F>>`.
///
/// # Two type parameters (a mode-generic column struct)
/// Chip column structs are generic over both the field type `T` and a *mode* `M` (e.g.
/// `M: TrustMode`), with a single mode-dependent field `adapter_cols: M::AdapterCols<T>`. For the
/// extraction (`SupervisorMode`) those adapter columns are `EmptyCols` (zero columns), so we
/// **skip every field whose type references the mode parameter** and emit
/// `impl<F, EF, M: TrustMode> Into<Shape<…>> for Cols<ExprRef<F>, M>`. The skip matches the
/// previously hand-written `*_cols_shape` composers in the constraint compiler.
/// ```compile_fail
/// #[derive(IntoShape)]
/// struct AddCols<T, M: TrustMode> {
///     state: CPUState<T>, adapter: RTypeReader<T>, add_operation: AddOperation<T>,
///     is_real: T, adapter_cols: M::AdapterCols<T>,   // ← skipped (references `M`)
/// }
/// ```
pub fn into_shape_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let name = &ast.ident;
    let name_str = name.to_string();

    // We support one type parameter (`T`) or two (`T`, plus a mode `M`).
    let generics = &ast.generics;
    let type_params: Vec<&syn::TypeParam> = generics
        .params
        .iter()
        .filter_map(|p| match p {
            GenericParam::Type(ty) => Some(ty),
            _ => None,
        })
        .collect();
    if type_params.is_empty() || type_params.len() > 2 {
        panic!("IntoShape requires one or two generic type parameters");
    }

    // The optional second type parameter is the mode `M`; fields whose type mentions it
    // (the `M::AdapterCols<T>` adapter columns) are skipped.
    let mode_ident = type_params.get(1).map(|ty| ty.ident.clone());

    let fields = match &ast.data {
        Data::Struct(data_struct) => data_struct
            .fields
            .iter()
            .filter_map(|field| {
                let field_name = field.ident.as_ref()?;
                if let Some(m) = &mode_ident {
                    if type_mentions_ident(&field.ty, m) {
                        return None;
                    }
                }
                let field_name_str = field_name.to_string();
                Some(quote! {
                    (#field_name_str.to_string(), Box::new(self.#field_name.into()))
                })
            })
            .collect::<Vec<_>>(),
        _ => panic!("IntoShape can only be derived for structs"),
    };

    // The impl target and extra impl-generics depend on whether there is a mode parameter.
    // With a mode `M` we replicate its bounds verbatim (e.g. `M: TrustMode`) so the impl is valid.
    let (extra_impl_generic, target_type) = match &mode_ident {
        Some(m) => {
            let mode_param = &type_params[1]; // carries `M: TrustMode` (ident + bounds)
            (
                quote! { , #mode_param },
                quote! { #name<sp1_hypercube::ir::ExprRef<F>, #m> },
            )
        }
        None => (quote! {}, quote! { #name<sp1_hypercube::ir::ExprRef<F>> }),
    };

    let expanded = quote! {
        impl<F: slop_algebra::Field, EF: slop_algebra::ExtensionField<F> #extra_impl_generic>
            Into<sp1_hypercube::ir::Shape<sp1_hypercube::ir::ExprRef<F>, sp1_hypercube::ir::ExprExtRef<EF>>>
            for #target_type
        {
            fn into(self) -> sp1_hypercube::ir::Shape<sp1_hypercube::ir::ExprRef<F>, sp1_hypercube::ir::ExprExtRef<EF>> {
                sp1_hypercube::ir::Shape::Struct(
                    #name_str.to_string(),
                    vec![
                        #(#fields,)*
                    ],
                )
            }
        }
    };

    TokenStream::from(expanded)
}

/// Whether a field type's token stream mentions `ident` as a whole token — used to detect the
/// mode-dependent `M::AdapterCols<T>` field so it can be skipped. Token-string matching (rather
/// than substring) avoids false positives like `MyType` for mode `M`.
fn type_mentions_ident(ty: &syn::Type, ident: &syn::Ident) -> bool {
    let target = ident.to_string();
    ty.to_token_stream()
        .to_string()
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|tok| tok == target)
}
