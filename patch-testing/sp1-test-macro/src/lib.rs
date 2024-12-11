use proc_macro::TokenStream;
use quote::quote;
use syn::parse_macro_input;

mod attr;

#[proc_macro_attribute]
pub fn sp1_test(attr: TokenStream, item: TokenStream) -> TokenStream {
    let options = parse_macro_input!(attr as attr::AttrOptions);
    println!("options: {:?}", options);

    let mut setup_fn = parse_macro_input!(item as syn::ItemFn);

    // try to do some validation here
    if setup_fn.sig.inputs.len() != 1 {
        return syn::Error::new_spanned(
            &setup_fn.sig,
            "The SP1 test attribute requires a single argument: `&mut sp1_sdk::SP1Stdin`",
        )
        .to_compile_error()
        .into();
    }

    if matches!(setup_fn.sig.output, syn::ReturnType::Default) {
        return syn::Error::new_spanned(
            &setup_fn.sig,
            "The SP1 test attribute requires a return type: `impl FnOnce(sp1_sdk::SP1PublicValues)",
        )
        .to_compile_error()
        .into();
    }

    let test_name = setup_fn.sig.ident.clone();
    let setup_name =
        syn::Ident::new(&format!("{}_setup", setup_fn.sig.ident), setup_fn.sig.ident.span());
    setup_fn.sig.ident = setup_name.clone();

    let elf_name = match options.elf_name() {
        Some(elf) => elf,
        None => panic!("The SP1 test attribute requires an ELF file to be specified"),
    };

    let bounds_check = quote! {
         fn assert_proper_cb<F: FnOnce(::sp1_sdk::SP1PublicValues)>(cb: &F) {
                let _ = cb;
            }

        assert_proper_cb(&cb);
    };

    let execute_test = quote! {
        #[test]
        fn #test_name() {
            const ELF: &[u8] = ::sp1_sdk::include_elf!(#elf_name);

            let client = ::sp1_sdk::ProverClient::new();
            let mut stdin = ::sp1_sdk::SP1Stdin::new();

            #setup_fn

            let cb = #setup_name(&mut stdin);

            #bounds_check

            let (public, _) = client.execute(ELF, stdin).run().unwrap();

            cb(public);
        }
    };

    let maybe_prove_test = if options.prove() {
        let prove_name = syn::Ident::new(&format!("{}_prove", test_name), test_name.span());

        let prove_fn = quote! {
            #[test]
            fn #prove_name() {
                const ELF: &[u8] = ::sp1_sdk::include_elf!(#elf_name);

                let client = ::sp1_sdk::ProverClient::new();
                let mut stdin = ::sp1_sdk::SP1Stdin::new();

                #setup_fn

                let cb = #setup_name(&mut stdin);

                #bounds_check

                let (pk, _) = client.setup(ELF);
                let proof = client.prove(&pk, stdin).run().unwrap();

                cb(proof.public_values);
            }
        };

        Some(prove_fn)
    } else {
        None
    };

    let maybe_gpu_tests = if options.gpu() {
        let gpu_name = syn::Ident::new(&format!("{}_gpu", test_name), test_name.span());
        let gpu_prove_name = syn::Ident::new(&format!("{}_gpu_prove", test_name), test_name.span());

        let gpu_fn = quote! {
            #[test]
            fn #gpu_name() {
                    const ELF: &[u8] = ::sp1_sdk::include_elf!(#elf_name);

                let client = ::sp1_sdk::ProverClient::gpu();
                let mut stdin = ::sp1_sdk::SP1Stdin::new();

                #setup_fn

                let cb = #setup_name(&mut stdin);

                #bounds_check

                let (public, _) = client.execute(ELF, stdin).run().unwrap();

                cb(public);
            }
        };

        let gpu_prove_fn = if options.prove() {
            Some(quote! {
                #[test]
                fn #gpu_prove_name() {
                    const ELF: &[u8] = ::sp1_sdk::include_elf!(#elf_name);

                    let client = ::sp1_sdk::ProverClient::gpu();
                    let mut stdin = ::sp1_sdk::SP1Stdin::new();

                    #setup_fn

                    let cb = #setup_name(&mut stdin);

                    #bounds_check

                    let (pk, _) = client.setup(ELF);
                    let proof = client.prove(&pk, stdin).run().unwrap();

                    cb(proof.public_values);
                }
            })
        } else {
            None
        };

        Some(quote! {
            #gpu_fn

            #gpu_prove_fn
        })
    } else {
        None
    };

    let expanded = quote! {
        #execute_test

        #maybe_prove_test

        #maybe_gpu_tests
    };

    TokenStream::from(expanded)
}
