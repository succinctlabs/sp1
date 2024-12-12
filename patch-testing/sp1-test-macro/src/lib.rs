use proc_macro::TokenStream;
use quote::quote;
use syn::parse_macro_input;

mod attr;


/// The `sp1_test` attribute is used to define a test case one time, that can be used to test
/// execution, proof types, and the various provers.
///
/// The accepted attrubute arguments are:
/// - [elf = ] "<elf_name>",
/// - [prove],
/// - [gpu].
///
/// Passing in any other arguments will result in a compile error.
/// Tests are broken up into two parts: setup and check.
///
/// The way this macro handles this is by expecting a function with the following signature:
/// ```rust,ignore
/// fn test_name(stdin: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(SP1PublicValues);
/// ```
///
/// The body of `test_name` is the "setup", and the returned `FnOnce(SP1PublicValues)` is the
/// "check".
///
/// Here is a full example of how to use this macro:
/// ```rust,ignore
/// #[sp1_test("sha_256_program")]
/// fn test_expected_digest_rand_times_lte_100_test(stdin: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(SP1PublicValues) {
///    let times = rand::random::<u8>().min(100);
///
///    let preimages: Vec<Vec<u8>> = (0..times)
///        .map(|_| {
///            let rand_len = rand::random::<u8>();
///            (0..rand_len).map(|_| rand::random::<u8>()).collect::<Vec<u8>>()
///        })
///        .collect();
///
///    let digests = preimages
///        .iter()
///        .map(|preimage| {
///            let mut sha256_9_8 = sha2_v0_9_8::Sha256::new();
///            sha256_9_8.update(preimage);
///
///            let mut sha256_10_6 = sha2_v0_10_6::Sha256::new();
///            sha256_10_6.update(preimage);
///
///            (sha256_9_8.finalize().into(), sha256_10_6.finalize().into())
///        })
///       .collect::<Vec<([u8; 32], [u8; 32])>>();
///
///    stdin.write(&times);
///    preimages.iter().for_each(|preimage| stdin.write_slice(preimage.as_slice()));
///
///    move |mut public| {
///        let outputs = public.read::<Vec<([u8; 32], [u8; 32])>>();
///        assert_eq!(digests, outputs);
///    }
/// }
/// ```
///
/// Note: You MUST have sp1-sdk in your dependencies, and you MUST have and to use the `gpu`
/// option, you must have the `cuda` feature enabled on the SDK.
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
            #[cfg(feature = "prove")]
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
            #[cfg(feature = "cuda")]
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
                #[cfg(feature = "cuda")]
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
