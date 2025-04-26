use proc_macro::TokenStream;
use quote::quote;
use syn::parse_macro_input;

mod attr;

/// The `sp1_test` attribute is used to define a test case one time, that can be used to test
/// execution, proof types, and the various provers.
///
/// The accepted attribute arguments are:
/// - [elf = ] "<elf_name>",
/// - [prove],
/// - [gpu].
/// - [setup = <function_name>]
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
    if attr.is_empty() {
        return syn::Error::new_spanned(
            proc_macro2::TokenStream::new(),
            "The SP1 test attribute requires at least an ELF file to be specified",
        )
        .to_compile_error()
        .into();
    }

    let options = parse_macro_input!(attr as attr::AttrOptions);

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

    let syscalls = options.syscalls();

    let bounds_check = quote! {
        fn __assert_proper_cb<F: FnOnce(::sp1_sdk::SP1PublicValues)>(cb: &F) {
            let _ = cb;
        }

        __assert_proper_cb(&__macro_internal_cb);
    };

    let maybe_client_setup = options.setup().map(|setup| {
        quote! {
            fn __asset_proper_setup<F: FnOnce(::sp1_sdk::CpuProver) -> ::sp1_sdk::ProverClient>(setup: F) {
                let _ = setup;
            }

            __asset_proper_setup(#setup);

            let __macro_internal_client = #setup(__macro_internal_client);
        }
    });

    let verify = quote! {
        {
            __macro_internal_client.verify(&__macro_internal_proof, &__macro_internal_vk).unwrap();
        }
    };

    let execute_test = quote! {
        #[cfg(not(any(feature = "prove", feature = "gpu")))]
        #[test]
        fn #test_name() {
            const __MACRO_INTERNAL_ELF: &[u8] = ::sp1_sdk::include_elf!(#elf_name);

            let mut __macro_internal_stdin = ::sp1_sdk::SP1Stdin::new();
            let __macro_internal_client = &*::sp1_test::SP1_CPU_PROVER;

            #setup_fn

            let __macro_internal_cb = #setup_name(&mut __macro_internal_stdin);

            #bounds_check

            #maybe_client_setup

            let (__macro_internal_public, __macro_internal_execution_report) = __macro_internal_client.execute(__MACRO_INTERNAL_ELF, &__macro_internal_stdin).run().unwrap();

            for syscall in [#(::sp1_core_executor::syscalls::SyscallCode::#syscalls),*] {
                assert!(__macro_internal_execution_report.syscall_counts[syscall] > 0, "Syscall {syscall} has not been emitted");
            }

            __macro_internal_cb(__macro_internal_public);

            println!("Cycle Count: {}", __macro_internal_execution_report.total_instruction_count());

            ::sp1_test::write_cycles(concat!(env!("CARGO_CRATE_NAME"), "_", stringify!(#test_name)), __macro_internal_execution_report.total_instruction_count());
        }
    };

    let maybe_prove_test = if options.prove() {
        let prove_name = syn::Ident::new(&format!("{}_prove", test_name), test_name.span());

        let prove_fn = quote! {
            #[cfg(feature = "prove")]
            #[test]
            fn #prove_name() {
                use ::sp1_sdk::Prover;
                const __MACRO_INTERNAL_ELF: &[u8] = ::sp1_sdk::include_elf!(#elf_name);

                let __macro_internal_client = &*::sp1_test::SP1_CPU_PROVER;
                let mut __macro_internal_stdin = ::sp1_sdk::SP1Stdin::new();

                #setup_fn

                let __macro_internal_cb = #setup_name(&mut __macro_internal_stdin);

                #bounds_check

                let (__macro_internal_pk, __macro_internal_vk) = __macro_internal_client.setup(__MACRO_INTERNAL_ELF);
                let __macro_internal_proof = __macro_internal_client.prove(&__macro_internal_pk, &__macro_internal_stdin).compressed().run().unwrap();

                #verify

                __macro_internal_cb(__macro_internal_proof.public_values);
            }
        };

        Some(prove_fn)
    } else {
        None
    };

    let gpu_prove = if options.gpu() {
        let gpu_prove_name = syn::Ident::new(&format!("{}_gpu_prove", test_name), test_name.span());

        Some(quote! {
            #[cfg(feature = "gpu")]
            #[test]
            fn #gpu_prove_name() {
                use ::sp1_sdk::Prover;
                const __MACRO_INTERNAL_ELF: &[u8] = ::sp1_sdk::include_elf!(#elf_name);

                // Note: Gpu tests must be ran serially.
                // A parking-lot mutex is used internally to avoid priority inversion.
                let _lock = ::sp1_test::lock_serial();

                // Note: We must sleep on gpu tests to wait for Docker cleanup.
                std::thread::sleep(std::time::Duration::from_secs(5));

                let __macro_internal_client = ::sp1_sdk::ProverClient::builder().cuda().build();
                let mut __macro_internal_stdin = ::sp1_sdk::SP1Stdin::new();

                #setup_fn

                let __macro_internal_cb = #setup_name(&mut __macro_internal_stdin);

                #bounds_check

                let (__macro_internal_pk, __macro_internal_vk) = __macro_internal_client.setup(__MACRO_INTERNAL_ELF);
                let __macro_internal_proof = __macro_internal_client.prove(&__macro_internal_pk, &__macro_internal_stdin).compressed().run().unwrap();

                #verify

                __macro_internal_cb(__macro_internal_proof.public_values);
            }
        })
    } else {
        None
    };

    let expanded = quote! {
        #execute_test

        #maybe_prove_test

        #gpu_prove
    };

    TokenStream::from(expanded)
}
