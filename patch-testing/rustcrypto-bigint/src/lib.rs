#[sp1_test::sp1_test("bigint_test_mul_mod_special", syscalls = [UINT256_MUL], gpu, prove)]
pub fn test_bigint_mul_mod_special(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use crypto_bigint::{Encoding, Limb, Uint};

    let times: u8 = 255;
    stdin.write(&times);

    let mut unpatched_results: Vec<Vec<u8>> = Vec::new();

    while unpatched_results.len() < times as usize {
        let a_bytes = rand::random::<[u32; 8]>();
        let b_bytes = rand::random::<[u32; 8]>();

        stdin.write(&a_bytes.to_vec());
        stdin.write(&b_bytes.to_vec());

        let a_bytes_64 = unsafe { std::mem::transmute::<[u32; 8], [u64; 4]>(a_bytes) };
        let b_bytes_64 = unsafe { std::mem::transmute::<[u32; 8], [u64; 4]>(b_bytes) };
        let a = Uint::<4>::from_words(a_bytes_64);
        let b = Uint::<4>::from_words(b_bytes_64);

        let c = 356u64;
        let c = Limb(c);
        let result = a.mul_mod_special(&b, c);

        unpatched_results.push(result.to_be_bytes().to_vec());
    }

    |mut public| {
        for res in unpatched_results {
            let zk_res = public.read::<Vec<u8>>();
            assert_eq!(res, zk_res);
        }
    }
}

#[sp1_test::sp1_test("bigint_test_mul_add_residue", syscalls = [UINT256_MUL], gpu, prove)]
pub fn test_bigint_mul_add_residue(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use crypto_bigint::modular::constant_mod::ResidueParams;
    use crypto_bigint::{const_residue, impl_modulus, Encoding, U256};

    impl_modulus!(
        Modulus,
        U256,
        "9CC24C5DF431A864188AB905AC751B727C9447A8E99E6366E1AD78A21E8D882B"
    );

    let times: u8 = 255;
    stdin.write(&times);

    let mut unpatched_results: Vec<Vec<u8>> = Vec::new();

    while unpatched_results.len() < times as usize {
        let a = rand::random::<u64>();
        let b = rand::random::<u64>();
        stdin.write(&a);
        stdin.write(&b);

        let a_uint = U256::from(a);
        let b_uint = U256::from(b);
        let a_residue = const_residue!(a_uint, Modulus);
        let b_residue = const_residue!(b_uint, Modulus);

        let result = a_residue * b_residue + a_residue;

        unpatched_results.push(result.retrieve().to_be_bytes().to_vec());
    }

    |mut public| {
        for res in unpatched_results {
            let zk_res = public.read::<Vec<u8>>();
            assert_eq!(res, zk_res);
        }
    }
}
