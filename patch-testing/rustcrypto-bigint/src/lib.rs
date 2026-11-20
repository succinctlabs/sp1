#[sp1_test::sp1_test("bigint_test_mul_mod_special", syscalls = [UINT256_MUL], gpu, prove)]
pub fn test_bigint_mul_mod_special(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use crypto_bigint::{Encoding, Limb, Uint};

    let times: u8 = 255;
    stdin.write(&times);

    let mut unpatched_results: Vec<Vec<u8>> = Vec::new();

    while unpatched_results.len() < times as usize {
        let a_bytes_64 = rand::random::<[u64; 4]>();
        let b_bytes_64 = rand::random::<[u64; 4]>();

        stdin.write(&a_bytes_64);
        stdin.write(&b_bytes_64);

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

#[sp1_test::sp1_test("bigint_test_mul_mod_special_edges", prove)]
pub fn test_bigint_mul_mod_special_zero(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    mul_mod_special_edges(stdin, &[0], &[32, 16, 64])
}

// Upstream panics for one limb and c = 0. Keep this exception separate so
// it cannot hide the three-way comparison at the other widths.
#[sp1_test::sp1_test("bigint_test_mul_mod_special_edges", prove)]
pub fn test_bigint_mul_mod_special_zero_single_limb(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    mul_mod_special_edges(stdin, &[0], &[8])
}

#[sp1_test::sp1_test("bigint_test_mul_mod_special_edges", syscalls = [UINT256_MUL], prove)]
pub fn test_bigint_mul_mod_special_controls(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    mul_mod_special_edges(stdin, &[1, 356, u64::MAX], &[32, 8, 16, 64])
}

fn mul_mod_special_edges(
    stdin: &mut sp1_sdk::SP1Stdin,
    cs: &[u64],
    widths: &[usize],
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use num_bigint::BigUint;
    use rand::{RngCore, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x535031);
    let mut cases = Vec::new();
    for &bytes in widths {
        let mut one = vec![0u8; bytes];
        one[bytes - 1] = 1;
        let mut top = vec![0; bytes];
        top[0] = 128;
        let edges = [vec![0; bytes], one, vec![255; bytes], top, vec![0xaa; bytes]];
        let mut pairs: Vec<_> =
            edges.iter().flat_map(|a| edges.iter().map(move |b| (a.clone(), b.clone()))).collect();
        for _ in 0..64 {
            let mut a = vec![0; bytes];
            let mut b = vec![0; bytes];
            rng.fill_bytes(&mut a);
            rng.fill_bytes(&mut b);
            pairs.push((a, b));
        }
        for c in cs {
            for (a, b) in &pairs {
                let modulus = (BigUint::from(1u8) << (bytes * 8)) - BigUint::from(*c);
                let result = (BigUint::from_bytes_be(a) * BigUint::from_bytes_be(b)) % modulus;
                let encoded = result.to_bytes_be();
                let mut expected = vec![0; bytes];
                expected[bytes - encoded.len()..].copy_from_slice(&encoded);
                cases.push((a.clone(), b.clone(), *c, expected));
            }
        }
    }
    stdin.write(&u32::try_from(cases.len()).unwrap());
    for (a, b, c, expected) in &cases {
        macro_rules! native_multiply {
            ($bigint:ident) => {{
                use $bigint::{Encoding, Limb, U128, U256, U512, U64};
                macro_rules! multiply {
                    ($uint:ty) => {
                        <$uint>::from_be_slice(a)
                            .mul_mod_special(&<$uint>::from_be_slice(b), Limb(*c))
                            .to_be_bytes()
                            .to_vec()
                    };
                }
                match a.len() {
                    8 => multiply!(U64),
                    16 => multiply!(U128),
                    32 => multiply!(U256),
                    64 => multiply!(U512),
                    _ => unreachable!(),
                }
            }};
        }
        assert_eq!(&native_multiply!(crypto_bigint_patched), expected, "native patch");
        // Upstream divides by zero for one limb and c = 0. Both patched modes
        // still check those cases against the independent BigUint reference.
        if a.len() != 8 || *c != 0 {
            assert_eq!(&native_multiply!(crypto_bigint), expected, "original crate");
        }
        stdin.write_vec(a.clone());
        stdin.write_vec(b.clone());
        stdin.write(c);
    }
    move |mut public| {
        for (_, _, _, expected) in cases {
            assert_eq!(public.read::<Vec<u8>>(), expected);
        }
    }
}

#[sp1_test::sp1_test("bigint_test_residue_identity", syscalls = [UINT256_MUL], prove)]
pub fn test_bigint_modulus_one_identity(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    residue_cases(stdin, 0)
}

#[sp1_test::sp1_test("bigint_test_residue_identity", syscalls = [UINT256_MUL], prove)]
pub fn test_bigint_modulus_one_pow(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    residue_cases(stdin, 1)
}

mod original_residues {
    use crypto_bigint as bigint;
    include!("../program/residue_cases.rs");
}

mod patched_residues {
    use crypto_bigint_patched as bigint;
    include!("../program/residue_cases.rs");
}

fn residue_cases(
    stdin: &mut sp1_sdk::SP1Stdin,
    mode: u8,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    let original = original_residues::run(mode);
    let patched = patched_residues::run(mode);
    assert_eq!(patched, original, "native patch vs original crate");
    stdin.write(&mode);
    move |mut public| assert_eq!(public.read::<Vec<Vec<u8>>>(), original, "zkVM vs native")
}
