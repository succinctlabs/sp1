#[sp1_test::sp1_test("bls12_381_fp_test_sqrt", gpu, prove)]
pub fn test_sqrt_fp_100(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use bls12_381::fp::Fp;

    let times: u8 = 100; 
    stdin.write(&times);

    let mut unpatched_results: Vec<Option<Vec<u8>>> = Vec::new();

    while unpatched_results.len() < times as usize {
        let rand = Fp::random(&mut rand::thread_rng());

        stdin.write(&rand.to_bytes().to_vec());

        let sqrt_bytes = rand.sqrt().into_option().map(|v| v.to_bytes().to_vec());

        unpatched_results.push(sqrt_bytes);
    }


    |mut public| {
        for res in unpatched_results {
            let zk_res = public.read::<Option<Vec<u8>>>();

            assert_eq!(res, zk_res);
        }
    }
}

#[sp1_test::sp1_test("bls12_381_fp_test_inverse", gpu, prove)]
pub fn test_inverse_fp_100(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use bls12_381::fp::Fp;

    let times: u8 = 100; 
    stdin.write(&times);

    let mut unpatched_results: Vec<Option<Vec<u8>>> = Vec::new();

    while unpatched_results.len() < times as usize {
        let rand = Fp::random(&mut rand::thread_rng());

        stdin.write(&rand.to_bytes().to_vec());

        let sqrt_bytes = rand.invert().into_option().map(|v| v.to_bytes().to_vec());

        unpatched_results.push(sqrt_bytes);
    }


    |mut public| {
        for res in unpatched_results {
            let zk_res = public.read::<Option<Vec<u8>>>();

            assert_eq!(res, zk_res);
        }
    }
}

#[sp1_test::sp1_test("bls12_381_fp2_test_sqrt", gpu, prove)]
pub fn test_sqrt_fp2_100(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use bls12_381::fp2::Fp2;

    let times: u8 = 100; 
    stdin.write(&times);

    let mut unpatched_results: Vec<Option<Vec<u8>>> = Vec::new();

    while unpatched_results.len() < times as usize {
        let rand = Fp2::random(&mut rand::thread_rng());

        stdin.write(&rand.to_bytes().to_vec());

        let sqrt_bytes = rand.sqrt().into_option().map(|v| v.to_bytes().to_vec());

        unpatched_results.push(sqrt_bytes);
    }


    |mut public| {
        for res in unpatched_results {
            let zk_res = public.read::<Option<Vec<u8>>>();

            assert_eq!(res, zk_res);
        }
    }
}

#[sp1_test::sp1_test("bls12_381_fp2_test_inverse", gpu, prove)]
pub fn test_inverse_fp2_100(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use bls12_381::fp2::Fp2;

    let times: u8 = 100; 
    stdin.write(&times);

    let mut unpatched_results: Vec<Option<Vec<u8>>> = Vec::new();

    while unpatched_results.len() < times as usize {
        let rand = Fp2::random(&mut rand::thread_rng());
        
        stdin.write(&rand.to_bytes().to_vec());

        let sqrt_bytes = rand.invert().into_option().map(|v| v.to_bytes().to_vec());

        unpatched_results.push(sqrt_bytes);
    }


    |mut public| {
        for res in unpatched_results {
            let zk_res = public.read::<Option<Vec<u8>>>();

            assert_eq!(res, zk_res);
        }
    }
}
