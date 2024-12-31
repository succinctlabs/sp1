
#[sp1_test::sp1_test("bls12_381_test_sqrt", gpu, prove)]
pub fn test_verify_rand_lte_100(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use bls12_381::fp::Fp;

    let times: u8 = 100; 
    stdin.write(&times);

    let mut unpatched_results: Vec<Option<Vec<u8>>> = Vec::new();

    while unpatched_results.len() < times as usize {
        let rand_bytes = rand::random::<[u8; 48]>();
        let Some(rand) = Fp::from_bytes(&rand_bytes).into_option() else {
            continue;
        };
        
        stdin.write(&rand_bytes.to_vec());

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


