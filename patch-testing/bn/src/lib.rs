#[sp1_test::sp1_test("bn_test_fq_sqrt", gpu, prove)]
pub fn test_bn_test_fq_sqrt_100(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use substrate_bn::Fq;

    let times: u8 = 100;
    stdin.write(&times);

    let mut unpatched_results: Vec<Vec<u8>> = Vec::new();

    while unpatched_results.len() < times as usize {
        let rand_bytes = rand::random::<[u8; 32]>();
        let rand = match Fq::from_slice(&rand_bytes) {
            Ok(rand) => rand,
            Err(_) => continue,
        };

        let mut sqrt_bytes = [0u8; 32];
        match rand.sqrt() {
            Some(sqrt) => sqrt.to_big_endian(&mut sqrt_bytes).unwrap(),
            None => continue,
        };

        stdin.write(&rand_bytes.to_vec());
        unpatched_results.push(sqrt_bytes.to_vec());
    }

    |mut public| {
        for res in unpatched_results {
            let zk_res = public.read::<Vec<u8>>();
            assert_eq!(res, zk_res);
        }
    }
}

#[sp1_test::sp1_test("bn_test_fq_inverse", gpu, prove)]
pub fn test_bn_test_fq_inverse_100(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use substrate_bn::Fq;

    let times: u8 = 100;
    stdin.write(&times);

    let mut unpatched_results: Vec<Vec<u8>> = Vec::new();

    while unpatched_results.len() < times as usize {
        let rand_bytes = rand::random::<[u8; 32]>();
        let rand = match Fq::from_slice(&rand_bytes) {
            Ok(rand) => rand,
            Err(_) => continue,
        };

        let mut inverse_bytes = [0u8; 32];
        match rand.inverse() {
            Some(inverse) => inverse.to_big_endian(&mut inverse_bytes).unwrap(),
            None => continue,
        };

        stdin.write(&rand_bytes.to_vec());
        unpatched_results.push(inverse_bytes.to_vec());
    }

    |mut public| {
        for res in unpatched_results {
            let zk_res = public.read::<Vec<u8>>();
            assert_eq!(res, zk_res);
        }
    }
}

#[sp1_test::sp1_test("bn_test_fr_inverse", gpu, prove)]
pub fn test_bn_test_fr_inverse_100(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use substrate_bn::Fr;

    let times: u8 = 100;
    stdin.write(&times);

    let mut unpatched_results: Vec<Vec<u8>> = Vec::new();

    while unpatched_results.len() < times as usize {
        let rand_bytes = rand::random::<[u8; 32]>();
        let rand = match Fr::from_slice(&rand_bytes) {
            Ok(rand) => rand,
            Err(_) => continue,
        };

        let mut inverse_bytes = [0u8; 32];
        match rand.inverse() {
            Some(inverse) => inverse.to_big_endian(&mut inverse_bytes).unwrap(),
            None => continue,
        };

        stdin.write(&rand_bytes.to_vec());
        unpatched_results.push(inverse_bytes.to_vec());
    }

    |mut public| {
        for res in unpatched_results {
            let zk_res = public.read::<Vec<u8>>();
            assert_eq!(res, zk_res);
        }
    }
}
