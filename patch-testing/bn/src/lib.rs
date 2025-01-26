#[sp1_test::sp1_test("bn_test_fq_sqrt", syscalls = [BN254_FP_MUL], gpu, prove)]
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

#[sp1_test::sp1_test("bn_test_fq_inverse", syscalls = [BN254_FP_MUL], gpu, prove)]
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

#[sp1_test::sp1_test("bn_test_fr_inverse", syscalls = [UINT256_MUL], gpu, prove)]
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

#[sp1_test::sp1_test("bn_test_g1_add", syscalls = [BN254_ADD, BN254_FP_ADD, BN254_FP_MUL], gpu, prove)]
pub fn test_bn_test_g1_add_100(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use substrate_bn::{AffineG1, Fr, Group, G1};

    let rng = &mut rand::thread_rng();

    let times: u8 = 100;
    stdin.write(&times);

    let mut i = 0;
    while i < times {
        let a_s = Fr::random(rng);
        let b_s = Fr::random(rng);

        let a = G1::one() * a_s;
        let b = G1::one() * b_s;
        let c = a + b;

        let a: AffineG1 = AffineG1::from_jacobian(a).unwrap();
        let b: AffineG1 = AffineG1::from_jacobian(b).unwrap();
        let c: AffineG1 = AffineG1::from_jacobian(c).unwrap();

        let mut a_x_bytes = [0u8; 32];
        let mut a_y_bytes = [0u8; 32];
        a.x().to_big_endian(&mut a_x_bytes).unwrap();
        a.y().to_big_endian(&mut a_y_bytes).unwrap();
        stdin.write(&a_x_bytes.to_vec());
        stdin.write(&a_y_bytes.to_vec());

        let mut b_x_bytes = [0u8; 32];
        let mut b_y_bytes = [0u8; 32];
        b.x().to_big_endian(&mut b_x_bytes).unwrap();
        b.y().to_big_endian(&mut b_y_bytes).unwrap();
        stdin.write(&b_x_bytes.to_vec());
        stdin.write(&b_y_bytes.to_vec());

        let mut c_x_bytes = [0u8; 32];
        let mut c_y_bytes = [0u8; 32];
        c.x().to_big_endian(&mut c_x_bytes).unwrap();
        c.y().to_big_endian(&mut c_y_bytes).unwrap();
        stdin.write(&c_x_bytes.to_vec());
        stdin.write(&c_y_bytes.to_vec());

        i += 1;
    }

    |_| {}
}

#[sp1_test::sp1_test("bn_test_g1_double", syscalls = [BN254_DOUBLE, BN254_FP_ADD, BN254_FP_MUL], gpu, prove)]
pub fn test_bn_test_g1_double_100(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use substrate_bn::{AffineG1, Fr, Group, G1};

    let rng = &mut rand::thread_rng();

    let times: u8 = 100;
    stdin.write(&times);

    let mut i = 0;
    while i < times {
        let a_s = Fr::random(rng);

        let a = G1::one() * a_s;
        let b = a + a;

        let a: AffineG1 = AffineG1::from_jacobian(a).unwrap();
        let b: AffineG1 = AffineG1::from_jacobian(b).unwrap();

        let mut a_x_bytes = [0u8; 32];
        let mut a_y_bytes = [0u8; 32];
        a.x().to_big_endian(&mut a_x_bytes).unwrap();
        a.y().to_big_endian(&mut a_y_bytes).unwrap();
        stdin.write(&a_x_bytes.to_vec());
        stdin.write(&a_y_bytes.to_vec());

        let mut b_x_bytes = [0u8; 32];
        let mut b_y_bytes = [0u8; 32];
        b.x().to_big_endian(&mut b_x_bytes).unwrap();
        b.y().to_big_endian(&mut b_y_bytes).unwrap();
        stdin.write(&b_x_bytes.to_vec());
        stdin.write(&b_y_bytes.to_vec());

        i += 1;
    }

    |_| {}
}
