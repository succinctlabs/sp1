#[sp1_test::sp1_test("bn_test_fq_sqrt", syscalls = [BN254_FP_MUL], gpu, prove)]
pub fn test_bn_test_fq_sqrt_100(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use substrate_bn::Fq;

    let times: u8 = 100;
    stdin.write(&times);

    let mut unpatched_results: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    while unpatched_results.len() < times as usize {
        let rand_bytes = rand::random::<[u8; 32]>();
        let rand = match Fq::from_slice(&rand_bytes) {
            Ok(rand) => rand,
            Err(_) => continue,
        };

        let sqrt = match rand.sqrt() {
            Some(sqrt) => sqrt,
            None => continue,
        };
        let mut sqrt_bytes = [0u8; 32];
        let mut neg_sqrt_bytes = [0u8; 32];
        sqrt.to_big_endian(&mut sqrt_bytes).unwrap();
        (-sqrt).to_big_endian(&mut neg_sqrt_bytes).unwrap();

        stdin.write(&rand_bytes.to_vec());
        unpatched_results.push((sqrt_bytes.to_vec(), neg_sqrt_bytes.to_vec()));
    }

    |mut public| {
        for (res, neg_res) in unpatched_results {
            let zk_res = public.read::<Vec<u8>>();
            assert!(zk_res == res || zk_res == neg_res);
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

#[sp1_test::sp1_test("bn_test_g1_add_neg", syscalls = [BN254_FP_ADD, BN254_FP_MUL], gpu, prove)]
pub fn test_bn_test_g1_add_neg(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use substrate_bn::{Fr, Group, G1};
    use substrate_bn_patched::AffineG1 as PatchedAffineG1;

    let rng = &mut rand::thread_rng();

    let times: u8 = 10;
    stdin.write(&times);

    let mut patched_results: Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();

    let mut i = 0;
    while i < times {
        let a_s = Fr::random(rng);
        let a_jac = G1::one() * a_s;
        let a = substrate_bn::AffineG1::from_jacobian(a_jac).unwrap();

        let mut a_x_bytes = [0u8; 32];
        let mut a_y_bytes = [0u8; 32];
        a.x().to_big_endian(&mut a_x_bytes).unwrap();
        a.y().to_big_endian(&mut a_y_bytes).unwrap();
        stdin.write(&a_x_bytes.to_vec());
        stdin.write(&a_y_bytes.to_vec());

        let patched_a = PatchedAffineG1::new(
            substrate_bn_patched::Fq::from_slice(&a_x_bytes).unwrap(),
            substrate_bn_patched::Fq::from_slice(&a_y_bytes).unwrap(),
        )
        .unwrap();

        let add_neg = patched_a + (-patched_a);
        let sub_self = patched_a - patched_a;

        let mut add_neg_x = [0u8; 32];
        let mut add_neg_y = [0u8; 32];
        add_neg.x().to_big_endian(&mut add_neg_x).unwrap();
        add_neg.y().to_big_endian(&mut add_neg_y).unwrap();

        let mut sub_self_x = [0u8; 32];
        let mut sub_self_y = [0u8; 32];
        sub_self.x().to_big_endian(&mut sub_self_x).unwrap();
        sub_self.y().to_big_endian(&mut sub_self_y).unwrap();

        let expected_zero_x = [0u8; 32];
        let mut expected_zero_y = [0u8; 32];
        expected_zero_y[31] = 1;

        assert_eq!(add_neg_x, expected_zero_x);
        assert_eq!(add_neg_y, expected_zero_y);
        assert_eq!(sub_self_x, expected_zero_x);
        assert_eq!(sub_self_y, expected_zero_y);

        patched_results.push((
            add_neg_x.to_vec(),
            add_neg_y.to_vec(),
            sub_self_x.to_vec(),
            sub_self_y.to_vec(),
        ));

        i += 1;
    }

    move |mut public| {
        for (exp_add_x, exp_add_y, exp_sub_x, exp_sub_y) in patched_results {
            let zk_add_x = public.read::<Vec<u8>>();
            let zk_add_y = public.read::<Vec<u8>>();
            assert_eq!(exp_add_x, zk_add_x);
            assert_eq!(exp_add_y, zk_add_y);

            let zk_sub_x = public.read::<Vec<u8>>();
            let zk_sub_y = public.read::<Vec<u8>>();
            assert_eq!(exp_sub_x, zk_sub_x);
            assert_eq!(exp_sub_y, zk_sub_y);
        }
    }
}

#[sp1_test::sp1_test("bn_test_g1_mul_zero", gpu, prove)]
pub fn test_bn_test_g1_mul_zero(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use substrate_bn::{Fr, Group, G1};
    use substrate_bn_patched::{AffineG1 as PatchedAffineG1, Fr as PatchedFr};

    let rng = &mut rand::thread_rng();

    let a_s = Fr::random(rng);
    let a_jac = G1::one() * a_s;
    let a = substrate_bn::AffineG1::from_jacobian(a_jac).unwrap();

    let mut a_x_bytes = [0u8; 32];
    let mut a_y_bytes = [0u8; 32];
    a.x().to_big_endian(&mut a_x_bytes).unwrap();
    a.y().to_big_endian(&mut a_y_bytes).unwrap();
    stdin.write(&a_x_bytes.to_vec());
    stdin.write(&a_y_bytes.to_vec());

    let patched_a = PatchedAffineG1::new(
        substrate_bn_patched::Fq::from_slice(&a_x_bytes).unwrap(),
        substrate_bn_patched::Fq::from_slice(&a_y_bytes).unwrap(),
    )
    .unwrap();

    let mul_zero = patched_a * PatchedFr::zero();
    let mut mul_zero_x = [0u8; 32];
    let mut mul_zero_y = [0u8; 32];
    mul_zero.x().to_big_endian(&mut mul_zero_x).unwrap();
    mul_zero.y().to_big_endian(&mut mul_zero_y).unwrap();

    let zero_mul_one = PatchedAffineG1::zero() * PatchedFr::one();
    let mut zero_mul_one_x = [0u8; 32];
    let mut zero_mul_one_y = [0u8; 32];
    zero_mul_one.x().to_big_endian(&mut zero_mul_one_x).unwrap();
    zero_mul_one.y().to_big_endian(&mut zero_mul_one_y).unwrap();

    let expected_zero_x = [0u8; 32];
    let mut expected_zero_y = [0u8; 32];
    expected_zero_y[31] = 1;
    assert_eq!(mul_zero_x, expected_zero_x);
    assert_eq!(mul_zero_y, expected_zero_y);
    assert_eq!(zero_mul_one_x, expected_zero_x);
    assert_eq!(zero_mul_one_y, expected_zero_y);

    move |mut public| {
        let zk_x = public.read::<Vec<u8>>();
        let zk_y = public.read::<Vec<u8>>();
        assert_eq!(zk_x, mul_zero_x.to_vec());
        assert_eq!(zk_y, mul_zero_y.to_vec());

        let zk_x2 = public.read::<Vec<u8>>();
        let zk_y2 = public.read::<Vec<u8>>();
        assert_eq!(zk_x2, zero_mul_one_x.to_vec());
        assert_eq!(zk_y2, zero_mul_one_y.to_vec());
    }
}

#[sp1_test::sp1_test("bn_test_g1_msm_edge", gpu, prove)]
pub fn test_bn_test_g1_msm_edge(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use substrate_bn::{Fr, Group, G1};
    use substrate_bn_patched::{AffineG1 as PatchedAffineG1, Fr as PatchedFr};

    let rng = &mut rand::thread_rng();

    let n: u8 = 100;
    stdin.write(&n);

    let mut point_bytes = Vec::new();
    for _ in 0..n {
        let s = Fr::random(rng);
        let p_jac = G1::one() * s;
        let p = substrate_bn::AffineG1::from_jacobian(p_jac).unwrap();

        let mut x_bytes = [0u8; 32];
        let mut y_bytes = [0u8; 32];
        p.x().to_big_endian(&mut x_bytes).unwrap();
        p.y().to_big_endian(&mut y_bytes).unwrap();
        stdin.write(&x_bytes.to_vec());
        stdin.write(&y_bytes.to_vec());
        point_bytes.push((x_bytes, y_bytes));
    }

    let patched_points: Vec<PatchedAffineG1> = point_bytes
        .iter()
        .map(|(x, y)| {
            PatchedAffineG1::new(
                substrate_bn_patched::Fq::from_slice(x).unwrap(),
                substrate_bn_patched::Fq::from_slice(y).unwrap(),
            )
            .unwrap()
        })
        .collect();

    let zero_scalars: Vec<PatchedFr> = vec![PatchedFr::zero(); n as usize];
    let all_zero_result = PatchedAffineG1::msm(&patched_points, &zero_scalars);
    let mut all_zero_x = [0u8; 32];
    let mut all_zero_y = [0u8; 32];
    all_zero_result.x().to_big_endian(&mut all_zero_x).unwrap();
    all_zero_result.y().to_big_endian(&mut all_zero_y).unwrap();

    let mut mixed_scalars: Vec<PatchedFr> = vec![PatchedFr::zero(); n as usize];
    mixed_scalars[0] = PatchedFr::one();
    let mixed_result = PatchedAffineG1::msm(&patched_points, &mixed_scalars);
    let mut mixed_x = [0u8; 32];
    let mut mixed_y = [0u8; 32];
    mixed_result.x().to_big_endian(&mut mixed_x).unwrap();
    mixed_result.y().to_big_endian(&mut mixed_y).unwrap();

    let expected_zero_x = [0u8; 32];
    let mut expected_zero_y = [0u8; 32];
    expected_zero_y[31] = 1;
    assert_eq!(all_zero_x, expected_zero_x);
    assert_eq!(all_zero_y, expected_zero_y);
    assert_eq!(mixed_x, point_bytes[0].0);
    assert_eq!(mixed_y, point_bytes[0].1);

    move |mut public| {
        let zk_x = public.read::<Vec<u8>>();
        let zk_y = public.read::<Vec<u8>>();
        assert_eq!(zk_x, all_zero_x.to_vec());
        assert_eq!(zk_y, all_zero_y.to_vec());

        let zk_x2 = public.read::<Vec<u8>>();
        let zk_y2 = public.read::<Vec<u8>>();
        assert_eq!(zk_x2, mixed_x.to_vec());
        assert_eq!(zk_y2, mixed_y.to_vec());
    }
}

#[sp1_test::sp1_test("bn_test_fq_partial_ord", gpu, prove)]
pub fn test_bn_test_fq_partial_ord(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use substrate_bn_patched::Fq as PatchedFq;

    let times: u8 = 100;
    stdin.write(&times);

    for _ in 0..times {
        loop {
            let rand_bytes = rand::random::<[u8; 32]>();
            if let Ok(a) = PatchedFq::from_slice(&rand_bytes) {
                let b = PatchedFq::from_slice(&rand_bytes).unwrap();
                assert_eq!(a.partial_cmp(&b), Some(core::cmp::Ordering::Equal));
                stdin.write(&rand_bytes.to_vec());
                break;
            }
        }
    }

    move |mut public| {
        for _ in 0..times {
            let ok = public.read::<u8>();
            assert_eq!(ok, 1);
        }
    }
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
#[sp1_test::sp1_test("bn_field_checks", gpu, prove)]
pub fn test_field_checks(_: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    |mut public| assert!(public.read::<bool>())
}
