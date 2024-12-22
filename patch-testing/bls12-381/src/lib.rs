#[sp1_test::sp1_test("bls12_381_test", gpu, prove)]
pub fn test_verify_rand_lte_100(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    let _ = stdin;

    |_| {

    }
}
