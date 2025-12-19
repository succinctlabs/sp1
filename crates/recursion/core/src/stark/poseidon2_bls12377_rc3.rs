//! Poseidon2 round constants for BLS12-377 Fr (t=3).
//!
//! **Source of truth**: ICICLE's published constants:
//! `icicle/include/icicle/hash/poseidon2_constants/constants/bls12_377_poseidon2.h`
//! under `rounds_constants_3`.
//!
//! Parameters:
//! - width \(t\) = 3
//! - alpha = 11
//! - full rounds \(R_F\) = 8
//! - partial rounds \(R_P\) = 37
//!
//! ICICLE encodes `rounds_constants_3` in a compact form:
//! - 3 constants per *full* round (for all lanes)
//! - 1 constant per *partial* round (for lane 0 only)
//! This totals `4*3 + 37*1 + 4*3 = 61` constants.

use std::sync::OnceLock;

use ff::PrimeField as FFPrimeField;
use p3_bls12_377_fr::{Bls12377Fr, FFBls12377Fr};

const WIDTH: usize = 3;
const ROUNDS_F: usize = 8;
const ROUNDS_P: usize = 37;
const TOTAL_ROUNDS: usize = ROUNDS_F + ROUNDS_P; // 45

/// ICICLE `rounds_constants_3` (BLS12-377, t=3, alpha=11, RF=8, RP=37).
///
/// Each entry is a big-endian hex string (0x-prefixed). Strings may omit leading zero bytes.
const ICICLE_ROUNDS_CONSTANTS_3: [&str; 61] = [
    "0x894b84bdb19c99b174eef89446c8042b49d9d2a82fc46c4d653ebdcd127a9aa",
    "0xc6b7ff8356bd516fad4f06f4c5354bb1ea26d27b3e9b156e89f0c9ba9ea1163",
    "0xd03966afba794725c52dd8f7507a62b3441fb8608becf0b0cc077744ed99175",
    "0x8c34d497d141ad73833b13ced2b8f457312a3ed8b5a6d9387f6efdc451260ac",
    "0x11e6eeea347fd87200953e431bb652bac5e86acc07849fcc34066fc43475cffe",
    "0xb9034e2459a594e1be61dc0359ee295ae75b00fdce16ef62f4d8ccd13ffb859",
    "0x4b223f6f682ee44bf4a873f3213f089c3d177918571ad89bbd14dc41d6a24e6",
    "0x837100b8863659249a0f72e38804af3e1297893de888f0d9fec16cfba2ab82",
    "0xc81b73f232fa3111835446ea4cfc56e28be0582edfb0f83d4ebbefb278afbba",
    "0xb78e340840581b85f52728896d521caf8ae8cf427068415b04a53d27dc289b6",
    "0x574ee59fd4970e96a6614a64f18fa36a685c18580dbdf781438efbfa4b09514",
    "0x38f66ae633f3b619c8c56dc8229664af8206a45eb72d87f1ffd2476e4888072",
    "0xb49e75e262625b53ace4b7f65bb2c21939ffeef5972cea323bf413452bfdf72",
    "0x1041c87189c3c09a68d02fa4987a40b64d8fc292b4e4bdfa6aa1625d4b4e347a",
    "0x617005b62e4dcbb8498f7b5f43ead4675593ccc72cf8b2f4a01fa2e1da60b1a",
    "0xa1251b1b798a04e658b1434bd328d5f3ee68e1ac1bb6e817ea31475f0f47a56",
    "0xb336196b7d36dde674677dfba167bec7603a3c96bf20899a9d4c616f0ffa402",
    "0x128e08a771214fc069a55f842eeb0a8c370a8c94cbbd573432466b555f9231f1",
    "0xc790be90ed5461394e69ff6624b1e65fbe25dc9daebfee6b6965a039eff3744",
    "0xb586c3356fa5d91c8bc23605141464545007477bcc96acbbe8efced6246e980",
    "0xa728798fadfc910fd1549526343488b5ee1de16c9471212c85b85892f5b60e4",
    "0xb88a3d215d130dfb3c39c7ed503303704b58e16d7710dfb5f9bf9e3d5a20e8d",
    "0xa1d326b6b608ad8565c3e8e7e7ccd497d4cca0ee291f9a73114b4e9824cfb69",
    "0x57113400390d93f8389e1bec27e88e0793cd3949228717f795276915d4ab828",
    "0x84a8a42dfee951df4471112d863f64d7d5460f046289b4421087d3869e1a1a4",
    "0xd23209a191a79b5e7228d9d19956724a256c57bbb7136be0864edd0a70ff5b6",
    "0x6f851da6c82b3a1a672bd64a45143572b504037935f373bf7baf8299342cb26",
    "0x7eaafe8322cc00fd21fba188b4e00ce5a7549316735482ff55f8de90f17492a",
    "0xa2c1b6cd105105347b6cccf1b0a75124a4e7232b12fb39925e7c2f776e5ba30",
    "0xce6cab1e12a67f98fc9705ffa96c8a10e4c11f29a31ce28273bf8b50c7e4729",
    "0xfd2ae97a893ddc5aabf968d4067b6e7da71e548bd744e13179410dd4ad40fe2",
    "0xc397b9593b7e3a15609549af9ee1c305ace3233a8b70d791d47d273091a197b",
    "0x48e2850c540b39acc7bce93429d2bde169ec7249b3cf361bd3f7de3f51d576f",
    "0xc2d5af8414c6c7ce014f345fc6b0bd90d313d794f3274e7396b18eee353c6e1",
    "0x5232e19ed5be0cc0a6f158edcca9fcdb53684db1379a6ccd0cd9b43e898cd1e",
    "0x121d8e282bba81dc8a608140dde24856e4289abbc1cc213c85842db14a7392c3",
    "0x11ac4b1250a86aa1cdb9b103d9bcc7d6ba641d012ef557ada2e571e27d241708",
    "0x56a6c575f7a3ee274f91e6fca0233d3e4a9bb1eb3c58fb052af73acc8df2b7a",
    "0xbca1f27ae2e39fd568b543f19336d2d1003446982b00317eafb7a56bcd06730",
    "0xe9f191a928aa8c498873d150994e6bca51cdbdaf2285eccb2aaa93cc73291d",
    "0x4465495bdea2589718a8f12ad7198273aea88c72442ddf8d879093cc51a7586",
    "0x1040f9e259df7c4a09ed900afcee53107c7608b276477ae51b3b4bfd40e2b825",
    "0x11d223e26d5c6ba13a8c4382a51f62d97cc553f9be8770470cbd248deda5044f",
    "0x3bf579fa65a5e93fbd27d67791c493cecaa1c55b505c526b84c738b073e085e",
    "0x7967b3d5778a590b6cc278493a64559445188c3cdb0224585c60603f73a6014",
    "0xbf4c86a238f1e63bde595027513d18e26fa557cb4ba00196159778578133cb0",
    "0xa582308f6a557cb37cb0a615659d7211f228a09f591fa0a4f28b7cb42b4bde8",
    "0xdcc13ae2b4c6179a435253fcbb275f8e4ee4c1cb0eae8d679b512a299a56dc8",
    "0xcf02a438c9896590f44512473a4dd39cbc1bde9a53f0b3db38fb6d2f18e91a8",
    "0x5c647cd7fc470cc99e170e20270423b8eee990919b1b09cfc4a386e6fe5a2ce",
    "0x6a3eee48a5ca08253fb4269241ed389e45ba8db152b8850de999b2de2c10257",
    "0xe4b0350a154112207e2eecfc173ad3896cf9a7d8942249c71bf318f329141e8",
    "0x7e7370481cc29ffce69ba474f5655078ab875161563fbc9379890411996613b",
    "0x28d1224a254fc72827cd40c6e516f74b412cb9bffe167294ebdeda4f2dca32f",
    "0xedd071622a8d683a1ac9143eccbf8716b3dfe11fa0ae2aba3abe87d615de44a",
    "0x10ba95e17edfec41ca46d94471f755059fe31b505746f9d5401c127cdc295aa3",
    "0x87f089986c09c923d0546aa9a950094fbf66086c5877be7495806dc6ff1e75e",
    "0x1881b97f72998e6c78f6fd491a33dedc163190de20923ab7b3198af285a9aa7",
    "0x99c71834ef68ccc063eb2b57cf6967e2d5e08cdb32eafba0ddc659323b49a9e",
    "0xa4312710936ff86b44d9bbe51dd26faf32bdc6f774eac9dbcf1c96faba24394",
    "0x19e2b92497e2585e28fd0c5cbdad9c93faa238d34d5eb24a3e8e81ac9b5f343",
];

#[inline]
fn fr_from_hex_be_loose(hex: &str) -> Bls12377Fr {
    let h = hex.strip_prefix("0x").expect("0x-prefixed hex");
    assert!(h.len() <= 64, "expected <= 32 bytes of hex, got {} chars", h.len());
    assert!(h.len() % 2 == 0, "expected even number of hex chars");

    // Left-pad with zeros to 32 bytes.
    let mut padded = String::with_capacity(64);
    for _ in 0..(64 - h.len()) {
        padded.push('0');
    }
    padded.push_str(h);

    let mut be = [0u8; 32];
    for i in 0..32 {
        let byte = u8::from_str_radix(&padded[2 * i..2 * i + 2], 16).expect("hex byte");
        be[i] = byte;
    }
    let mut le = be;
    le.reverse();

    let mut repr = <FFBls12377Fr as FFPrimeField>::Repr::default();
    for (i, digit) in repr.0.as_mut().iter_mut().enumerate() {
        *digit = le[i];
    }

    let value = FFBls12377Fr::from_repr(repr);
    if value.is_some().into() {
        Bls12377Fr { value: value.unwrap() }
    } else {
        panic!("Invalid BLS12-377 field element: {hex}")
    }
}

pub fn bls12377_poseidon2_rc3() -> &'static Vec<[Bls12377Fr; WIDTH]> {
    static RC3: OnceLock<Vec<[Bls12377Fr; WIDTH]>> = OnceLock::new();
    RC3.get_or_init(|| {
        let zero = Bls12377Fr::zero();

        let mut out = Vec::<[Bls12377Fr; WIDTH]>::with_capacity(TOTAL_ROUNDS);
        let mut i = 0usize;

        // First half of full rounds: 4 rounds, 3 constants each.
        for _ in 0..(ROUNDS_F / 2) {
            let c0 = fr_from_hex_be_loose(ICICLE_ROUNDS_CONSTANTS_3[i]);
            let c1 = fr_from_hex_be_loose(ICICLE_ROUNDS_CONSTANTS_3[i + 1]);
            let c2 = fr_from_hex_be_loose(ICICLE_ROUNDS_CONSTANTS_3[i + 2]);
            out.push([c0, c1, c2]);
            i += 3;
        }

        // Partial rounds: 37 rounds, 1 constant (lane 0) each.
        for _ in 0..ROUNDS_P {
            let c0 = fr_from_hex_be_loose(ICICLE_ROUNDS_CONSTANTS_3[i]);
            out.push([c0, zero, zero]);
            i += 1;
        }

        // Second half of full rounds: 4 rounds, 3 constants each.
        for _ in 0..(ROUNDS_F / 2) {
            let c0 = fr_from_hex_be_loose(ICICLE_ROUNDS_CONSTANTS_3[i]);
            let c1 = fr_from_hex_be_loose(ICICLE_ROUNDS_CONSTANTS_3[i + 1]);
            let c2 = fr_from_hex_be_loose(ICICLE_ROUNDS_CONSTANTS_3[i + 2]);
            out.push([c0, c1, c2]);
            i += 3;
        }

        assert_eq!(out.len(), TOTAL_ROUNDS);
        assert_eq!(i, ICICLE_ROUNDS_CONSTANTS_3.len(), "unexpected ICICLE RC3 length");
        out
    })
}


