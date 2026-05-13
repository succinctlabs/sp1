//! Execute bn254-c against host-side substrate-bn computations.

use rand::rngs::OsRng;
use sp1_sdk::{utils, Elf, Prover, ProverClient, SP1Stdin};
use substrate_bn::{AffineG1, AffineG2, Fr, Group, G1, G2};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("BN254_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

fn encode_g1(p: G1) -> [u8; 64] {
    let mut out = [0u8; 64];
    if let Some(a) = AffineG1::from_jacobian(p) {
        a.x().to_big_endian(&mut out[0..32]).unwrap();
        a.y().to_big_endian(&mut out[32..64]).unwrap();
    }
    out
}

/// EIP-197 G2 layout: `x.a1 || x.a0 || y.a1 || y.a0`, each 32 bytes BE.
fn encode_g2(p: G2) -> [u8; 128] {
    let mut out = [0u8; 128];
    if let Some(a) = AffineG2::from_jacobian(p) {
        a.x().imaginary().to_big_endian(&mut out[0..32]).unwrap();
        a.x().real().to_big_endian(&mut out[32..64]).unwrap();
        a.y().imaginary().to_big_endian(&mut out[64..96]).unwrap();
        a.y().real().to_big_endian(&mut out[96..128]).unwrap();
    }
    out
}

fn fr_to_be(s: Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    s.into_u256().to_big_endian(&mut out).unwrap();
    out
}

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let client = ProverClient::builder().light().build().await;
    let mut rng = OsRng;

    // ---- g1_add: compute A = a*G, B = b*G; ask guest to add; check vs (a+b)*G.
    let a = Fr::random(&mut rng);
    let b = Fr::random(&mut rng);
    let big_a = G1::one() * a;
    let big_b = G1::one() * b;
    let expected_add = G1::one() * (a + b);

    let mut input = Vec::with_capacity(1 + 128);
    input.push(0); // mode = g1_add
    input.extend_from_slice(&encode_g1(big_a));
    input.extend_from_slice(&encode_g1(big_b));
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);
    let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
    info!(cycles = report.total_instruction_count() + report.total_syscall_count(), "g1_add",);
    assert_eq!(public_values.as_slice(), encode_g1(expected_add));

    // ---- g1_mul: ask guest to compute scalar*A; check vs (scalar*a)*G.
    let scalar = Fr::random(&mut rng);
    let expected_mul = big_a * scalar;
    let mut input = Vec::with_capacity(1 + 96);
    input.push(1); // mode = g1_mul
    input.extend_from_slice(&encode_g1(big_a));
    input.extend_from_slice(&fr_to_be(scalar));
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);
    let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
    info!(cycles = report.total_instruction_count() + report.total_syscall_count(), "g1_mul",);
    assert_eq!(public_values.as_slice(), encode_g1(expected_mul));

    // ---- g1_add: identity preserved (P + 0 = P).
    let mut input = Vec::with_capacity(1 + 128);
    input.push(0);
    input.extend_from_slice(&encode_g1(big_a));
    input.extend_from_slice(&[0u8; 64]);
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);
    let (public_values, _) = client.execute(ELF, stdin).await.unwrap();
    assert_eq!(public_values.as_slice(), encode_g1(big_a));

    info!("bn254-c g1_add and g1_mul match host-side substrate-bn results");

    // ---- pairing: empty pairing must verify (Π over zero pairs = 1).
    let mut input = vec![2u8]; // mode = pairing
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);
    let (public_values, _) = client.execute(ELF, stdin).await.unwrap();
    assert_eq!(public_values.as_slice(), &[1], "empty pairing should verify");

    // ---- pairing: bilinearity check via e(aP, Q) * e(-aP, Q) == 1.
    let a = Fr::random(&mut rng);
    let p = G1::one() * a;
    let q = G2::one();
    input.clear();
    input.push(2);
    input.extend_from_slice(&encode_g1(p));
    input.extend_from_slice(&encode_g2(q));
    input.extend_from_slice(&encode_g1(-p));
    input.extend_from_slice(&encode_g2(q));
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);
    let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
    info!(
        cycles = report.total_instruction_count() + report.total_syscall_count(),
        "pairing(P,Q)·pairing(-P,Q)",
    );
    assert_eq!(public_values.as_slice(), &[1], "e(P,Q)·e(-P,Q) should equal 1");

    // ---- pairing: a single non-trivial pair (P, Q) must NOT verify.
    input.clear();
    input.push(2);
    input.extend_from_slice(&encode_g1(p));
    input.extend_from_slice(&encode_g2(q));
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);
    let (public_values, _) = client.execute(ELF, stdin).await.unwrap();
    assert_eq!(public_values.as_slice(), &[0], "single non-trivial pairing should not be 1");

    info!("bn254-c pairing matches host-side substrate-bn pairing_batch");

    // ---- EIP-196 g1_add golden vectors.
    for v in zkevm_fixtures::eip196::add_vectors() {
        let mut input = Vec::with_capacity(1 + 128);
        input.push(0); // mode = g1_add
        input.extend_from_slice(&v.p1);
        input.extend_from_slice(&v.p2);
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (public_values, _) = client.execute(ELF, stdin).await.unwrap();
        assert_eq!(public_values.as_slice(), &v.expected[..], "eip-196 g1_add[{}]", v.name);
    }
    info!("all eip-196 g1_add golden vectors match");

    // ---- EIP-196 g1_mul golden vectors.
    for v in zkevm_fixtures::eip196::mul_vectors() {
        let mut input = Vec::with_capacity(1 + 96);
        input.push(1); // mode = g1_mul
        input.extend_from_slice(&v.point);
        input.extend_from_slice(&v.scalar);
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (public_values, _) = client.execute(ELF, stdin).await.unwrap();
        assert_eq!(public_values.as_slice(), &v.expected[..], "eip-196 g1_mul[{}]", v.name);
    }
    info!("all eip-196 g1_mul golden vectors match");

    // ---- EIP-197 pairing golden vectors.
    for v in zkevm_fixtures::eip197::vectors() {
        let mut input = Vec::with_capacity(1 + v.pairs.len());
        input.push(2); // mode = pairing
        input.extend_from_slice(&v.pairs);
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (public_values, _) = client.execute(ELF, stdin).await.unwrap();
        let expected = if v.expected_verified { &[1u8][..] } else { &[0u8][..] };
        assert_eq!(public_values.as_slice(), expected, "eip-197 pairing[{}]", v.name);
    }
    info!("all eip-197 pairing golden vectors match");
}
