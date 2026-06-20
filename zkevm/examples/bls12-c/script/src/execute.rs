//! Execute bls12-c against host-side bls12_381 computations.

use bls12_381::hash_to_curve::MapToCurve;
use bls12_381::{fp, fp2, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;
use rand::rngs::OsRng;
use sp1_sdk::{utils, Elf, Prover, ProverClient, SP1Stdin};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("BLS12_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let client = ProverClient::builder().light().build().await;
    let mut rng = OsRng;

    // ---- g1_add ----
    {
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let big_a = G1Affine::from(G1Projective::generator() * a);
        let big_b = G1Affine::from(G1Projective::generator() * b);
        let expected = G1Affine::from(G1Projective::generator() * (a + b)).to_uncompressed();

        let mut input = Vec::with_capacity(1 + 192);
        input.push(0);
        input.extend_from_slice(&big_a.to_uncompressed());
        input.extend_from_slice(&big_b.to_uncompressed());
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
        info!(cycles = report.total_instruction_count() + report.total_syscall_count(), "g1_add",);
        assert_eq!(public_values.as_slice(), expected);
    }

    // ---- g2_add ----
    {
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let big_a = G2Affine::from(G2Projective::generator() * a);
        let big_b = G2Affine::from(G2Projective::generator() * b);
        let expected = G2Affine::from(G2Projective::generator() * (a + b)).to_uncompressed();

        let mut input = Vec::with_capacity(1 + 384);
        input.push(1);
        input.extend_from_slice(&big_a.to_uncompressed());
        input.extend_from_slice(&big_b.to_uncompressed());
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
        info!(cycles = report.total_instruction_count() + report.total_syscall_count(), "g2_add",);
        assert_eq!(public_values.as_slice(), expected);
    }

    // ---- pairing: e(g1, g2) * e(-g1, g2) == 1 (should verify) ----
    {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let neg_g1 = G1Affine::from(-G1Projective::from(g1));
        let mut input = Vec::with_capacity(1 + 2 * (96 + 192));
        input.push(2);
        input.extend_from_slice(&g1.to_uncompressed());
        input.extend_from_slice(&g2.to_uncompressed());
        input.extend_from_slice(&neg_g1.to_uncompressed());
        input.extend_from_slice(&g2.to_uncompressed());
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
        info!(
            cycles = report.total_instruction_count() + report.total_syscall_count(),
            "pairing (cancelling pair)",
        );
        assert_eq!(public_values.as_slice(), &[1u8]);
    }

    // ---- pairing: single non-cancelling pair (should NOT verify) ----
    {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let mut input = Vec::with_capacity(1 + (96 + 192));
        input.push(2);
        input.extend_from_slice(&g1.to_uncompressed());
        input.extend_from_slice(&g2.to_uncompressed());
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
        info!(
            cycles = report.total_instruction_count() + report.total_syscall_count(),
            "pairing (single non-trivial pair)",
        );
        assert_eq!(public_values.as_slice(), &[0u8]);
    }

    // ---- map_fp_to_g1 ----
    {
        // Use the BLS12-381 modulus minus a small offset to get a non-zero Fp
        // that's deterministic and easy to encode.
        let mut fp_bytes = [0u8; 48];
        fp_bytes[47] = 5;
        let fp_in = fp::Fp::from_bytes(&fp_bytes).unwrap();
        let expected =
            G1Affine::from(G1Projective::map_to_curve(&fp_in).clear_cofactor()).to_uncompressed();

        let mut input = Vec::with_capacity(1 + 48);
        input.push(3);
        input.extend_from_slice(&fp_bytes);
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
        info!(
            cycles = report.total_instruction_count() + report.total_syscall_count(),
            "map_fp_to_g1",
        );
        assert_eq!(public_values.as_slice(), expected);
    }

    // ---- map_fp2_to_g2 ----
    {
        let mut c0_bytes = [0u8; 48];
        c0_bytes[47] = 7;
        let mut c1_bytes = [0u8; 48];
        c1_bytes[47] = 11;
        let c0 = fp::Fp::from_bytes(&c0_bytes).unwrap();
        let c1 = fp::Fp::from_bytes(&c1_bytes).unwrap();
        let fp2_in = fp2::Fp2 { c0, c1 };
        let expected =
            G2Affine::from(G2Projective::map_to_curve(&fp2_in).clear_cofactor()).to_uncompressed();

        let mut input = Vec::with_capacity(1 + 96);
        input.push(4);
        input.extend_from_slice(&c1_bytes);
        input.extend_from_slice(&c0_bytes);
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
        info!(
            cycles = report.total_instruction_count() + report.total_syscall_count(),
            "map_fp2_to_g2",
        );
        assert_eq!(public_values.as_slice(), expected);
    }

    // ---- g1_msm: Σ s_i * P_i = result, checked against host bls12_381.
    {
        let pts: [Scalar; 3] =
            [Scalar::random(&mut rng), Scalar::random(&mut rng), Scalar::random(&mut rng)];
        let scalars: [Scalar; 3] =
            [Scalar::random(&mut rng), Scalar::random(&mut rng), Scalar::random(&mut rng)];
        let mut acc = G1Projective::identity();
        let mut input = vec![5u8]; // mode = g1_msm
        for i in 0..3 {
            let p = G1Affine::from(G1Projective::generator() * pts[i]);
            input.extend_from_slice(&p.to_uncompressed());
            input.extend_from_slice(&scalar_to_be(scalars[i]));
            acc += G1Projective::from(p) * scalars[i];
        }
        let expected = G1Affine::from(acc).to_uncompressed();

        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
        info!(
            cycles = report.total_instruction_count() + report.total_syscall_count(),
            num_pairs = 3,
            "g1_msm",
        );
        assert_eq!(public_values.as_slice(), expected);
    }

    // ---- g2_msm: same shape for G2.
    {
        let pts: [Scalar; 3] =
            [Scalar::random(&mut rng), Scalar::random(&mut rng), Scalar::random(&mut rng)];
        let scalars: [Scalar; 3] =
            [Scalar::random(&mut rng), Scalar::random(&mut rng), Scalar::random(&mut rng)];
        let mut acc = G2Projective::identity();
        let mut input = vec![6u8]; // mode = g2_msm
        for i in 0..3 {
            let p = G2Affine::from(G2Projective::generator() * pts[i]);
            input.extend_from_slice(&p.to_uncompressed());
            input.extend_from_slice(&scalar_to_be(scalars[i]));
            acc += G2Projective::from(p) * scalars[i];
        }
        let expected = G2Affine::from(acc).to_uncompressed();

        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
        info!(
            cycles = report.total_instruction_count() + report.total_syscall_count(),
            num_pairs = 3,
            "g2_msm",
        );
        assert_eq!(public_values.as_slice(), expected);
    }

    info!("bls12-c g1_add, g2_add, pairing, map_fp_to_g1, map_fp2_to_g2, g1_msm, g2_msm all match host-side bls12_381");

    // ---- EIP-2537 g1_add golden vectors.
    for v in zkevm_fixtures::eip2537::g1_add_vectors() {
        let mut input = Vec::with_capacity(1 + 192);
        input.push(0); // mode = g1_add
        input.extend_from_slice(&v.p1);
        input.extend_from_slice(&v.p2);
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (public_values, _) = client.execute(ELF, stdin).await.unwrap();
        assert_eq!(public_values.as_slice(), &v.expected[..], "eip-2537 g1_add[{}]", v.name);
    }
    info!("all eip-2537 g1_add golden vectors match");

    // ---- EIP-2537 g2_add golden vectors.
    for v in zkevm_fixtures::eip2537::g2_add_vectors() {
        let mut input = Vec::with_capacity(1 + 384);
        input.push(1); // mode = g2_add
        input.extend_from_slice(&v.p1);
        input.extend_from_slice(&v.p2);
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (public_values, _) = client.execute(ELF, stdin).await.unwrap();
        assert_eq!(public_values.as_slice(), &v.expected[..], "eip-2537 g2_add[{}]", v.name);
    }
    info!("all eip-2537 g2_add golden vectors match");

    // ---- EIP-2537 g1_msm golden vectors.
    for v in zkevm_fixtures::eip2537::g1_msm_vectors() {
        let mut input = Vec::with_capacity(1 + v.pairs.len());
        input.push(5); // mode = g1_msm
        input.extend_from_slice(&v.pairs);
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (public_values, _) = client.execute(ELF, stdin).await.unwrap();
        assert_eq!(public_values.as_slice(), &v.expected[..], "eip-2537 g1_msm[{}]", v.name);
    }
    info!("all eip-2537 g1_msm golden vectors match");

    // ---- EIP-2537 g2_msm golden vectors.
    for v in zkevm_fixtures::eip2537::g2_msm_vectors() {
        let mut input = Vec::with_capacity(1 + v.pairs.len());
        input.push(6); // mode = g2_msm
        input.extend_from_slice(&v.pairs);
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (public_values, _) = client.execute(ELF, stdin).await.unwrap();
        assert_eq!(public_values.as_slice(), &v.expected[..], "eip-2537 g2_msm[{}]", v.name);
    }
    info!("all eip-2537 g2_msm golden vectors match");

    // ---- EIP-2537 pairing golden vectors.
    for v in zkevm_fixtures::eip2537::pairing_vectors() {
        let mut input = Vec::with_capacity(1 + v.pairs.len());
        input.push(2); // mode = pairing
        input.extend_from_slice(&v.pairs);
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (public_values, _) = client.execute(ELF, stdin).await.unwrap();
        let expected = if v.expected_verified { &[1u8][..] } else { &[0u8][..] };
        assert_eq!(public_values.as_slice(), expected, "eip-2537 pairing[{}]", v.name);
    }
    info!("all eip-2537 pairing golden vectors match");
}

/// Encode a Scalar as 32 big-endian bytes. Mirrors `libzkevm::precompile::bls12_381::decode_scalar`
/// (zero-pad to 64 bytes LE for `Scalar::from_bytes_wide`); we just emit the
/// canonical 32-byte BE representation that round-trips through that decoder.
fn scalar_to_be(s: Scalar) -> [u8; 32] {
    let le = s.to_bytes();
    let mut be = [0u8; 32];
    for (i, b) in le.iter().enumerate() {
        be[31 - i] = *b;
    }
    be
}
