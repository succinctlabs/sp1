//! Execute blake2f-c against the EIP-152 canonical test vectors.

use sp1_sdk::{utils, Elf, Prover, ProverClient, SP1Stdin};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("BLAKE2F_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

/// EIP-152 test vectors 4–7. Each entry is `(rounds, h_hex, m_hex, t_hex,
/// f, expected_h_hex)`. h, m, t are little-endian u64 words; expected is
/// the post-compression `h`. h is the BLAKE2b IV XORed with the
/// unkeyed-512 parameter block; m is the message buffer "abc" + 125
/// zero bytes; t = (3, 0). Vector 4 (12 rounds, f=1) coincides with the
/// final state of `BLAKE2b("abc")`.
#[allow(clippy::type_complexity)]
const VECTORS: &[(u32, &str, &str, &str, u8, &str)] = &[
    // Vector 4 — 12 rounds, final block.
    (
        12,
        "48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5\
         d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b",
        "6162630000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000000",
        "03000000000000000000000000000000",
        1,
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
         7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    ),
    // Vector 5 — 1 round, final block.
    (
        1,
        "48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5\
         d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b",
        "6162630000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000000",
        "03000000000000000000000000000000",
        1,
        "b63a380cb2897d521994a85234ee2c181b5f844d2c624c002677e9703449d2fb\
         a551b3a8333bcdf5f2f7e08993d53923de3d64fcc68c034e717b9293fed7a421",
    ),
    // Vector 6 — 1 round, non-final block.
    (
        1,
        "48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5\
         d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b",
        "6162630000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000000",
        "03000000000000000000000000000000",
        0,
        "f5ac05ae4119ecaff1d460125dfb67c8b09905d708331b55c10b6b84d8fb3eea\
         0e741b0c85d57c64c56bbb5b0bf794f7495748b71f97e851ebc1f91fe47e5297",
    ),
    // Vector 7 — 12 rounds, non-final block.
    (
        12,
        "48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5\
         d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b",
        "6162630000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000000",
        "03000000000000000000000000000000",
        0,
        "75ab69d3190a562c51aef8d88f1c2775876944407270c42c9844252c26d28752\
         98743e7f6d5ea2f2d3e8d226039cd31b4e426ac4f2d3d666a610c2116fde4735",
    ),
];

fn build_input(rounds: u32, h: &[u8], m: &[u8], t: &[u8], f: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + 64 + 128 + 16 + 1);
    buf.extend_from_slice(&rounds.to_be_bytes());
    buf.extend_from_slice(h);
    buf.extend_from_slice(m);
    buf.extend_from_slice(t);
    buf.push(f);
    buf
}

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let client = ProverClient::builder().light().build().await;

    for (i, (rounds, h_hex, m_hex, t_hex, f, expected_hex)) in VECTORS.iter().enumerate() {
        let h = hex::decode(h_hex.replace([' ', '\n'], "")).unwrap();
        let m = hex::decode(m_hex.replace([' ', '\n'], "")).unwrap();
        let t = hex::decode(t_hex).unwrap();
        let expected = hex::decode(expected_hex.replace([' ', '\n'], "")).unwrap();

        let input = build_input(*rounds, &h, &m, &t, *f);
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);

        let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
        let out = public_values.as_slice();
        info!(
            vector = i,
            rounds = *rounds,
            cycles = report.total_instruction_count() + report.total_syscall_count(),
            "executed blake2f-c",
        );
        assert_eq!(out, expected.as_slice(), "vector {i} mismatch");
    }
    info!("all blake2f outputs match EIP-152 expected state");
}
