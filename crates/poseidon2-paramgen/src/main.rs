use std::collections::VecDeque;
use std::fs;
use std::io::Write;
use std::path::Path;

use hex::ToHex;
use num_bigint::BigUint;
use num_traits::{One, Zero};

/// Poseidon2 parameter generation for prime fields following HorizenLabs' `poseidon2_rust_params.sage`.
///
/// This binary regenerates the round constants used by the *native-field* Poseidon2 instance
/// for `t=3, alpha=5, R_F=8, R_P=56` over BLS12-377 scalar field.
///
/// It emits:
/// - a Rust module with `bls12377_poseidon2_rc3()` for SP1's recursion core
/// - a Go file containing `rc3Vals` for gnark-ffi Poseidon2.
fn main() {
    // BLS12-377 scalar field modulus (arkworks: `ark-bls12-377` Fr modulus)
    let p = BigUint::parse_bytes(
        b"8444461749428370424248824938781546531375899335154063827935233455917409239041",
        10,
    )
    .expect("valid modulus");

    // Matches SP1 outer recursion Poseidon2 instance (see sp1 recursion core `outer_perm()`):
    let field: u32 = 1; // prime field
    let sbox: u32 = 0; // matches HorizenLabs script default (Poseidon2 SBOX flag)
    let n_bits: usize = p.bits() as usize;
    let t: usize = 3;
    let r_f: usize = 8;
    let r_p: usize = 56;

    let rc3 = generate_poseidon2_rc3_prime_field(field, sbox, n_bits, t, r_f, r_p, &p);

    let out_rust = Path::new(
        "vendor/sp1-bls12-377/crates/recursion/core/src/stark/poseidon2_bls12377_rc3.rs",
    );
    let out_go = Path::new(
        "vendor/sp1-bls12-377/crates/recursion/gnark-ffi/go/sp1/poseidon2/rc3_bls12377_generated.go",
    );

    write_rust_rc3_module(out_rust, &rc3);
    write_go_rc3_vals(out_go, &rc3);

    eprintln!(
        "Generated Poseidon2 RC3 for BLS12-377: wrote {} and {}",
        out_rust.display(),
        out_go.display()
    );
}

fn generate_poseidon2_rc3_prime_field(
    field: u32,
    sbox: u32,
    n_bits: usize,
    t: usize,
    r_f: usize,
    r_p: usize,
    prime: &BigUint,
) -> Vec<[BigUint; 3]> {
    assert_eq!(t, 3, "this generator currently emits rc3 (t=3)");
    assert_eq!(r_f % 2, 0, "Poseidon2 requires even R_F");
    let rounds = r_f + r_p;
    let r_f_half = r_f / 2;

    let mut grain = Grain::new(field, sbox, n_bits, t, r_f, r_p);
    let mut out = Vec::with_capacity(rounds);

    for r in 0..rounds {
        let is_partial = r >= r_f_half && r < (r_f_half + r_p);

        let c0 = grain.sample_below_modulus(n_bits, prime);
        let row = if is_partial {
            [c0, BigUint::zero(), BigUint::zero()]
        } else {
            let c1 = grain.sample_below_modulus(n_bits, prime);
            let c2 = grain.sample_below_modulus(n_bits, prime);
            [c0, c1, c2]
        };
        out.push(row);
    }

    out
}

/// Implements the Grain LFSR-like generator from `poseidon2_rust_params.sage`.
struct Grain {
    state: VecDeque<u8>,
}

impl Grain {
    fn new(field: u32, sbox: u32, n_bits: usize, t: usize, r_f: usize, r_p: usize) -> Self {
        let mut init = Vec::with_capacity(80);
        init.extend(bits_be(field, 2));
        init.extend(bits_be(sbox, 4));
        init.extend(bits_be(n_bits as u32, 12));
        init.extend(bits_be(t as u32, 12));
        init.extend(bits_be(r_f as u32, 10));
        init.extend(bits_be(r_p as u32, 10));
        init.extend(std::iter::repeat(1u8).take(30));
        assert_eq!(init.len(), 80);

        let mut state: VecDeque<u8> = init.into_iter().collect();

        // Warm-up: 160 steps.
        for _ in 0..160 {
            step(&mut state);
        }

        Self { state }
    }

    fn next_bit(&mut self) -> u8 {
        // Mirrors:
        // new_bit = step()
        // while new_bit == 0: step(); step()
        // new_bit = step(); yield new_bit
        let mut new_bit = step(&mut self.state);
        while new_bit == 0 {
            let _ = step(&mut self.state);
            new_bit = step(&mut self.state);
        }
        new_bit = step(&mut self.state);
        new_bit
    }

    fn random_bits(&mut self, num_bits: usize) -> BigUint {
        let mut x = BigUint::zero();
        for _ in 0..num_bits {
            let b = self.next_bit();
            x <<= 1u8;
            if b == 1 {
                x += BigUint::one();
            }
        }
        x
    }

    fn sample_below_modulus(&mut self, num_bits: usize, modulus: &BigUint) -> BigUint {
        loop {
            let x = self.random_bits(num_bits);
            if &x < modulus {
                return x;
            }
        }
    }
}

fn step(state: &mut VecDeque<u8>) -> u8 {
    let new_bit = state[62] ^ state[51] ^ state[38] ^ state[23] ^ state[13] ^ state[0];
    state.pop_front();
    state.push_back(new_bit);
    new_bit
}

fn bits_be(x: u32, width: usize) -> impl Iterator<Item = u8> {
    (0..width).map(move |i| {
        let shift = (width - 1 - i) as u32;
        ((x >> shift) & 1) as u8
    })
}

fn write_rust_rc3_module(path: &Path, rc3: &[[BigUint; 3]]) {
    // Render as little-endian bytes so we can construct `FFBls12377Fr` without parsing.
    let mut s = String::new();
    s.push_str("//! Auto-generated Poseidon2 round constants for BLS12-377 Fr (t=3).\n");
    s.push_str("//!\n");
    s.push_str("//! Generated by `crates/poseidon2-paramgen` from HorizenLabs `poseidon2_rust_params.sage`.\n");
    s.push_str("//! Do not edit by hand.\n\n");
    s.push_str("use std::sync::OnceLock;\n\n");
    s.push_str("use ff::PrimeField as FFPrimeField;\n");
    s.push_str("use p3_bls12_377_fr::{Bls12377Fr, FFBls12377Fr};\n\n");

    s.push_str(&format!(
        "const RC3_LE_BYTES: [[[u8; 32]; 3]; {}] = [\n",
        rc3.len()
    ));
    for row in rc3 {
        s.push_str("    [\n");
        for elem in row {
            let mut le = elem.to_bytes_le();
            le.resize(32, 0u8);
            let bytes: [u8; 32] = le.try_into().expect("32 bytes");
            s.push_str("        [");
            for (i, b) in bytes.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                s.push_str(&format!("0x{b:02x}"));
            }
            s.push_str("],\n");
        }
        s.push_str("    ],\n");
    }
    s.push_str("];\n\n");

    s.push_str("fn bls12377_from_le_bytes(bytes: [u8; 32]) -> Bls12377Fr {\n");
    s.push_str("    let mut repr = <FFBls12377Fr as FFPrimeField>::Repr::default();\n");
    s.push_str("    for (i, digit) in repr.0.as_mut().iter_mut().enumerate() {\n");
    s.push_str("        *digit = bytes[i];\n");
    s.push_str("    }\n");
    s.push_str("    let value = FFBls12377Fr::from_repr(repr);\n");
    s.push_str("    if value.is_some().into() {\n");
    s.push_str("        Bls12377Fr { value: value.unwrap() }\n");
    s.push_str("    } else {\n");
    s.push_str("        panic!(\"Invalid field element\")\n");
    s.push_str("    }\n");
    s.push_str("}\n\n");

    s.push_str("pub fn bls12377_poseidon2_rc3() -> &'static Vec<[Bls12377Fr; 3]> {\n");
    s.push_str("    static RC: OnceLock<Vec<[Bls12377Fr; 3]>> = OnceLock::new();\n");
    s.push_str("    RC.get_or_init(|| {\n");
    s.push_str("        RC3_LE_BYTES\n");
    s.push_str("            .iter()\n");
    s.push_str("            .map(|row| {\n");
    s.push_str("                [\n");
    s.push_str("                    bls12377_from_le_bytes(row[0]),\n");
    s.push_str("                    bls12377_from_le_bytes(row[1]),\n");
    s.push_str("                    bls12377_from_le_bytes(row[2]),\n");
    s.push_str("                ]\n");
    s.push_str("            })\n");
    s.push_str("            .collect()\n");
    s.push_str("    })\n");
    s.push_str("}\n");

    write_file_atomic(path, s.as_bytes());
}

fn write_go_rc3_vals(path: &Path, rc3: &[[BigUint; 3]]) {
    let mut s = String::new();
    s.push_str("// Code generated by `poseidon2-paramgen`. DO NOT EDIT.\n");
    s.push_str("// Source generator: HorizenLabs `poseidon2_rust_params.sage` (Grain-based RC generation).\n\n");
    s.push_str("package poseidon2\n\n");
    s.push_str("import \"github.com/consensys/gnark/frontend\"\n\n");
    s.push_str(&format!(
        "var rc3Vals = [{}][width]frontend.Variable{{\n",
        rc3.len()
    ));
    for row in rc3 {
        s.push_str("    {");
        for (i, elem) in row.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            let mut be = elem.to_bytes_be();
            if be.len() > 32 {
                panic!("field element does not fit in 32 bytes");
            }
            if be.len() < 32 {
                let mut padded = vec![0u8; 32 - be.len()];
                padded.extend_from_slice(&be);
                be = padded;
            }
            let hex = be.encode_hex::<String>();
            s.push_str(&format!("frontend.Variable(\"0x{hex}\")"));
        }
        s.push_str("},\n");
    }
    s.push_str("}\n");
    write_file_atomic(path, s.as_bytes());
}

fn write_file_atomic(path: &Path, contents: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create output dirs");
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp).expect("create tmp");
        f.write_all(contents).expect("write tmp");
        f.sync_all().ok();
    }
    fs::rename(tmp, path).expect("atomic rename");
}


