//! Witness-vector dumper — the **completeness / conformance** companion to the constraint
//! extractor (`main.rs`, `--format lean`).
//!
//! The constraint extractor symbolically captures each operation's `eval` (it is generic over
//! `AB: SP1AirBuilder`, so a recording builder can record every constraint). Witness generation
//! (`populate`) is *not* symbolically capturable the same way: it is native imperative code over
//! concrete `u64`/`u8` with data-dependent control flow, so there is no builder to swap out. This
//! binary therefore ties the Lean witness functions to the Rust source by **conformance test
//! vectors** instead of symbolic extraction: it calls the real `populate` on a fixed, reproducible
//! battery of inputs (edge cases + a seeded LCG) and dumps, per input, the resulting column field
//! values and the `ByteLookupEvent`s that `populate` emitted.
//!
//! `update_extracted.py` reads this JSON and writes `SP1CleanNative/Extracted/<Op>WitnessVectors.lean`;
//! the conformance checks in `SP1CleanNative/Faithful/<Op>Witness.lean` then `#guard` that the
//! (factored-out) Lean `witness` function reproduces these column values for each vector. This is
//! agreement on the sampled inputs, *not* an all-inputs proof — edge-case coverage is the mitigation.
//!
//! It is strictly **additive** and **read-only** w.r.t. SP1 operation/chip logic: nothing here
//! touches `eval`/`populate`/the column structs. The emitted byte events double as a tie to the
//! `.send (.byte …)` entries in the extracted constraint list.
//!
//! Usage: `cargo run -q -p sp1-constraint-compiler --bin witness_vectors -- --operation AddOperation`
//! (emits JSON to stdout).

use clap::Parser;
use serde_json::{json, Value};

use slop_algebra::PrimeField32;
use sp1_core_executor::events::ByteLookupEvent;
use sp1_core_machine::operations::{AddOperation, LtOperationUnsigned, SubOperation};
use sp1_primitives::{consts::u64_to_u16_limbs, SP1Field};

type F = SP1Field;

#[derive(Parser, Debug)]
#[command(author, version, about = "Dump witness-generation (populate) conformance vectors", long_about = None)]
struct Args {
    /// Operation name to dump vectors for (e.g. `AddOperation`).
    #[arg(long)]
    operation: String,
}

/// A tiny deterministic LCG (Numerical Recipes constants) so the random portion of the input
/// battery is **reproducible** across runs — regenerating must not churn the emitted Lean file.
/// `Date.now()`/`rand` are deliberately avoided.
struct Lcg(u64);
impl Lcg {
    fn next_u64(&mut self) -> u64 {
        // Two LCG steps composed into a full 64-bit word (the low bits of an LCG are weak).
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let hi = self.0;
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (hi & 0xFFFF_FFFF_0000_0000) | (self.0 >> 32)
    }
}

/// Serialize one emitted `ByteLookupEvent` as `{opcode, a, b, c}` with `opcode` as its numeric
/// discriminant (AND=0 … Range=6), matching the Lean `ByteOpcode.ofNat n` mapping.
fn event_json(e: &ByteLookupEvent) -> Value {
    json!({ "opcode": e.opcode as u8, "a": e.a, "b": e.b, "c": e.c })
}

/// Read a column word's limbs back as their canonical integers (KoalaBear → u32).
fn limbs<const N: usize>(w: &[F; N]) -> Vec<u32> {
    w.iter().map(|x| x.as_canonical_u32()).collect()
}

/// The 64-bit operand battery shared by the binary ALU ops: hand-listed edge cases (zero, max,
/// per-limb carry boundaries, sign-bit-set) followed by a seeded-LCG random tail.
fn u64_battery() -> Vec<u64> {
    let mut v = vec![
        0,
        1,
        0xFFFF,                 // limb-0 boundary
        0x1_0000,
        0xFFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,  // all-ones (full wrap)
        0x8000_0000_0000_0000,  // sign bit set
        0x7FFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_0000_0000,
        0x0000_0000_FFFF_FFFF,
        42,
        1234567890,
    ];
    let mut lcg = Lcg(0x5151_5151_2727_2727);
    for _ in 0..32 {
        v.push(lcg.next_u64());
    }
    v
}

/// Dump conformance vectors for a `Word`-valued binary ALU op whose `populate(blu, a, b) -> u64`
/// computes the result and writes a single `Word` column (Add, Sub). `pop` runs the real `populate`
/// and returns `(output, value_limbs)`; the operand pairing and battery are shared.
fn word_op_vectors(
    name: &str,
    mut pop: impl FnMut(&mut Vec<ByteLookupEvent>, u64, u64) -> (u64, Vec<u32>),
) -> Value {
    let battery = u64_battery();
    let n = battery.len();
    let mut vectors = Vec::new();
    // Pair each battery value with itself, its successor (wrap-around coverage), and a few crosses.
    for (i, &a) in battery.iter().enumerate() {
        for &b in &[battery[i], battery[(i + 1) % n], battery[(i + 7) % n]] {
            let mut blu = Vec::<ByteLookupEvent>::new();
            let (out, value) = pop(&mut blu, a, b);
            blu.sort_by_key(|e| (e.opcode as u8, e.a, e.b, e.c));
            vectors.push(json!({
                "inputs": { "a": a, "b": b },
                // Operand u16 limbs (SP1's little-endian `Word` convention) — the form the Lean
                // `witness` function consumes, so the conformance check needs no re-derivation.
                "a_limbs": u64_to_u16_limbs(a),
                "b_limbs": u64_to_u16_limbs(b),
                "output": out,
                "value": value,
                "events": blu.iter().map(event_json).collect::<Vec<_>>(),
            }));
        }
    }
    json!({ "operation": name, "vectors": vectors })
}

/// `LtOperationUnsigned::populate_unsigned(a, b, c)` — scans `b`/`c`'s u16 limbs from the top for the
/// first differing pair, writing the one-hot `u16_flags`, the differing `comparison_limbs`, and the
/// **field inverse** `not_eq_inv = (b_limb - c_limb)⁻¹` (the column with no ℕ analogue). The `a`
/// argument (the `b < c` result bit) feeds only the nested `U16CompareOperation`, not the columns
/// dumped here, so we pass the true `b < c`.
fn lt_unsigned_vectors() -> Value {
    let battery = u64_battery();
    let n = battery.len();
    let mut vectors = Vec::new();
    for (i, &b) in battery.iter().enumerate() {
        for &c in &[battery[i], battery[(i + 1) % n], battery[(i + 7) % n]] {
            let mut cols = LtOperationUnsigned::<F>::default();
            let mut blu = Vec::<ByteLookupEvent>::new();
            cols.populate_unsigned(&mut blu, (b < c) as u64, b, c);
            vectors.push(json!({
                "inputs": { "b": b, "c": c },
                "b_limbs": u64_to_u16_limbs(b),
                "cc_limbs": u64_to_u16_limbs(c),
                "comparison_limbs": limbs(&cols.comparison_limbs),
                "u16_flags": limbs(&cols.u16_flags),
                // The inverse column: KoalaBear canonical value of `(b_limb - c_limb)⁻¹`.
                "not_eq_inv": cols.not_eq_inv.as_canonical_u32(),
            }));
        }
    }
    json!({ "operation": "LtOperationUnsigned", "vectors": vectors })
}

fn main() {
    let args = Args::parse();
    let out = match args.operation.as_str() {
        // `AddOperation::populate` = `a.wrapping_add(b)`; `SubOperation::populate` = `a.wrapping_sub(b)`.
        // Both write a single `value : Word` column + one `Range` event per limb.
        "AddOperation" => word_op_vectors("AddOperation", |blu, a, b| {
            let mut c = AddOperation::<F>::default();
            let out = c.populate(blu, a, b);
            (out, limbs(&c.value.0))
        }),
        "SubOperation" => word_op_vectors("SubOperation", |blu, a, b| {
            let mut c = SubOperation::<F>::default();
            let out = c.populate(blu, a, b);
            (out, limbs(&c.value.0))
        }),
        "LtOperationUnsigned" => lt_unsigned_vectors(),
        other => {
            eprintln!("Error: operation '{other}' has no witness-vector dumper yet");
            std::process::exit(1);
        }
    };
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
