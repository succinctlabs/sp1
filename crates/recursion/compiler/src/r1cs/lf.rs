//! LF-targeted R1CS export + "lift" pass for BabyBear semantics.
//!
//! This module is intended to support proving SP1's BabyBear-native R1CS relation inside
//! LF+ over a large-modulus ring/field (e.g. Frog), by rewriting each BabyBear constraint
//! into an *integer* equality that is meaningful in the host field once LF+ enforces
//! boundedness of all witness values.
//!
//! High level:
//! - Start from BabyBear-native `R1CS<F: PrimeField64>` (F = BabyBear).
//! - Convert all coefficients into centered signed integers in (-(p-1)/2 .. (p-1)/2].
//! - For constraint rows that are *field-agnostic* (boolean / select / equality), keep as-is.
//! - Otherwise, introduce an extra witness variable `q_i` and rewrite:
//!     (A_i·w) * (B_i·w) = (C_i·w) + p_bb * q_i
//!   where `p_bb` is treated as an integer coefficient (not a BabyBear field element).
//!
//! NOTE: This format uses *integer coefficients* (i64) so we can represent `p_bb`.

use crate::r1cs::types::SparseRow;
use p3_field::PrimeField64;
use sp1_primitives::io::sha256_hash;
use std::io::{Read, Write};

/// BabyBear prime modulus (p = 2^31 - 2^27 + 1).
pub const BABYBEAR_P_U64: u64 = 2013265921;

#[inline]
pub fn bb_coeff_to_centered_i64(c: u64) -> i64 {
    // c is in [0, p)
    let p = BABYBEAR_P_U64 as i64;
    let c = c as i64;
    // centered rep in (-(p-1)/2 .. (p-1)/2]
    if c > p / 2 { c - p } else { c }
}

#[derive(Debug, Clone, Default)]
pub struct SparseRowI64 {
    /// (variable_index, coefficient)
    pub terms: Vec<(usize, i64)>,
}

impl SparseRowI64 {
    #[inline]
    pub fn new() -> Self {
        Self { terms: Vec::new() }
    }

    #[inline]
    pub fn add_term(&mut self, var_idx: usize, coeff: i64) {
        if coeff != 0 {
            self.terms.push((var_idx, coeff));
        }
    }

    #[inline]
    pub fn single(var_idx: usize, coeff: i64) -> Self {
        Self { terms: vec![(var_idx, coeff)] }
    }

    #[inline]
    pub fn zero() -> Self {
        Self { terms: Vec::new() }
    }
}

/// LF-targeted R1CS with *signed integer coefficients*.
#[derive(Debug, Clone)]
pub struct R1CSLf {
    pub num_vars: usize,
    pub num_constraints: usize,
    pub num_public: usize,
    pub p_bb: u64,
    pub a: Vec<SparseRowI64>,
    pub b: Vec<SparseRowI64>,
    pub c: Vec<SparseRowI64>,
}

impl R1CSLf {
    /// Compute digest of the LF-targeted R1CS (covers p_bb + all coeffs).
    pub fn digest(&self) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(b"R1CS_LF_DIGEST_v1");
        data.extend_from_slice(&self.p_bb.to_le_bytes());
        data.extend_from_slice(&(self.num_vars as u64).to_le_bytes());
        data.extend_from_slice(&(self.num_constraints as u64).to_le_bytes());
        data.extend_from_slice(&(self.num_public as u64).to_le_bytes());

        fn ser_matrix(dst: &mut Vec<u8>, tag: &[u8], m: &[SparseRowI64]) {
            dst.extend_from_slice(tag);
            for row in m {
                dst.extend_from_slice(&(row.terms.len() as u64).to_le_bytes());
                for (idx, coeff) in &row.terms {
                    dst.extend_from_slice(&(*idx as u64).to_le_bytes());
                    dst.extend_from_slice(&coeff.to_le_bytes());
                }
            }
        }

        ser_matrix(&mut data, b"A_MATRIX", &self.a);
        ser_matrix(&mut data, b"B_MATRIX", &self.b);
        ser_matrix(&mut data, b"C_MATRIX", &self.c);

        let hash_vec = sha256_hash(&data);
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash_vec);
        result
    }

    /// Serialize to binary. This is intentionally self-verifying (digest in header).
    ///
    /// Format:
    /// HEADER (80 bytes fixed):
    ///   - Magic: "R1LF" (4)
    ///   - Version: u32 = 1 (4)
    ///   - Digest: [u8; 32] (32)
    ///   - p_bb: u64 (8)
    ///   - num_vars: u64 (8)
    ///   - num_constraints: u64 (8)
    ///   - num_public: u64 (8)
    ///   - total_nonzeros: u64 (8)
    ///
    /// BODY:
    ///   - For each of A,B,C matrices:
    ///     - For each row:
    ///       - num_terms: u32
    ///       - terms: (var_idx: u32, coeff_i64: i64)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let digest = self.digest();

        let total_nonzeros: u64 = self
            .a
            .iter()
            .chain(self.b.iter())
            .chain(self.c.iter())
            .map(|row| row.terms.len() as u64)
            .sum();

        buf.extend_from_slice(b"R1LF");
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&digest);
        buf.extend_from_slice(&self.p_bb.to_le_bytes());
        buf.extend_from_slice(&(self.num_vars as u64).to_le_bytes());
        buf.extend_from_slice(&(self.num_constraints as u64).to_le_bytes());
        buf.extend_from_slice(&(self.num_public as u64).to_le_bytes());
        buf.extend_from_slice(&total_nonzeros.to_le_bytes());

        for matrix in [&self.a, &self.b, &self.c] {
            for row in matrix {
                buf.extend_from_slice(&(row.terms.len() as u32).to_le_bytes());
                for (idx, coeff) in &row.terms {
                    buf.extend_from_slice(&(*idx as u32).to_le_bytes());
                    buf.extend_from_slice(&coeff.to_le_bytes());
                }
            }
        }
        buf
    }

    pub fn save_to_file(&self, path: &str) -> std::io::Result<()> {
        let bytes = self.to_bytes();
        let mut file = std::fs::File::create(path)?;
        file.write_all(&bytes)?;
        Ok(())
    }

    pub fn read_header(data: &[u8]) -> Result<([u8; 32], u64, usize, usize, usize, u64), &'static str> {
        if data.len() < 80 {
            return Err("R1LF file too small for header");
        }
        if &data[0..4] != b"R1LF" {
            return Err("Invalid R1LF magic");
        }
        let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
        if version != 1 {
            return Err("Unsupported R1LF version (expected 1)");
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&data[8..40]);
        let p_bb = u64::from_le_bytes(data[40..48].try_into().unwrap());
        let num_vars = u64::from_le_bytes(data[48..56].try_into().unwrap()) as usize;
        let num_constraints = u64::from_le_bytes(data[56..64].try_into().unwrap()) as usize;
        let num_public = u64::from_le_bytes(data[64..72].try_into().unwrap()) as usize;
        let total_nonzeros = u64::from_le_bytes(data[72..80].try_into().unwrap());
        Ok((digest, p_bb, num_vars, num_constraints, num_public, total_nonzeros))
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let (expected_digest, p_bb, num_vars, num_constraints, num_public, _nnz) =
            Self::read_header(data)?;
        let mut pos = 80;

        fn read_matrix(
            data: &[u8],
            pos: &mut usize,
            num_constraints: usize,
        ) -> Result<Vec<SparseRowI64>, &'static str> {
            let mut out = Vec::with_capacity(num_constraints);
            for _ in 0..num_constraints {
                if *pos + 4 > data.len() {
                    return Err("Unexpected end of R1LF data");
                }
                let num_terms = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap()) as usize;
                *pos += 4;
                let mut terms = Vec::with_capacity(num_terms);
                for _ in 0..num_terms {
                    if *pos + 12 > data.len() {
                        return Err("Unexpected end of R1LF data");
                    }
                    let idx = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap()) as usize;
                    *pos += 4;
                    let coeff = i64::from_le_bytes(data[*pos..*pos + 8].try_into().unwrap());
                    *pos += 8;
                    if coeff != 0 {
                        terms.push((idx, coeff));
                    }
                }
                out.push(SparseRowI64 { terms });
            }
            Ok(out)
        }

        let a = read_matrix(data, &mut pos, num_constraints)?;
        let b = read_matrix(data, &mut pos, num_constraints)?;
        let c = read_matrix(data, &mut pos, num_constraints)?;
        let r1cs = Self { num_vars, num_constraints, num_public, p_bb, a, b, c };

        let actual_digest = r1cs.digest();
        if actual_digest != expected_digest {
            return Err("R1LF digest mismatch - file corrupted or tampered");
        }
        Ok(r1cs)
    }

    pub fn load_from_file(path: &str) -> std::io::Result<Self> {
        let mut file = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Self::from_bytes(&bytes).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LiftStats {
    pub num_constraints: usize,
    pub lifted_constraints: usize,
    pub skipped_bool: usize,
    pub skipped_eq: usize,
    pub skipped_select: usize,
    pub skipped_linear: usize,
    pub added_vars: usize,
}

fn row_is_single_term(row: &SparseRowI64, idx: usize, coeff: i64) -> bool {
    row.terms.len() == 1 && row.terms[0].0 == idx && row.terms[0].1 == coeff
}

fn row_is_zero(row: &SparseRowI64) -> bool {
    row.terms.is_empty()
}

/// Convert a BabyBear `SparseRow<F>` into an integer-coefficient row, using centered reps.
fn row_bb_to_i64<F: PrimeField64>(row: &SparseRow<F>) -> SparseRowI64 {
    let mut out = SparseRowI64::new();
    for (idx, coeff) in &row.terms {
        let c = bb_coeff_to_centered_i64(coeff.as_canonical_u64());
        out.add_term(*idx, c);
    }
    out
}

/// Conservative lift pass:
/// - Skips boolean/select/equality constraints (no new q var).
/// - Lifts everything else by adding a fresh `q_i` and adding `(+p_bb)*q_i` to C-row.
pub fn lift_r1cs_to_lf<F: PrimeField64>(
    r1cs_bb: &crate::r1cs::types::R1CS<F>,
) -> (R1CSLf, LiftStats) {
    let p = BABYBEAR_P_U64 as i64;

    // Convert matrices to i64 coeffs.
    let mut a_i64 = Vec::with_capacity(r1cs_bb.num_constraints);
    let mut b_i64 = Vec::with_capacity(r1cs_bb.num_constraints);
    let mut c_i64 = Vec::with_capacity(r1cs_bb.num_constraints);
    for i in 0..r1cs_bb.num_constraints {
        a_i64.push(row_bb_to_i64(&r1cs_bb.a[i]));
        b_i64.push(row_bb_to_i64(&r1cs_bb.b[i]));
        c_i64.push(row_bb_to_i64(&r1cs_bb.c[i]));
    }

    // First pass: identify boolean variables by pattern.
    // b * (1 - b) = 0
    let mut is_bool = vec![false; r1cs_bb.num_vars.max(1)];
    for i in 0..r1cs_bb.num_constraints {
        let a = &a_i64[i];
        let b = &b_i64[i];
        let c = &c_i64[i];
        if c.terms.is_empty()
            && a.terms.len() == 1
            && a.terms[0].1 == 1
            && b.terms.len() == 2
        {
            let bvar = a.terms[0].0;
            // B: (1 - b)
            let mut has_const = false;
            let mut has_minus_b = false;
            for (idx, coeff) in &b.terms {
                if *idx == 0 && *coeff == 1 {
                    has_const = true;
                }
                if *idx == bvar && *coeff == -1 {
                    has_minus_b = true;
                }
            }
            if has_const && has_minus_b {
                if bvar < is_bool.len() {
                    is_bool[bvar] = true;
                }
            }
        }
    }

    let mut stats = LiftStats { num_constraints: r1cs_bb.num_constraints, ..Default::default() };

    // Second pass: lift rows.
    let mut next_var = r1cs_bb.num_vars; // append new variables at end
    for i in 0..r1cs_bb.num_constraints {
        let a = &a_i64[i];
        let b = &b_i64[i];
        let c = &c_i64[i];

        // Skip boolean constraint pattern.
        if c.terms.is_empty()
            && a.terms.len() == 1
            && a.terms[0].1 == 1
            && {
                let bvar = a.terms[0].0;
                b.terms.len() == 2
                    && b.terms.iter().any(|(j, cj)| *j == 0 && *cj == 1)
                    && b.terms.iter().any(|(j, cj)| *j == bvar && *cj == -1)
            }
        {
            stats.skipped_bool += 1;
            continue;
        }

        // Skip equality constraint: (x - y) * 1 = 0
        if row_is_single_term(b, 0, 1) && row_is_zero(c) && a.terms.len() == 2 {
            let &(x, cx) = a.terms.get(0).expect("len=2");
            let &(y, cy) = a.terms.get(1).expect("len=2");
            if (cx, cy) == (1, -1) || (cx, cy) == (-1, 1) {
                // Requires canonical/bounded witnesses, but that's already a LF+ requirement.
                stats.skipped_eq += 1;
                continue;
            }
        }

        // Skip select constraint: (cond) * (a - b) = (out - b), with cond boolean.
        if a.terms.len() == 1 && a.terms[0].1 == 1 {
            let cond = a.terms[0].0;
            if cond < is_bool.len() && is_bool[cond] && b.terms.len() == 2 && c.terms.len() == 2 {
                // B: a - b
                // C: out - b  (shares the same "-b" term)
                let mut b_has_plus = None;
                let mut b_has_minus = None;
                for (j, cj) in b.terms.iter().copied() {
                    if cj == 1 {
                        b_has_plus = Some(j);
                    } else if cj == -1 {
                        b_has_minus = Some(j);
                    }
                }
                let mut c_has_plus = None;
                let mut c_has_minus = None;
                for (j, cj) in c.terms.iter().copied() {
                    if cj == 1 {
                        c_has_plus = Some(j);
                    } else if cj == -1 {
                        c_has_minus = Some(j);
                    }
                }
                if let (Some(_a_var), Some(b_var), Some(_out_var), Some(b_var2)) =
                    (b_has_plus, b_has_minus, c_has_plus, c_has_minus)
                {
                    if b_var == b_var2 {
                        stats.skipped_select += 1;
                        continue;
                    }
                }
            }
        }

        // Otherwise lift: add q_i with coefficient +p in C row.
        let q = next_var;
        next_var += 1;
        stats.lifted_constraints += 1;
        stats.added_vars += 1;

        c_i64[i].add_term(q, p);
    }

    let out = R1CSLf {
        num_vars: next_var,
        num_constraints: r1cs_bb.num_constraints,
        num_public: r1cs_bb.num_public,
        p_bb: BABYBEAR_P_U64,
        a: a_i64,
        b: b_i64,
        c: c_i64,
    };
    (out, stats)
}

/// Cheaper lift mode: only lift **true multiplication** constraints (A!=1 and B!=1).
///
/// Rationale:
/// - In large SP1 shrink R1CS, the vast majority of constraints are "linear" (A==1 or B==1),
///   which would otherwise each get a full-width `q_i`.
/// - This mode targets the big win first: reduce the count of large-range quotients to the set
///   of true-mul constraints.
///
/// IMPORTANT: This does **not** by itself prove BabyBear-in-Frog semantics for linear constraints
/// that may wrap mod p; it is intended as an experimental step toward an IR-level lift.
pub fn lift_r1cs_to_lf_true_mul_only<F: PrimeField64>(
    r1cs_bb: &crate::r1cs::types::R1CS<F>,
) -> (R1CSLf, LiftStats) {
    let p = BABYBEAR_P_U64 as i64;

    // Convert matrices to i64 coeffs.
    let mut a_i64 = Vec::with_capacity(r1cs_bb.num_constraints);
    let mut b_i64 = Vec::with_capacity(r1cs_bb.num_constraints);
    let mut c_i64 = Vec::with_capacity(r1cs_bb.num_constraints);
    for i in 0..r1cs_bb.num_constraints {
        a_i64.push(row_bb_to_i64(&r1cs_bb.a[i]));
        b_i64.push(row_bb_to_i64(&r1cs_bb.b[i]));
        c_i64.push(row_bb_to_i64(&r1cs_bb.c[i]));
    }

    // Identify boolean variables (same as the main lift).
    let mut is_bool = vec![false; r1cs_bb.num_vars.max(1)];
    for i in 0..r1cs_bb.num_constraints {
        let a = &a_i64[i];
        let b = &b_i64[i];
        let c = &c_i64[i];
        if c.terms.is_empty()
            && a.terms.len() == 1
            && a.terms[0].1 == 1
            && b.terms.len() == 2
        {
            let bvar = a.terms[0].0;
            let mut has_const = false;
            let mut has_minus_b = false;
            for (idx, coeff) in &b.terms {
                if *idx == 0 && *coeff == 1 {
                    has_const = true;
                }
                if *idx == bvar && *coeff == -1 {
                    has_minus_b = true;
                }
            }
            if has_const && has_minus_b && bvar < is_bool.len() {
                is_bool[bvar] = true;
            }
        }
    }

    let mut stats = LiftStats { num_constraints: r1cs_bb.num_constraints, ..Default::default() };

    let row_is_one = |row: &SparseRowI64| -> bool {
        row.terms.len() == 1 && row.terms[0].0 == 0 && row.terms[0].1 == 1
    };

    let mut next_var = r1cs_bb.num_vars;
    for i in 0..r1cs_bb.num_constraints {
        let a = &a_i64[i];
        let b = &b_i64[i];
        let c = &c_i64[i];

        // Skip boolean constraint pattern.
        if c.terms.is_empty()
            && a.terms.len() == 1
            && a.terms[0].1 == 1
            && {
                let bvar = a.terms[0].0;
                b.terms.len() == 2
                    && b.terms.iter().any(|(j, cj)| *j == 0 && *cj == 1)
                    && b.terms.iter().any(|(j, cj)| *j == bvar && *cj == -1)
            }
        {
            stats.skipped_bool += 1;
            continue;
        }

        // Skip equality constraint: (x - y) * 1 = 0
        if row_is_single_term(b, 0, 1) && row_is_zero(c) && a.terms.len() == 2 {
            let &(x, cx) = a.terms.get(0).expect("len=2");
            let &(y, cy) = a.terms.get(1).expect("len=2");
            if (cx, cy) == (1, -1) || (cx, cy) == (-1, 1) {
                stats.skipped_eq += 1;
                continue;
            }
        }

        // Skip select constraint: (cond) * (a - b) = (out - b), with cond boolean.
        if a.terms.len() == 1 && a.terms[0].1 == 1 {
            let cond = a.terms[0].0;
            if cond < is_bool.len() && is_bool[cond] && b.terms.len() == 2 && c.terms.len() == 2 {
                let mut b_has_plus = None;
                let mut b_has_minus = None;
                for (j, cj) in b.terms.iter().copied() {
                    if cj == 1 {
                        b_has_plus = Some(j);
                    } else if cj == -1 {
                        b_has_minus = Some(j);
                    }
                }
                let mut c_has_plus = None;
                let mut c_has_minus = None;
                for (j, cj) in c.terms.iter().copied() {
                    if cj == 1 {
                        c_has_plus = Some(j);
                    } else if cj == -1 {
                        c_has_minus = Some(j);
                    }
                }
                if let (Some(_a_var), Some(b_var), Some(_out_var), Some(b_var2)) =
                    (b_has_plus, b_has_minus, c_has_plus, c_has_minus)
                {
                    if b_var == b_var2 {
                        stats.skipped_select += 1;
                        continue;
                    }
                }
            }
        }

        // Only lift true-mul constraints.
        if row_is_one(a) || row_is_one(b) {
            stats.skipped_linear += 1;
            continue;
        }

        let q = next_var;
        next_var += 1;
        stats.lifted_constraints += 1;
        stats.added_vars += 1;
        c_i64[i].add_term(q, p);
    }

    let out = R1CSLf {
        num_vars: next_var,
        num_constraints: r1cs_bb.num_constraints,
        num_public: r1cs_bb.num_public,
        p_bb: BABYBEAR_P_U64,
        a: a_i64,
        b: b_i64,
        c: c_i64,
    };
    (out, stats)
}

