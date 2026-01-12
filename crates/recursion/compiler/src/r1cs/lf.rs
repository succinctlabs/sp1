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
use p3_maybe_rayon::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};

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
    pub added_q_vars: usize,
    pub added_carry_vars: usize,
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

/// Faithful lift mode that introduces:
/// - a full-width quotient `q_i` for **true multiplication** constraints (A!=1 && B!=1), and
/// - a **small carry** `c_i` for **linear** constraints (A==1 || B==1),
/// both encoded as `(+p_bb) * (q_i or c_i)` added to the C-row.
///
/// This keeps the number of constraints unchanged; it only increases witness variables and nnz.
///
/// IMPORTANT: Correctness/soundness requires LF+ to enforce boundedness of all witness values,
/// including these new carry/quotient vars, so field equalities imply intended integer equalities.
pub fn lift_r1cs_to_lf_with_linear_carries<F: PrimeField64>(
    r1cs_bb: &crate::r1cs::types::R1CS<F>,
) -> (R1CSLf, LiftStats) {
    let (r1lf, stats, _w) = lift_r1cs_to_lf_core::<F>(r1cs_bb, None).expect("core lift cannot fail without witness");
    (r1lf, stats)
}

/// Lift the R1CS to `R1LF` and simultaneously extend a satisfying BabyBear witness with the
/// lift-introduced auxiliary vars (quotients/carries).
///
/// Returns:
/// - `r1lf`: the lifted relation (same as `lift_r1cs_to_lf_with_linear_carries`)
/// - `stats`: lift stats
/// - `w_lf_u64`: witness of length `r1lf.num_vars` with canonical u64 representatives in `[0,p)`,
///   where the tail are the computed aux vars.
///
/// IMPORTANT: this computes aux vars using the *integer* semantics implied by the lift:
/// it interprets all BabyBear values via centered representatives and requires exact divisibility by `p`.
pub fn lift_r1cs_to_lf_with_linear_carries_and_witness<F: PrimeField64>(
    r1cs_bb: &crate::r1cs::types::R1CS<F>,
    witness_bb: &[F],
) -> Result<(R1CSLf, LiftStats, Vec<u64>), String> {
    let (r1lf, stats, w) = lift_r1cs_to_lf_core::<F>(r1cs_bb, Some(witness_bb))?;
    let w = w.expect("core should return witness when witness_bb is provided");
    Ok((r1lf, stats, w))
}

// ============================================================================
// Refactored core lift (single source of truth for rewrite logic)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LiftDecision {
    SkipBool,
    SkipEq,
    SkipSelect,
    LiftCarry,
    LiftQuotient,
}

fn lift_r1cs_to_lf_core<F: PrimeField64>(
    r1cs_bb: &crate::r1cs::types::R1CS<F>,
    witness_bb: Option<&[F]>,
) -> Result<(R1CSLf, LiftStats, Option<Vec<u64>>), String> {
    if let Some(w) = witness_bb {
        if w.len() != r1cs_bb.num_vars {
            return Err(format!(
                "witness length mismatch: expected {} got {}",
                r1cs_bb.num_vars,
                w.len()
            ));
        }
        if w.is_empty() || w[0].as_canonical_u64() != 1 {
            return Err("witness_bb[0] must be 1".to_string());
        }
    }

    let p = BABYBEAR_P_U64 as i64;
    let p_i128 = BABYBEAR_P_U64 as i128;

    // Convert matrices to i64 coeffs (parallel when `p3-maybe-rayon` enables it).
    let a_i64: Vec<SparseRowI64> = (0..r1cs_bb.num_constraints)
        .into_par_iter()
        .map(|i| row_bb_to_i64(&r1cs_bb.a[i]))
        .collect();
    let b_i64: Vec<SparseRowI64> = (0..r1cs_bb.num_constraints)
        .into_par_iter()
        .map(|i| row_bb_to_i64(&r1cs_bb.b[i]))
        .collect();
    let mut c_i64: Vec<SparseRowI64> = (0..r1cs_bb.num_constraints)
        .into_par_iter()
        .map(|i| row_bb_to_i64(&r1cs_bb.c[i]))
        .collect();

    // Identify boolean variables (same as before), but parallelize the scan.
    let mut is_bool = vec![false; r1cs_bb.num_vars.max(1)];
    let bool_hits: Vec<usize> = (0..r1cs_bb.num_constraints)
        .into_par_iter()
        .filter_map(|i| {
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
                if has_const && has_minus_b {
                    return Some(bvar);
                }
            }
            None
        })
        .collect();
    for bvar in bool_hits {
        if bvar < is_bool.len() {
            is_bool[bvar] = true;
        }
    }

    #[inline]
    fn row_is_one(row: &SparseRowI64) -> bool {
        row.terms.len() == 1 && row.terms[0].0 == 0 && row.terms[0].1 == 1
    }

    #[inline]
    fn decide_row(a: &SparseRowI64, b: &SparseRowI64, c: &SparseRowI64, is_bool: &[bool]) -> LiftDecision {
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
            return LiftDecision::SkipBool;
        }

        // Skip equality constraint: (x - y) * 1 = 0
        if row_is_single_term(b, 0, 1) && row_is_zero(c) && a.terms.len() == 2 {
            let &(_x, cx) = a.terms.get(0).expect("len=2");
            let &(_y, cy) = a.terms.get(1).expect("len=2");
            if (cx, cy) == (1, -1) || (cx, cy) == (-1, 1) {
                return LiftDecision::SkipEq;
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
                        return LiftDecision::SkipSelect;
                    }
                }
            }
        }

        // Lift everything else.
        let is_linear = row_is_one(a) || row_is_one(b);
        if is_linear {
            LiftDecision::LiftCarry
        } else {
            LiftDecision::LiftQuotient
        }
    }

    #[inline]
    fn eval_row_i128<F: PrimeField64>(row: &SparseRowI64, w: &[F]) -> i128 {
        row.terms
            .iter()
            .map(|(idx, coeff)| {
                let v = bb_coeff_to_centered_i64(w[*idx].as_canonical_u64()) as i128;
                (*coeff as i128) * v
            })
            .sum()
    }

    let mut stats = LiftStats { num_constraints: r1cs_bb.num_constraints, ..Default::default() };
    // Decide lift/skip per row (parallel) then assign deterministic aux indices (sequential prefix sum).
    let decisions: Vec<LiftDecision> = (0..r1cs_bb.num_constraints)
        .into_par_iter()
        .map(|i| decide_row(&a_i64[i], &b_i64[i], &c_i64[i], &is_bool))
        .collect();

    // Map each constraint i -> aux position (0..lifted-1) or u32::MAX if not lifted.
    let mut lift_pos: Vec<u32> = vec![u32::MAX; r1cs_bb.num_constraints];
    let mut next_aux: u32 = 0;
    for (i, d) in decisions.iter().enumerate() {
        match d {
            LiftDecision::SkipBool => stats.skipped_bool += 1,
            LiftDecision::SkipEq => stats.skipped_eq += 1,
            LiftDecision::SkipSelect => stats.skipped_select += 1,
            LiftDecision::LiftCarry => {
                stats.lifted_constraints += 1;
                stats.added_vars += 1;
                stats.added_carry_vars += 1;
                lift_pos[i] = next_aux;
                next_aux += 1;
            }
            LiftDecision::LiftQuotient => {
                stats.lifted_constraints += 1;
                stats.added_vars += 1;
                stats.added_q_vars += 1;
                lift_pos[i] = next_aux;
                next_aux += 1;
            }
        }
    }
    let lifted_total = next_aux as usize;

    // Extend witness (compute aux vars) in parallel if witness provided.
    let mut w_out: Option<Vec<u64>> = witness_bb.map(|w| w.iter().map(|x| x.as_canonical_u64()).collect());
    if let (Some(witness_bb), Some(w_out_vec)) = (witness_bb, w_out.as_mut()) {
        // Use atomics to safely fill aux slots in parallel.
        let aux: Vec<AtomicU64> = (0..lifted_total).map(|_| AtomicU64::new(u64::MAX)).collect();

        (0..r1cs_bb.num_constraints)
            .into_par_iter()
            .try_for_each(|i| -> Result<(), String> {
                let pos = lift_pos[i];
                if pos == u32::MAX {
                    return Ok(());
                }
                let a = &a_i64[i];
                let b = &b_i64[i];
                let c = &c_i64[i];
                let a_int = eval_row_i128(a, witness_bb);
                let b_int = eval_row_i128(b, witness_bb);
                let c_int = eval_row_i128(c, witness_bb);
                let num = a_int * b_int - c_int;
                if num % p_i128 != 0 {
                    return Err(format!(
                        "lift witness: non-divisible row {i}: (a*b-c) not multiple of p"
                    ));
                }
                let mut v_int = num / p_i128;
                v_int %= p_i128;
                if v_int < 0 {
                    v_int += p_i128;
                }
                let v_u64 = v_int as u64;
                if v_u64 >= BABYBEAR_P_U64 {
                    return Err("lift witness: v out of range after mod p".to_string());
                }
                aux[pos as usize].store(v_u64, Ordering::Relaxed);
                Ok(())
            })?;

        // Append aux in deterministic order.
        if w_out_vec.len() != r1cs_bb.num_vars {
            return Err("lift witness: base witness length mismatch".to_string());
        }
        for (j, a) in aux.iter().enumerate() {
            let v = a.load(Ordering::Relaxed);
            if v == u64::MAX {
                return Err(format!("lift witness: aux slot {j} was not filled"));
            }
            w_out_vec.push(v);
        }
    }

    // Modify C rows in parallel: add (+p)*v_idx where v_idx = num_vars + lift_pos[i]
    let base_vars = r1cs_bb.num_vars;
    c_i64
        .par_iter_mut()
        .enumerate()
        .for_each(|(i, crow)| {
            let pos = lift_pos[i];
            if pos != u32::MAX {
                let v_idx = base_vars + pos as usize;
                crow.add_term(v_idx, p);
            }
        });

    let next_var = r1cs_bb.num_vars + lifted_total;

    let out = R1CSLf {
        num_vars: next_var,
        num_constraints: r1cs_bb.num_constraints,
        num_public: r1cs_bb.num_public,
        p_bb: BABYBEAR_P_U64,
        a: a_i64,
        b: b_i64,
        c: c_i64,
    };
    if let Some(w) = w_out.as_ref() {
        if out.num_vars != w.len() {
            return Err("lift witness: final witness length mismatch".to_string());
        }
    }
    Ok((out, stats, w_out))
}
