//! R1CS data structures for Symphony/LatticeFold integration.

use p3_field::PrimeField64;
use sp1_primitives::io::sha256_hash;
use std::collections::HashMap;
use std::io::{Read, Write};

/// A sparse row in an R1CS matrix.
/// Maps variable index -> coefficient.
#[derive(Debug, Clone, Default)]
pub struct SparseRow<F> {
    /// (variable_index, coefficient)
    pub terms: Vec<(usize, F)>,
}

impl<F: PrimeField64> SparseRow<F> {
    pub fn new() -> Self {
        Self { terms: Vec::new() }
    }

    pub fn add_term(&mut self, var_idx: usize, coeff: F) {
        if !coeff.is_zero() {
            self.terms.push((var_idx, coeff));
        }
    }

    /// Single variable with coefficient 1
    pub fn single(var_idx: usize) -> Self {
        Self {
            terms: vec![(var_idx, F::one())],
        }
    }

    /// Single variable with given coefficient
    pub fn single_with_coeff(var_idx: usize, coeff: F) -> Self {
        Self {
            terms: vec![(var_idx, coeff)],
        }
    }

    /// Constant (uses variable index 0 which holds value 1)
    pub fn constant(value: F) -> Self {
        Self {
            terms: vec![(0, value)],
        }
    }

    /// Zero row (empty)
    pub fn zero() -> Self {
        Self { terms: Vec::new() }
    }

    /// Evaluate the row against a witness vector
    pub fn evaluate(&self, witness: &[F]) -> F {
        self.terms
            .iter()
            .fold(F::zero(), |acc, (idx, coeff)| acc + *coeff * witness[*idx])
    }
}

/// Complete R1CS instance with matrices A, B, C.
#[derive(Debug, Clone)]
pub struct R1CS<F: PrimeField64> {
    /// Number of variables (including constant "1" at index 0)
    pub num_vars: usize,
    /// Number of constraints
    pub num_constraints: usize,
    /// Number of public inputs (indices 1..=num_public are public)
    pub num_public: usize,
    /// A matrix rows
    pub a: Vec<SparseRow<F>>,
    /// B matrix rows  
    pub b: Vec<SparseRow<F>>,
    /// C matrix rows
    pub c: Vec<SparseRow<F>>,
}

impl<F: PrimeField64> R1CS<F> {
    pub fn new() -> Self {
        Self {
            num_vars: 1, // Start with 1 for the constant "1"
            num_constraints: 0,
            num_public: 0,
            a: Vec::new(),
            b: Vec::new(),
            c: Vec::new(),
        }
    }

    /// Add a constraint: (a · w) * (b · w) = (c · w)
    pub fn add_constraint(&mut self, a: SparseRow<F>, b: SparseRow<F>, c: SparseRow<F>) {
        self.a.push(a);
        self.b.push(b);
        self.c.push(c);
        self.num_constraints += 1;
    }

    /// Verify the R1CS is satisfied by a witness
    pub fn is_satisfied(&self, witness: &[F]) -> bool {
        assert_eq!(witness.len(), self.num_vars);
        assert_eq!(witness[0], F::one(), "witness[0] must be 1");

        for i in 0..self.num_constraints {
            let a_val = self.a[i].evaluate(witness);
            let b_val = self.b[i].evaluate(witness);
            let c_val = self.c[i].evaluate(witness);
            if a_val * b_val != c_val {
                return false;
            }
        }
        true
    }

    /// Compute a cryptographic digest of the R1CS for commitment.
    /// Uses SHA256 for deterministic cross-platform hashing.
    /// 
    /// The digest covers:
    /// - num_vars, num_constraints, num_public (structure)
    /// - All entries in A, B, C matrices (constraint values)
    /// 
    /// This binding is critical for WE soundness: the armer commits to 
    /// a specific R1CS, and the decapsulation is only possible with a 
    /// witness satisfying that exact R1CS.
    pub fn digest(&self) -> [u8; 32] {
        let mut data = Vec::new();
        
        // Domain separation
        data.extend_from_slice(b"R1CS_DIGEST_v1");
        
        // Structure parameters
        data.extend_from_slice(&(self.num_vars as u64).to_le_bytes());
        data.extend_from_slice(&(self.num_constraints as u64).to_le_bytes());
        data.extend_from_slice(&(self.num_public as u64).to_le_bytes());
        
        // Serialize A matrix
        data.extend_from_slice(b"A_MATRIX");
        for row in &self.a {
            data.extend_from_slice(&(row.terms.len() as u64).to_le_bytes());
            for (idx, coeff) in &row.terms {
                data.extend_from_slice(&(*idx as u64).to_le_bytes());
                data.extend_from_slice(&coeff.as_canonical_u64().to_le_bytes());
            }
        }
        
        // Serialize B matrix
        data.extend_from_slice(b"B_MATRIX");
        for row in &self.b {
            data.extend_from_slice(&(row.terms.len() as u64).to_le_bytes());
            for (idx, coeff) in &row.terms {
                data.extend_from_slice(&(*idx as u64).to_le_bytes());
                data.extend_from_slice(&coeff.as_canonical_u64().to_le_bytes());
            }
        }
        
        // Serialize C matrix
        data.extend_from_slice(b"C_MATRIX");
        for row in &self.c {
            data.extend_from_slice(&(row.terms.len() as u64).to_le_bytes());
            for (idx, coeff) in &row.terms {
                data.extend_from_slice(&(*idx as u64).to_le_bytes());
                data.extend_from_slice(&coeff.as_canonical_u64().to_le_bytes());
            }
        }
        
        // SHA256 hash
        let hash_vec = sha256_hash(&data);
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash_vec);
        result
    }

    /// Serialize R1CS to binary format for file storage.
    /// 
    /// Format (v2 - self-verifying):
    /// ```text
    /// HEADER (72 bytes fixed):
    ///   - Magic: "R1CS" (4 bytes)
    ///   - Version: u32 = 2 (4 bytes)
    ///   - Digest: [u8; 32] - SHA256 of matrices (32 bytes)
    ///   - num_vars: u64 (8 bytes)
    ///   - num_constraints: u64 (8 bytes)
    ///   - num_public: u64 (8 bytes)
    ///   - total_nonzeros: u64 (8 bytes) - for quick size estimation
    /// 
    /// BODY (variable):
    ///   - For each of A, B, C matrices:
    ///     - For each row:
    ///       - num_terms: u32 (4 bytes)
    ///       - For each term: (var_idx: u32, coeff: u64) = 12 bytes
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        
        // Compute digest first (needed for header)
        let digest = self.digest();
        
        // Count total nonzeros
        let total_nonzeros: u64 = self.a.iter().chain(self.b.iter()).chain(self.c.iter())
            .map(|row| row.terms.len() as u64)
            .sum();
        
        // === HEADER (72 bytes) ===
        buf.extend_from_slice(b"R1CS");                                    // 4 bytes
        buf.extend_from_slice(&2u32.to_le_bytes());                        // 4 bytes (version 2)
        buf.extend_from_slice(&digest);                                     // 32 bytes
        buf.extend_from_slice(&(self.num_vars as u64).to_le_bytes());      // 8 bytes
        buf.extend_from_slice(&(self.num_constraints as u64).to_le_bytes()); // 8 bytes
        buf.extend_from_slice(&(self.num_public as u64).to_le_bytes());    // 8 bytes
        buf.extend_from_slice(&total_nonzeros.to_le_bytes());              // 8 bytes
        
        // === BODY ===
        for matrix in [&self.a, &self.b, &self.c] {
            for row in matrix {
                buf.extend_from_slice(&(row.terms.len() as u32).to_le_bytes());
                for (idx, coeff) in &row.terms {
                    buf.extend_from_slice(&(*idx as u32).to_le_bytes());
                    buf.extend_from_slice(&coeff.as_canonical_u64().to_le_bytes());
                }
            }
        }
        
        buf
    }
    
    /// Read just the header from R1CS file (fast, no matrix loading).
    /// Returns: (digest, num_vars, num_constraints, num_public, total_nonzeros)
    pub fn read_header(data: &[u8]) -> Result<([u8; 32], usize, usize, usize, u64), &'static str> {
        if data.len() < 72 {
            return Err("R1CS file too small for header");
        }
        if &data[0..4] != b"R1CS" {
            return Err("Invalid R1CS magic");
        }
        let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
        if version != 2 {
            return Err("Unsupported R1CS version (expected v2)");
        }
        
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&data[8..40]);
        let num_vars = u64::from_le_bytes(data[40..48].try_into().unwrap()) as usize;
        let num_constraints = u64::from_le_bytes(data[48..56].try_into().unwrap()) as usize;
        let num_public = u64::from_le_bytes(data[56..64].try_into().unwrap()) as usize;
        let total_nonzeros = u64::from_le_bytes(data[64..72].try_into().unwrap());
        
        Ok((digest, num_vars, num_constraints, num_public, total_nonzeros))
    }
    
    /// Deserialize R1CS from binary format with integrity verification.
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        // Read and validate header
        let (expected_digest, num_vars, num_constraints, num_public, _total_nonzeros) = 
            Self::read_header(data)?;
        
        let mut pos = 72; // Skip header
        
        // Read matrices
        let mut a = Vec::with_capacity(num_constraints);
        let mut b = Vec::with_capacity(num_constraints);
        let mut c = Vec::with_capacity(num_constraints);
        
        for matrix in [&mut a, &mut b, &mut c] {
            for _ in 0..num_constraints {
                if pos + 4 > data.len() {
                    return Err("Unexpected end of R1CS data");
                }
                let num_terms = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
                pos += 4;
                
                let mut terms = Vec::with_capacity(num_terms);
                for _ in 0..num_terms {
                    if pos + 12 > data.len() {
                        return Err("Unexpected end of R1CS data");
                    }
                    let idx = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
                    pos += 4;
                    let coeff_u64 = u64::from_le_bytes(data[pos..pos+8].try_into().unwrap());
                    pos += 8;
                    let coeff = F::from_canonical_u64(coeff_u64);
                    terms.push((idx, coeff));
                }
                matrix.push(SparseRow { terms });
            }
        }
        
        let r1cs = Self { num_vars, num_constraints, num_public, a, b, c };
        
        // Verify digest matches (integrity check)
        let actual_digest = r1cs.digest();
        if actual_digest != expected_digest {
            return Err("R1CS digest mismatch - file corrupted or tampered");
        }
        
        Ok(r1cs)
    }
    
    /// Load R1CS from file and verify expected digest.
    /// This is the recommended way to load in Symphony.
    pub fn load_and_verify(path: &str, expected_digest: &[u8; 32]) -> std::io::Result<Self> {
        // Quick header check first (fast fail)
        let mut file = std::fs::File::open(path)?;
        let mut header = [0u8; 72];
        file.read_exact(&mut header)?;
        
        let (file_digest, _, _, _, _) = Self::read_header(&header)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        
        if &file_digest != expected_digest {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("R1CS digest mismatch: expected {:02x?}, got {:02x?}", 
                    &expected_digest[..8], &file_digest[..8])
            ));
        }
        
        // Full load with verification
        Self::load_from_file(path)
    }
    
    /// Save R1CS to file.
    pub fn save_to_file(&self, path: &str) -> std::io::Result<()> {
        let bytes = self.to_bytes();
        let mut file = std::fs::File::create(path)?;
        file.write_all(&bytes)?;
        Ok(())
    }
    
    /// Load R1CS from file.
    pub fn load_from_file(path: &str) -> std::io::Result<Self> {
        let mut file = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Self::from_bytes(&bytes).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

/// Variable type tracking for type-safe R1CS construction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VarType {
    /// Native field variable (BN254 scalar in gnark, unused here)
    Var,
    /// BabyBear field element
    Felt,
    /// BabyBear extension field element (4 base elements)
    Ext,
}

/// Mapping from DSL variable IDs to R1CS indices
#[derive(Debug, Default)]
pub struct VarMap {
    /// Maps DSL variable string ID to (R1CS index, type)
    pub map: HashMap<String, (usize, VarType)>,
}

impl VarMap {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn get(&self, id: &str) -> Option<(usize, VarType)> {
        self.map.get(id).copied()
    }

    pub fn insert(&mut self, id: String, idx: usize, typ: VarType) {
        self.map.insert(id, (idx, typ));
    }
}
