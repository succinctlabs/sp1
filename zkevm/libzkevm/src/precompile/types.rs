//! Mirror of the C struct types in `zkvm_accelerators.h`.
//!
//! Every type is `#[repr(C, align(8))]` to match the `_Alignas(8)` in the
//! header. Sizes are byte-for-byte identical: a `zkvm_bytes_32` is 32 bytes,
//! 8-byte aligned.

#[repr(C, align(8))]
pub struct ZkvmBytes16 {
    pub data: [u8; 16],
}

#[repr(C, align(8))]
pub struct ZkvmBytes32 {
    pub data: [u8; 32],
}

#[repr(C, align(8))]
pub struct ZkvmBytes48 {
    pub data: [u8; 48],
}

#[repr(C, align(8))]
pub struct ZkvmBytes64 {
    pub data: [u8; 64],
}

#[repr(C, align(8))]
pub struct ZkvmBytes96 {
    pub data: [u8; 96],
}

#[repr(C, align(8))]
pub struct ZkvmBytes128 {
    pub data: [u8; 128],
}

#[repr(C, align(8))]
pub struct ZkvmBytes192 {
    pub data: [u8; 192],
}

// Aliases (size-equivalent, just for header parity).
pub type Keccak256Hash = ZkvmBytes32;
pub type Sha256Hash = ZkvmBytes32;
pub type Ripemd160Hash = ZkvmBytes32; // 12 zero pad + 20 bytes

pub type Secp256k1Hash = ZkvmBytes32;
pub type Secp256k1Signature = ZkvmBytes64;
pub type Secp256k1Pubkey = ZkvmBytes64;

pub type Secp256r1Hash = ZkvmBytes32;
pub type Secp256r1Signature = ZkvmBytes64;
pub type Secp256r1Pubkey = ZkvmBytes64;

pub type Bn254G1Point = ZkvmBytes64;
pub type Bn254G2Point = ZkvmBytes128;
pub type Bn254Scalar = ZkvmBytes32;

#[repr(C)]
pub struct Bn254PairingPair {
    pub g1: Bn254G1Point,
    pub g2: Bn254G2Point,
}

pub type Bls12381G1Point = ZkvmBytes96;
pub type Bls12381G2Point = ZkvmBytes192;
pub type Bls12381Scalar = ZkvmBytes32;
pub type Bls12381Fp = ZkvmBytes48;
pub type Bls12381Fp2 = ZkvmBytes96;

#[repr(C)]
pub struct Bls12381G1MsmPair {
    pub point: Bls12381G1Point,
    pub scalar: Bls12381Scalar,
}

#[repr(C)]
pub struct Bls12381G2MsmPair {
    pub point: Bls12381G2Point,
    pub scalar: Bls12381Scalar,
}

#[repr(C)]
pub struct Bls12381PairingPair {
    pub g1: Bls12381G1Point,
    pub g2: Bls12381G2Point,
}

pub type Blake2fState = ZkvmBytes64;
pub type Blake2fMessage = ZkvmBytes128;
pub type Blake2fOffset = ZkvmBytes16;

pub type KzgCommitment = ZkvmBytes48;
pub type KzgProof = ZkvmBytes48;
pub type KzgFieldElement = ZkvmBytes32;
