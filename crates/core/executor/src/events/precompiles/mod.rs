mod ec;
mod edwards;
mod fptower;
mod keccak256_permute;
mod sha256_compress;
mod sha256_extend;
mod uint256;

pub use ec::*;
pub use edwards::*;
pub use fptower::*;
pub use keccak256_permute::*;
use serde::{Deserialize, Serialize};
pub use sha256_compress::*;
pub use sha256_extend::*;
use strum::EnumIter;
pub use uint256::*;

use super::MemoryLocalEvent;

#[derive(Clone, Debug, Serialize, Deserialize, EnumIter)]
/// Precompile event.  There should be one variant for every precompile syscall.
pub enum PrecompileEvent {
    ShaExtend(ShaExtendEvent),
    ShaCompress(ShaCompressEvent),
    KeccakPermute(KeccakPermuteEvent),
    EdAdd(EllipticCurveAddEvent),
    EdDecompress(EdDecompressEvent),
    Secp256k1Add(EllipticCurveAddEvent),
    Secp256k1Double(EllipticCurveDoubleEvent),
    Secp256k1Decompress(EllipticCurveDecompressEvent),
    K256Decompress(EllipticCurveDecompressEvent),
    Bn254Add(EllipticCurveAddEvent),
    Bn254Double(EllipticCurveDoubleEvent),
    Bn254Fp(FpOpEvent),
    Bn254Fp2AddSub(Fp2AddSubEvent),
    Bn254Fp2Mul(Fp2MulEvent),
    Bls12381Add(EllipticCurveAddEvent),
    Bls12381Double(EllipticCurveDoubleEvent),
    Bls12381Decompress(EllipticCurveDecompressEvent),
    Bls12381Fp(FpOpEvent),
    Bls12381Fp2AddSub(Fp2AddSubEvent),
    Bls12381Fp2Mul(Fp2MulEvent),
    Uint256Mul(Uint256MulEvent),
}

pub trait PrecompileLocalMemory {
    fn get_local_mem_events(&self) -> impl IntoIterator<Item = &MemoryLocalEvent>;
}

impl PrecompileLocalMemory for Vec<PrecompileEvent> {
    fn get_local_mem_events(&self) -> impl IntoIterator<Item = &MemoryLocalEvent> {
        let mut iterators = Vec::new();

        for event in self.iter() {
            match event {
                PrecompileEvent::ShaExtend(e) => {
                    iterators.push(e.local_mem_access.iter());
                }
                PrecompileEvent::ShaCompress(e) => {
                    iterators.push(e.local_mem_access.iter());
                }
                PrecompileEvent::KeccakPermute(e) => {
                    iterators.push(e.local_mem_access.iter());
                }
                PrecompileEvent::EdDecompress(e) => {
                    iterators.push(e.local_mem_access.iter());
                }
                PrecompileEvent::Secp256k1Add(e)
                | PrecompileEvent::EdAdd(e)
                | PrecompileEvent::Bn254Add(e)
                | PrecompileEvent::Bls12381Add(e) => {
                    iterators.push(e.local_mem_access.iter());
                }
                PrecompileEvent::Secp256k1Double(e)
                | PrecompileEvent::Bn254Double(e)
                | PrecompileEvent::Bls12381Double(e) => {
                    iterators.push(e.local_mem_access.iter());
                }
                PrecompileEvent::Secp256k1Decompress(e)
                | PrecompileEvent::K256Decompress(e)
                | PrecompileEvent::Bls12381Decompress(e) => {
                    iterators.push(e.local_mem_access.iter());
                }
                PrecompileEvent::Uint256Mul(e) => {
                    iterators.push(e.local_mem_access.iter());
                }
                PrecompileEvent::Bls12381Fp(e) | PrecompileEvent::Bn254Fp(e) => {
                    iterators.push(e.local_mem_access.iter());
                }
                PrecompileEvent::Bls12381Fp2AddSub(e) | PrecompileEvent::Bn254Fp2AddSub(e) => {
                    iterators.push(e.local_mem_access.iter());
                }
                PrecompileEvent::Bls12381Fp2Mul(e) | PrecompileEvent::Bn254Fp2Mul(e) => {
                    iterators.push(e.local_mem_access.iter());
                }
            }
        }

        iterators.into_iter().flatten()
    }
}
