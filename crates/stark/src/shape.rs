use hashbrown::HashMap;
use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;

use crate::{air::MachineAir, memory::MemoryChipType, stark::RiscvAir};

use super::riscv_chips::*;

lazy_static::lazy_static! {
    pub static ref SP1_CORE_PROOF_SHAPES: Vec<HashMap<String, usize>> = core_proof_shapes::<BabyBear>();
}

fn core_proof_shapes<F: PrimeField32>() -> Vec<HashMap<String, usize>> {
    let cpu = RiscvAir::<F>::Cpu(CpuChip::default());
    let sha_extend = RiscvAir::<F>::Sha256Extend(ShaExtendChip::default());
    let sha_compress = RiscvAir::<F>::Sha256Compress(ShaCompressChip::default());
    let ed_add_assign =
        RiscvAir::<F>::Ed25519Add(EdAddAssignChip::<EdwardsCurve<Ed25519Parameters>>::new());
    let ed_decompress =
        RiscvAir::<F>::Ed25519Decompress(EdDecompressChip::<Ed25519Parameters>::default());
    let k256_decompress = RiscvAir::<F>::K256Decompress(WeierstrassDecompressChip::<
        SwCurve<Secp256k1Parameters>,
    >::with_lsb_rule());
    let secp256k1_add_assign = RiscvAir::<F>::Secp256k1Add(WeierstrassAddAssignChip::<
        SwCurve<Secp256k1Parameters>,
    >::new());
    let secp256k1_double_assign = RiscvAir::<F>::Secp256k1Double(WeierstrassDoubleAssignChip::<
        SwCurve<Secp256k1Parameters>,
    >::new());
    let keccak_permute = RiscvAir::<F>::KeccakP(KeccakPermuteChip::new());
    let bn254_add_assign =
        RiscvAir::<F>::Bn254Add(WeierstrassAddAssignChip::<SwCurve<Bn254Parameters>>::new());
    let bn254_double_assign =
        RiscvAir::<F>::Bn254Double(WeierstrassDoubleAssignChip::<SwCurve<Bn254Parameters>>::new());
    let bls12381_add =
        RiscvAir::<F>::Bls12381Add(WeierstrassAddAssignChip::<SwCurve<Bls12381Parameters>>::new());
    let bls12381_double = RiscvAir::<F>::Bls12381Double(WeierstrassDoubleAssignChip::<
        SwCurve<Bls12381Parameters>,
    >::new());
    let uint256_mul = RiscvAir::<F>::Uint256Mul(Uint256MulChip::default());
    let bls12381_decompress = RiscvAir::<F>::Bls12381Decompress(WeierstrassDecompressChip::<
        SwCurve<Bls12381Parameters>,
    >::with_lexicographic_rule());
    let div_rem = RiscvAir::<F>::DivRem(DivRemChip::default());
    let add = RiscvAir::<F>::Add(AddSubChip::default());
    let bitwise = RiscvAir::<F>::Bitwise(BitwiseChip::default());
    let mul = RiscvAir::<F>::Mul(MulChip::default());
    let shift_right = RiscvAir::<F>::ShiftRight(ShiftRightChip::default());
    let shift_left = RiscvAir::<F>::ShiftLeft(ShiftLeft::default());
    let lt = RiscvAir::<F>::Lt(LtChip::default());
    let memory_init = RiscvAir::<F>::MemoryInit(MemoryChip::new(MemoryChipType::Initialize));
    let memory_finalize = RiscvAir::<F>::MemoryFinal(MemoryChip::new(MemoryChipType::Finalize));

    vec![
        HashMap::from([
            (cpu.name(), 22),
            // Byte table is constant size.
            // (sha_extend.name(), 1),
            // (sha_compress.name(), 1),
            // (ed_add_assign.name(), 1),
            // (ed_decompress.name(), 1),
            // (k256_decompress.name(), 1),
            // (secp256k1_add_assign.name(), 1),
            // (secp256k1_double_assign.name(), 1),
            // (keccak_permute.name(), 1),
            // (bn254_add_assign.name(), 1),
            // (bn254_double_assign.name(), 1),
            // (bls12381_add.name(), 1),
            // (bls12381_double.name(), 1),
            // (uint256_mul.name(), 1),
            // (bls12381_decompress.name(), 1),
            // (div_rem.name(), 1),
            // (add.name(), 1),
            // (bitwise.name(), 1),
            // (mul.name(), 1),
            // (shift_right.name(), 1),
            // (shift_left.name(), 1),
            // (lt.name(), 1),
            // (memory_init.name(), 1),
            // (memory_finalize.name(), 1),
            // (program_memory_init.name(), 1),
            // (byte.name(), 1),
        ]),
        HashMap::from([
            (cpu.name(), 22),
            (add.name(), 20),
            (mul.name(), 20),
            (lt.name(), 20),
            (div_rem.name(), 20),
            (shift_left.name(), 20),
            (shift_right.name(), 20),
            (bitwise.name(), 20),
        ]),
        HashMap::from([(memory_init.name(), 22), (memory_finalize.name(), 22)]),
    ]
}
