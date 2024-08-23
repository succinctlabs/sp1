use hashbrown::HashMap;
use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;
use sp1_curves::weierstrass::{bls12_381::Bls12381BaseField, bn254::Bn254BaseField};
use sp1_stark::{air::MachineAir, Chip, Shape};

use super::riscv_chips::*;
use crate::{
    memory::{MemoryChipType, MemoryProgramChip},
    riscv::RiscvAir,
};

lazy_static::lazy_static! {
    pub static ref SP1_CORE_PROOF_SHAPES: Vec<Shape> = core_proof_shapes::<BabyBear>();
}

fn core_proof_shapes<F: PrimeField32>() -> Vec<Shape> {
    // The order of the chips is used to determine the order of trace generation.
    let mut chips: Vec<Chip<F, RiscvAir<F>>> = vec![];
    let cpu = Chip::new(RiscvAir::<F>::Cpu(CpuChip::default()));
    let program = Chip::new(RiscvAir::<F>::Program(ProgramChip::default()));
    let sha_extend = Chip::new(RiscvAir::<F>::Sha256Extend(ShaExtendChip::default()));
    let sha_compress = Chip::new(RiscvAir::<F>::Sha256Compress(ShaCompressChip::default()));
    let ed_add_assign = Chip::new(RiscvAir::<F>::Ed25519Add(EdAddAssignChip::<
        EdwardsCurve<Ed25519Parameters>,
    >::new()));
    let ed_decompress = Chip::new(RiscvAir::<F>::Ed25519Decompress(EdDecompressChip::<
        Ed25519Parameters,
    >::default()));
    let k256_decompress = Chip::new(RiscvAir::<F>::K256Decompress(WeierstrassDecompressChip::<
        SwCurve<Secp256k1Parameters>,
    >::with_lsb_rule()));
    let secp256k1_add_assign = Chip::new(RiscvAir::<F>::Secp256k1Add(WeierstrassAddAssignChip::<
        SwCurve<Secp256k1Parameters>,
    >::new()));
    let secp256k1_double_assign =
        Chip::new(RiscvAir::<F>::Secp256k1Double(WeierstrassDoubleAssignChip::<
            SwCurve<Secp256k1Parameters>,
        >::new()));
    let keccak_permute = Chip::new(RiscvAir::<F>::KeccakP(KeccakPermuteChip::new()));
    let bn254_add_assign = Chip::new(RiscvAir::<F>::Bn254Add(WeierstrassAddAssignChip::<
        SwCurve<Bn254Parameters>,
    >::new()));
    let bn254_double_assign = Chip::new(RiscvAir::<F>::Bn254Double(WeierstrassDoubleAssignChip::<
        SwCurve<Bn254Parameters>,
    >::new()));
    let bls12381_add = Chip::new(RiscvAir::<F>::Bls12381Add(WeierstrassAddAssignChip::<
        SwCurve<Bls12381Parameters>,
    >::new()));
    let bls12381_double = Chip::new(RiscvAir::<F>::Bls12381Double(WeierstrassDoubleAssignChip::<
        SwCurve<Bls12381Parameters>,
    >::new()));
    let uint256_mul = Chip::new(RiscvAir::<F>::Uint256Mul(Uint256MulChip::default()));
    let bls12381_fp = Chip::new(RiscvAir::<F>::Bls12381Fp(FpOpChip::<Bls12381BaseField>::new()));
    let bls12381_fp2_addsub = Chip::new(RiscvAir::<F>::Bls12381Fp2AddSub(Fp2AddSubAssignChip::<
        Bls12381BaseField,
    >::new()));
    let bls12381_fp2_mul =
        Chip::new(RiscvAir::<F>::Bls12381Fp2Mul(Fp2MulAssignChip::<Bls12381BaseField>::new()));
    let bn254_fp = Chip::new(RiscvAir::<F>::Bn254Fp(FpOpChip::<Bn254BaseField>::new()));
    let bn254_fp2_addsub =
        Chip::new(RiscvAir::<F>::Bn254Fp2AddSub(Fp2AddSubAssignChip::<Bn254BaseField>::new()));
    let bn254_fp2_mul =
        Chip::new(RiscvAir::<F>::Bn254Fp2Mul(Fp2MulAssignChip::<Bn254BaseField>::new()));
    let bls12381_decompress =
        Chip::new(RiscvAir::<F>::Bls12381Decompress(WeierstrassDecompressChip::<
            SwCurve<Bls12381Parameters>,
        >::with_lexicographic_rule()));
    let div_rem = Chip::new(RiscvAir::<F>::DivRem(DivRemChip::default()));
    let add_sub = Chip::new(RiscvAir::<F>::Add(AddSubChip::default()));
    let bitwise = Chip::new(RiscvAir::<F>::Bitwise(BitwiseChip::default()));
    let mul = Chip::new(RiscvAir::<F>::Mul(MulChip::default()));
    let shift_right = Chip::new(RiscvAir::<F>::ShiftRight(ShiftRightChip::default()));
    let shift_left = Chip::new(RiscvAir::<F>::ShiftLeft(ShiftLeft::default()));
    let lt = Chip::new(RiscvAir::<F>::Lt(LtChip::default()));
    let memory_init =
        Chip::new(RiscvAir::<F>::MemoryInit(MemoryChip::new(MemoryChipType::Initialize)));
    let memory_finalize =
        Chip::new(RiscvAir::<F>::MemoryFinal(MemoryChip::new(MemoryChipType::Finalize)));
    let memory_program = Chip::new(RiscvAir::<F>::ProgramMemory(MemoryProgramChip::default()));
    let byte = Chip::new(RiscvAir::<F>::ByteLookup(ByteChip::default()));
    vec![
        Shape {
            id: 0,
            shape: HashMap::from([
                (cpu.name(), 22),
                (add_sub.name(), 20),
                (mul.name(), 20),
                (lt.name(), 20),
                (div_rem.name(), 20),
                (shift_left.name(), 20),
                (shift_right.name(), 20),
                (bitwise.name(), 20),
            ]),
        },
        Shape {
            id: 1,
            shape: HashMap::from([
                (cpu.name(), 21),
                (add_sub.name(), 19),
                (mul.name(), 19),
                (lt.name(), 19),
                (div_rem.name(), 19),
                (shift_left.name(), 19),
                (shift_right.name(), 19),
                (bitwise.name(), 19),
            ]),
        },
        Shape {
            id: 2,
            shape: HashMap::from([
                (cpu.name(), 20),
                (add_sub.name(), 18),
                (mul.name(), 18),
                (lt.name(), 18),
                (div_rem.name(), 18),
                (shift_left.name(), 18),
                (shift_right.name(), 18),
                (bitwise.name(), 18),
            ]),
        },
        Shape {
            id: 3,
            shape: HashMap::from([
                (cpu.name(), 22),
                (add_sub.name(), 22),
                (mul.name(), 21),
                (lt.name(), 20),
                (div_rem.name(), 18),
                (shift_left.name(), 18),
                (shift_right.name(), 20),
                (bitwise.name(), 8),
            ]),
        },
        Shape { id: 4, shape: HashMap::new() },
        Shape {
            id: 5,
            shape: HashMap::from([
                (cpu.name(), 21),
                (add_sub.name(), 21),
                (mul.name(), 20),
                (lt.name(), 19),
                (div_rem.name(), 18),
                (shift_left.name(), 18),
                (shift_right.name(), 19),
                (bitwise.name(), 16),
            ]),
        },
        Shape {
            id: 6,
            shape: HashMap::from([(memory_init.name(), 22), (memory_finalize.name(), 22)]),
        },
    ]
}
