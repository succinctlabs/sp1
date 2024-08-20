use crate::{
    memory::{MemoryChipType, MemoryProgramChip},
    syscall::precompiles::fptower::{Fp2AddSubAssignChip, Fp2MulAssignChip, FpOpChip},
};
use blake3::Hash;
use hashbrown::HashMap;
use p3_air::BaseAir;
use p3_field::PrimeField32;
pub use riscv_chips::*;
use sp1_core_executor::{syscalls::SyscallCode, Opcode};
use sp1_curves::{
    uint256,
    weierstrass::{bls12_381::Bls12381BaseField, bn254::Bn254BaseField},
};
use sp1_stark::{
    air::{MachineAir, SP1_PROOF_NUM_PV_ELTS},
    Chip, StarkGenericConfig, StarkMachine,
};
use tracing::instrument;
use typenum::uint;

/// A module for importing all the different RISC-V chips.
pub(crate) mod riscv_chips {
    pub use crate::{
        alu::{AddSubChip, BitwiseChip, DivRemChip, LtChip, MulChip, ShiftLeft, ShiftRightChip},
        bytes::ByteChip,
        cpu::CpuChip,
        memory::MemoryChip,
        program::ProgramChip,
        syscall::precompiles::{
            edwards::{EdAddAssignChip, EdDecompressChip},
            keccak256::KeccakPermuteChip,
            sha256::{ShaCompressChip, ShaExtendChip},
            uint256::Uint256MulChip,
            weierstrass::{
                WeierstrassAddAssignChip, WeierstrassDecompressChip, WeierstrassDoubleAssignChip,
            },
        },
    };
    pub use sp1_curves::{
        edwards::{ed25519::Ed25519Parameters, EdwardsCurve},
        weierstrass::{
            bls12_381::Bls12381Parameters, bn254::Bn254Parameters, secp256k1::Secp256k1Parameters,
            SwCurve,
        },
    };
}

/// An AIR for encoding RISC-V execution.
///
/// This enum contains all the different AIRs that are used in the Sp1 RISC-V IOP. Each variant is
/// a different AIR that is used to encode a different part of the RISC-V execution, and the
/// different AIR variants have a joint lookup argument.
#[derive(sp1_derive::MachineAir)]
pub enum RiscvAir<F: PrimeField32> {
    /// An AIR that containts a preprocessed program table and a lookup for the instructions.
    Program(ProgramChip),
    /// An AIR for the RISC-V CPU. Each row represents a cpu cycle.
    Cpu(CpuChip),
    /// An AIR for the RISC-V Add and SUB instruction.
    Add(AddSubChip),
    /// An AIR for RISC-V Bitwise instructions.
    Bitwise(BitwiseChip),
    /// An AIR for RISC-V Mul instruction.
    Mul(MulChip),
    /// An AIR for RISC-V Div and Rem instructions.
    DivRem(DivRemChip),
    /// An AIR for RISC-V Lt instruction.
    Lt(LtChip),
    /// An AIR for RISC-V SLL instruction.
    ShiftLeft(ShiftLeft),
    /// An AIR for RISC-V SRL and SRA instruction.
    ShiftRight(ShiftRightChip),
    /// A lookup table for byte operations.
    ByteLookup(ByteChip<F>),
    /// A table for initializing the memory state.
    MemoryInit(MemoryChip),
    /// A table for finalizing the memory state.
    MemoryFinal(MemoryChip),
    /// A table for initializing the program memory.
    ProgramMemory(MemoryProgramChip),
    /// A precompile for sha256 extend.
    Sha256Extend(ShaExtendChip),
    /// A precompile for sha256 compress.
    Sha256Compress(ShaCompressChip),
    /// A precompile for addition on the Elliptic curve ed25519.
    Ed25519Add(EdAddAssignChip<EdwardsCurve<Ed25519Parameters>>),
    /// A precompile for decompressing a point on the Edwards curve ed25519.
    Ed25519Decompress(EdDecompressChip<Ed25519Parameters>),
    /// A precompile for decompressing a point on the K256 curve.
    K256Decompress(WeierstrassDecompressChip<SwCurve<Secp256k1Parameters>>),
    /// A precompile for addition on the Elliptic curve secp256k1.
    Secp256k1Add(WeierstrassAddAssignChip<SwCurve<Secp256k1Parameters>>),
    /// A precompile for doubling a point on the Elliptic curve secp256k1.
    Secp256k1Double(WeierstrassDoubleAssignChip<SwCurve<Secp256k1Parameters>>),
    /// A precompile for the Keccak permutation.
    KeccakP(KeccakPermuteChip),
    /// A precompile for addition on the Elliptic curve bn254.
    Bn254Add(WeierstrassAddAssignChip<SwCurve<Bn254Parameters>>),
    /// A precompile for doubling a point on the Elliptic curve bn254.
    Bn254Double(WeierstrassDoubleAssignChip<SwCurve<Bn254Parameters>>),
    /// A precompile for addition on the Elliptic curve bls12_381.
    Bls12381Add(WeierstrassAddAssignChip<SwCurve<Bls12381Parameters>>),
    /// A precompile for doubling a point on the Elliptic curve bls12_381.
    Bls12381Double(WeierstrassDoubleAssignChip<SwCurve<Bls12381Parameters>>),
    /// A precompile for uint256 mul.
    Uint256Mul(Uint256MulChip),
    /// A precompile for decompressing a point on the BLS12-381 curve.
    Bls12381Decompress(WeierstrassDecompressChip<SwCurve<Bls12381Parameters>>),
    /// A precompile for BLS12-381 fp operation.
    Bls12381Fp(FpOpChip<Bls12381BaseField>),
    /// A precompile for BLS12-381 fp2 multiplication.
    Bls12381Fp2Mul(Fp2MulAssignChip<Bls12381BaseField>),
    /// A precompile for BLS12-381 fp2 addition/subtraction.
    Bls12381Fp2AddSub(Fp2AddSubAssignChip<Bls12381BaseField>),
    /// A precompile for BN-254 fp operation.
    Bn254Fp(FpOpChip<Bn254BaseField>),
    /// A precompile for BN-254 fp2 multiplication.
    Bn254Fp2Mul(Fp2MulAssignChip<Bn254BaseField>),
    /// A precompile for BN-254 fp2 addition/subtraction.
    Bn254Fp2AddSub(Fp2AddSubAssignChip<Bn254BaseField>),
}

impl<F: PrimeField32> RiscvAir<F> {
    #[instrument("construct RiscvAir machine", level = "debug", skip_all)]
    pub fn machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
        let chips = Self::get_all().into_iter().map(Chip::new).collect::<Vec<_>>();
        StarkMachine::new(config, chips, SP1_PROOF_NUM_PV_ELTS)
    }

    /// Get all the different RISC-V AIRs.
    pub fn get_all() -> Vec<Self> {
        let mut syscall_costs: HashMap<SyscallCode, u64> = HashMap::new();
        let mut opcode_costs: HashMap<Opcode, u64> = HashMap::new();

        // The order of the chips is used to determine the order of trace generation.
        let mut chips = vec![];
        let cpu = Chip::new(RiscvAir::Cpu(CpuChip::default()));
        chips.push(cpu);

        let program = Chip::new(RiscvAir::Program(ProgramChip::default()));
        chips.push(program);

        let sha_extend = Chip::new(RiscvAir::Sha256Extend(ShaExtendChip::default()));
        chips.push(sha_extend);
        syscall_costs.insert(SyscallCode::SHA_EXTEND, 48 * sha_extend.cost());

        let sha_compress = Chip::new(RiscvAir::Sha256Compress(ShaCompressChip::default()));
        chips.push(sha_compress);
        syscall_costs.insert(SyscallCode::SHA_COMPRESS, 80 * sha_compress.cost());

        let ed_add_assign = Chip::new(RiscvAir::Ed25519Add(EdAddAssignChip::<
            EdwardsCurve<Ed25519Parameters>,
        >::new()));
        chips.push(ed_add_assign);
        syscall_costs.insert(SyscallCode::ED_ADD, ed_add_assign.cost());

        let ed_decompress = Chip::new(RiscvAir::Ed25519Decompress(EdDecompressChip::<
            Ed25519Parameters,
        >::default()));
        chips.push(ed_decompress);
        syscall_costs.insert(SyscallCode::ED_DECOMPRESS, ed_decompress.cost());

        let k256_decompress = Chip::new(RiscvAir::K256Decompress(WeierstrassDecompressChip::<
            SwCurve<Secp256k1Parameters>,
        >::with_lsb_rule()));
        chips.push(k256_decompress);
        syscall_costs.insert(SyscallCode::SECP256K1_DECOMPRESS, k256_decompress.cost());

        let secp256k1_add_assign = Chip::new(RiscvAir::Secp256k1Add(WeierstrassAddAssignChip::<
            SwCurve<Secp256k1Parameters>,
        >::new()));
        chips.push(secp256k1_add_assign);
        syscall_costs.insert(SyscallCode::SECP256K1_ADD, secp256k1_add_assign.cost());

        let secp256k1_double_assign =
            Chip::new(RiscvAir::Secp256k1Double(WeierstrassDoubleAssignChip::<
                SwCurve<Secp256k1Parameters>,
            >::new()));
        chips.push(secp256k1_double_assign);
        syscall_costs.insert(SyscallCode::SECP256K1_DOUBLE, secp256k1_double_assign.cost());

        let keccak_permute = Chip::new(RiscvAir::KeccakP(KeccakPermuteChip::new()));
        chips.push(keccak_permute);
        syscall_costs.insert(SyscallCode::KECCAK_PERMUTE, 24 * keccak_permute.cost());

        let bn254_add_assign = Chip::new(RiscvAir::Bn254Add(WeierstrassAddAssignChip::<
            SwCurve<Bn254Parameters>,
        >::new()));
        chips.push(bn254_add_assign);
        syscall_costs.insert(SyscallCode::BN254_ADD, bn254_add_assign.cost());

        let bn254_double_assign = Chip::new(RiscvAir::Bn254Double(WeierstrassDoubleAssignChip::<
            SwCurve<Bn254Parameters>,
        >::new()));
        chips.push(bn254_double_assign);

        let bls12381_add = Chip::new(RiscvAir::Bls12381Add(WeierstrassAddAssignChip::<
            SwCurve<Bls12381Parameters>,
        >::new()));
        chips.push(bls12381_add);
        syscall_costs.insert(SyscallCode::BLS12381_ADD, bls12381_add.cost());

        let bls12381_double = Chip::new(RiscvAir::Bls12381Double(WeierstrassDoubleAssignChip::<
            SwCurve<Bls12381Parameters>,
        >::new()));
        chips.push(bls12381_double);
        syscall_costs.insert(SyscallCode::BLS12381_DOUBLE, bls12381_double.cost());

        let uint256_mul = Chip::new(RiscvAir::Uint256Mul(Uint256MulChip::default()));
        chips.push(uint256_mul);
        syscall_costs.insert(SyscallCode::UINT256_MUL, uint256_mul.cost());

        let bls12381_fp = Chip::new(RiscvAir::Bls12381Fp(FpOpChip::<Bls12381BaseField>::new()));
        chips.push(bls12381_fp);
        syscall_costs.insert(SyscallCode::BLS12381_FP_ADD, bls12381_fp.cost());

        let bls12381_fp2_addsub =
            Chip::new(RiscvAir::Bls12381Fp2AddSub(Fp2AddSubAssignChip::<Bls12381BaseField>::new()));
        chips.push(bls12381_fp2_addsub);
        syscall_costs.insert(SyscallCode::BLS12381_FP2_ADD, bls12381_fp2_addsub.cost());

        let bls12381_fp2_mul =
            Chip::new(RiscvAir::Bls12381Fp2Mul(Fp2MulAssignChip::<Bls12381BaseField>::new()));
        chips.push(bls12381_fp2_mul);
        syscall_costs.insert(SyscallCode::BLS12381_FP2_MUL, bls12381_fp2_mul.cost());

        let bn254_fp = Chip::new(RiscvAir::Bn254Fp(FpOpChip::<Bn254BaseField>::new()));
        chips.push(bn254_fp);
        syscall_costs.insert(SyscallCode::BN254_FP_ADD, bn254_fp.cost());

        let bn254_fp2_addsub =
            Chip::new(RiscvAir::Bn254Fp2AddSub(Fp2AddSubAssignChip::<Bn254BaseField>::new()));
        chips.push(bn254_fp2_addsub);
        syscall_costs.insert(SyscallCode::BN254_FP2_ADD, bn254_fp2_addsub.cost());

        let bn254_fp2_mul =
            Chip::new(RiscvAir::Bn254Fp2Mul(Fp2MulAssignChip::<Bn254BaseField>::new()));
        chips.push(bn254_fp2_mul);
        syscall_costs.insert(SyscallCode::BN254_FP2_MUL, bn254_fp2_mul.cost());

        let bls12381_decompress =
            Chip::new(RiscvAir::Bls12381Decompress(WeierstrassDecompressChip::<
                SwCurve<Bls12381Parameters>,
            >::with_lexicographic_rule()));
        chips.push(bls12381_decompress);
        syscall_costs.insert(SyscallCode::BLS12381_DECOMPRESS, bls12381_decompress.cost());

        let div_rem = Chip::new(RiscvAir::DivRem(DivRemChip::default()));
        chips.push(div_rem);
        opcode_costs.insert(Opcode::DIV, div_rem.cost());
        opcode_costs.insert(Opcode::DIVU, div_rem.cost());
        opcode_costs.insert(Opcode::REM, div_rem.cost());
        opcode_costs.insert(Opcode::REMU, div_rem.cost());

        let add_sub = Chip::new(RiscvAir::Add(AddSubChip::default()));
        chips.push(add_sub);
        opcode_costs.insert(Opcode::ADD, add_sub.cost());
        opcode_costs.insert(Opcode::SUB, add_sub.cost());

        // let bitwise = BitwiseChip::default();
        // chips.push(RiscvAir::Bitwise(bitwise));
        // let mul = MulChip::default();
        // chips.push(RiscvAir::Mul(mul));
        // let shift_right = ShiftRightChip::default();
        // chips.push(RiscvAir::ShiftRight(shift_right));
        // let shift_left = ShiftLeft::default();
        // chips.push(RiscvAir::ShiftLeft(shift_left));
        // let lt = LtChip::default();
        // chips.push(RiscvAir::Lt(lt));
        // let memory_init = MemoryChip::new(MemoryChipType::Initialize);
        // chips.push(RiscvAir::MemoryInit(memory_init));
        // let memory_finalize = MemoryChip::new(MemoryChipType::Finalize);
        // chips.push(RiscvAir::MemoryFinal(memory_finalize));
        // let program_memory_init = MemoryProgramChip::new();
        // chips.push(RiscvAir::ProgramMemory(program_memory_init));
        // let byte = ByteChip::default();
        // chips.push(RiscvAir::ByteLookup(byte));

        chips
    }
}

impl<F: PrimeField32> PartialEq for RiscvAir<F> {
    fn eq(&self, other: &Self) -> bool {
        self.name() == other.name()
    }
}

impl<F: PrimeField32> Eq for RiscvAir<F> {}

impl<F: PrimeField32> core::hash::Hash for RiscvAir<F> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.name().hash(state);
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
pub mod tests {

    use crate::{
        io::SP1Stdin,
        riscv::RiscvAir,
        utils,
        utils::{prove, run_test, setup_logger},
    };

    use sp1_core_executor::{
        programs::tests::{
            fibonacci_program, simple_memory_program, simple_program, ssz_withdrawals_program,
        },
        Instruction, Opcode, Program,
    };
    use sp1_stark::{
        baby_bear_poseidon2::BabyBearPoseidon2, CpuProver, SP1CoreOpts, StarkProvingKey,
        StarkVerifyingKey,
    };

    #[test]
    fn test_simple_prove() {
        utils::setup_logger();
        let program = simple_program();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_shift_prove() {
        utils::setup_logger();
        let shift_ops = [Opcode::SRL, Opcode::SRA, Opcode::SLL];
        let operands =
            [(1, 1), (1234, 5678), (0xffff, 0xffff - 1), (u32::MAX - 1, u32::MAX), (u32::MAX, 0)];
        for shift_op in shift_ops.iter() {
            for op in operands.iter() {
                let instructions = vec![
                    Instruction::new(Opcode::ADD, 29, 0, op.0, false, true),
                    Instruction::new(Opcode::ADD, 30, 0, op.1, false, true),
                    Instruction::new(*shift_op, 31, 29, 3, false, false),
                ];
                let program = Program::new(instructions, 0, 0);
                run_test::<CpuProver<_, _>>(program).unwrap();
            }
        }
    }

    #[test]
    fn test_sub_prove() {
        utils::setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
            Instruction::new(Opcode::SUB, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_add_prove() {
        setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_mul_prove() {
        let mul_ops = [Opcode::MUL, Opcode::MULH, Opcode::MULHU, Opcode::MULHSU];
        utils::setup_logger();
        let operands =
            [(1, 1), (1234, 5678), (8765, 4321), (0xffff, 0xffff - 1), (u32::MAX - 1, u32::MAX)];
        for mul_op in mul_ops.iter() {
            for operand in operands.iter() {
                let instructions = vec![
                    Instruction::new(Opcode::ADD, 29, 0, operand.0, false, true),
                    Instruction::new(Opcode::ADD, 30, 0, operand.1, false, true),
                    Instruction::new(*mul_op, 31, 30, 29, false, false),
                ];
                let program = Program::new(instructions, 0, 0);
                run_test::<CpuProver<_, _>>(program).unwrap();
            }
        }
    }

    #[test]
    fn test_lt_prove() {
        setup_logger();
        let less_than = [Opcode::SLT, Opcode::SLTU];
        for lt_op in less_than.iter() {
            let instructions = vec![
                Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
                Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
                Instruction::new(*lt_op, 31, 30, 29, false, false),
            ];
            let program = Program::new(instructions, 0, 0);
            run_test::<CpuProver<_, _>>(program).unwrap();
        }
    }

    #[test]
    fn test_bitwise_prove() {
        setup_logger();
        let bitwise_opcodes = [Opcode::XOR, Opcode::OR, Opcode::AND];

        for bitwise_op in bitwise_opcodes.iter() {
            let instructions = vec![
                Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
                Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
                Instruction::new(*bitwise_op, 31, 30, 29, false, false),
            ];
            let program = Program::new(instructions, 0, 0);
            run_test::<CpuProver<_, _>>(program).unwrap();
        }
    }

    #[test]
    fn test_divrem_prove() {
        setup_logger();
        let div_rem_ops = [Opcode::DIV, Opcode::DIVU, Opcode::REM, Opcode::REMU];
        let operands = [
            (1, 1),
            (123, 456 * 789),
            (123 * 456, 789),
            (0xffff * (0xffff - 1), 0xffff),
            (u32::MAX - 5, u32::MAX - 7),
        ];
        for div_rem_op in div_rem_ops.iter() {
            for op in operands.iter() {
                let instructions = vec![
                    Instruction::new(Opcode::ADD, 29, 0, op.0, false, true),
                    Instruction::new(Opcode::ADD, 30, 0, op.1, false, true),
                    Instruction::new(*div_rem_op, 31, 29, 30, false, false),
                ];
                let program = Program::new(instructions, 0, 0);
                run_test::<CpuProver<_, _>>(program).unwrap();
            }
        }
    }

    #[test]
    fn test_fibonacci_prove_simple() {
        setup_logger();
        let program = fibonacci_program();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_fibonacci_prove_checkpoints() {
        setup_logger();

        let program = fibonacci_program();
        let stdin = SP1Stdin::new();
        let mut opts = SP1CoreOpts::default();
        opts.shard_size = 1024;
        opts.shard_batch_size = 2;
        prove::<_, CpuProver<_, _>>(program, &stdin, BabyBearPoseidon2::new(), opts).unwrap();
    }

    #[test]
    fn test_fibonacci_prove_batch() {
        setup_logger();
        let program = fibonacci_program();
        let stdin = SP1Stdin::new();
        prove::<_, CpuProver<_, _>>(
            program,
            &stdin,
            BabyBearPoseidon2::new(),
            SP1CoreOpts::default(),
        )
        .unwrap();
    }

    #[test]
    fn test_simple_memory_program_prove() {
        setup_logger();
        let program = simple_memory_program();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_ssz_withdrawal() {
        setup_logger();
        let program = ssz_withdrawals_program();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_key_serde() {
        let program = ssz_withdrawals_program();
        let config = BabyBearPoseidon2::new();
        let machine = RiscvAir::machine(config);
        let (pk, vk) = machine.setup(&program);

        let serialized_pk = bincode::serialize(&pk).unwrap();
        let deserialized_pk: StarkProvingKey<BabyBearPoseidon2> =
            bincode::deserialize(&serialized_pk).unwrap();
        assert_eq!(pk.commit, deserialized_pk.commit);
        assert_eq!(pk.pc_start, deserialized_pk.pc_start);
        assert_eq!(pk.traces, deserialized_pk.traces);
        assert_eq!(pk.data.root(), deserialized_pk.data.root());
        assert_eq!(pk.chip_ordering, deserialized_pk.chip_ordering);

        let serialized_vk = bincode::serialize(&vk).unwrap();
        let deserialized_vk: StarkVerifyingKey<BabyBearPoseidon2> =
            bincode::deserialize(&serialized_vk).unwrap();
        assert_eq!(vk.commit, deserialized_vk.commit);
        assert_eq!(vk.pc_start, deserialized_vk.pc_start);
        assert_eq!(vk.chip_information.len(), deserialized_vk.chip_information.len());
        for (a, b) in vk.chip_information.iter().zip(deserialized_vk.chip_information.iter()) {
            assert_eq!(a.0, b.0);
            assert_eq!(a.1.log_n, b.1.log_n);
            assert_eq!(a.1.shift, b.1.shift);
            assert_eq!(a.2.height, b.2.height);
            assert_eq!(a.2.width, b.2.width);
        }
        assert_eq!(vk.chip_ordering, deserialized_vk.chip_ordering);
    }
}
