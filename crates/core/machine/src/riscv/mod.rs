pub mod cost;

mod shape;

use itertools::Itertools;
pub use shape::*;
use sp1_core_executor::{
    events::PrecompileLocalMemory, syscalls::SyscallCode, ExecutionRecord, Program,
};

use crate::{
    memory::{
        MemoryChipType, MemoryLocalChip, MemoryProgramChip, NUM_LOCAL_MEMORY_ENTRIES_PER_ROW,
    },
    riscv::MemoryChipType::{Finalize, Initialize},
    syscall::precompiles::fptower::{Fp2AddSubAssignChip, Fp2MulAssignChip, FpOpChip},
};
use hashbrown::{HashMap, HashSet};
use p3_field::PrimeField32;
pub use riscv_chips::*;
use sp1_curves::weierstrass::{bls12_381::Bls12381BaseField, bn254::Bn254BaseField};
use sp1_stark::{
    air::{InteractionScope, MachineAir, SP1_PROOF_NUM_PV_ELTS},
    Chip, InteractionKind, StarkGenericConfig, StarkMachine,
};
use strum_macros::{EnumDiscriminants, EnumIter};
use tracing::instrument;

pub const MAX_LOG_NUMBER_OF_SHARDS: usize = 16;
pub const MAX_NUMBER_OF_SHARDS: usize = 1 << MAX_LOG_NUMBER_OF_SHARDS;

/// A module for importing all the different RISC-V chips.
pub(crate) mod riscv_chips {
    pub use crate::{
        alu::{AddSubChip, BitwiseChip, DivRemChip, LtChip, MulChip, ShiftLeft, ShiftRightChip},
        bytes::ByteChip,
        cpu::CpuChip,
        memory::MemoryGlobalChip,
        program::ProgramChip,
        syscall::{
            chip::SyscallChip,
            precompiles::{
                edwards::{EdAddAssignChip, EdDecompressChip},
                keccak256::KeccakPermuteChip,
                sha256::{ShaCompressChip, ShaExtendChip},
                uint256::Uint256MulChip,
                weierstrass::{
                    WeierstrassAddAssignChip, WeierstrassDecompressChip,
                    WeierstrassDoubleAssignChip,
                },
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
#[derive(sp1_derive::MachineAir, EnumDiscriminants)]
#[strum_discriminants(derive(Hash, EnumIter))]
pub enum RiscvAir<F: PrimeField32> {
    /// An AIR that contains a preprocessed program table and a lookup for the instructions.
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
    /// A table for initializing the global memory state.
    MemoryGlobalInit(MemoryGlobalChip),
    /// A table for finalizing the global memory state.
    MemoryGlobalFinal(MemoryGlobalChip),
    /// A table for the local memory state.
    MemoryLocal(MemoryLocalChip),
    /// A table for initializing the program memory.
    ProgramMemory(MemoryProgramChip),
    /// A table for all the syscall invocations.
    SyscallCore(SyscallChip),
    /// A table for all the precompile invocations.
    SyscallPrecompile(SyscallChip),
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
        let chips = Self::chips();
        StarkMachine::new(config, chips, SP1_PROOF_NUM_PV_ELTS, true)
    }

    /// Get all the different RISC-V AIRs.
    pub fn chips() -> Vec<Chip<F, Self>> {
        let (chips, _) = Self::get_chips_and_costs();
        chips
    }

    /// Get all the costs of the different RISC-V AIRs.
    pub fn costs() -> HashMap<RiscvAirDiscriminants, u64> {
        let (_, costs) = Self::get_chips_and_costs();
        costs
    }

    pub fn get_airs_and_costs() -> (Vec<Self>, HashMap<RiscvAirDiscriminants, u64>) {
        let (chips, costs) = Self::get_chips_and_costs();
        (chips.into_iter().map(|chip| chip.into_inner()).collect(), costs)
    }

    /// Get all the different RISC-V AIRs.
    pub fn get_chips_and_costs() -> (Vec<Chip<F, Self>>, HashMap<RiscvAirDiscriminants, u64>) {
        let mut costs: HashMap<RiscvAirDiscriminants, u64> = HashMap::new();

        // The order of the chips is used to determine the order of trace generation.
        let mut chips = vec![];
        let cpu = Chip::new(RiscvAir::Cpu(CpuChip::default()));
        costs.insert(RiscvAirDiscriminants::Cpu, cpu.cost());
        chips.push(cpu);

        let program = Chip::new(RiscvAir::Program(ProgramChip::default()));
        chips.push(program);

        let sha_extend = Chip::new(RiscvAir::Sha256Extend(ShaExtendChip::default()));
        costs.insert(RiscvAirDiscriminants::Sha256Extend, 48 * sha_extend.cost());
        chips.push(sha_extend);

        let sha_compress = Chip::new(RiscvAir::Sha256Compress(ShaCompressChip::default()));
        costs.insert(RiscvAirDiscriminants::Sha256Compress, 80 * sha_compress.cost());
        chips.push(sha_compress);

        let ed_add_assign = Chip::new(RiscvAir::Ed25519Add(EdAddAssignChip::<
            EdwardsCurve<Ed25519Parameters>,
        >::new()));
        costs.insert(RiscvAirDiscriminants::Ed25519Add, ed_add_assign.cost());
        chips.push(ed_add_assign);

        let ed_decompress = Chip::new(RiscvAir::Ed25519Decompress(EdDecompressChip::<
            Ed25519Parameters,
        >::default()));
        costs.insert(RiscvAirDiscriminants::Ed25519Decompress, ed_decompress.cost());
        chips.push(ed_decompress);

        let k256_decompress = Chip::new(RiscvAir::K256Decompress(WeierstrassDecompressChip::<
            SwCurve<Secp256k1Parameters>,
        >::with_lsb_rule()));
        costs.insert(RiscvAirDiscriminants::K256Decompress, k256_decompress.cost());
        chips.push(k256_decompress);

        let secp256k1_add_assign = Chip::new(RiscvAir::Secp256k1Add(WeierstrassAddAssignChip::<
            SwCurve<Secp256k1Parameters>,
        >::new()));
        costs.insert(RiscvAirDiscriminants::Secp256k1Add, secp256k1_add_assign.cost());
        chips.push(secp256k1_add_assign);

        let secp256k1_double_assign =
            Chip::new(RiscvAir::Secp256k1Double(WeierstrassDoubleAssignChip::<
                SwCurve<Secp256k1Parameters>,
            >::new()));
        costs.insert(RiscvAirDiscriminants::Secp256k1Double, secp256k1_double_assign.cost());
        chips.push(secp256k1_double_assign);

        let keccak_permute = Chip::new(RiscvAir::KeccakP(KeccakPermuteChip::new()));
        costs.insert(RiscvAirDiscriminants::KeccakP, 24 * keccak_permute.cost());
        chips.push(keccak_permute);

        let bn254_add_assign = Chip::new(RiscvAir::Bn254Add(WeierstrassAddAssignChip::<
            SwCurve<Bn254Parameters>,
        >::new()));
        costs.insert(RiscvAirDiscriminants::Bn254Add, bn254_add_assign.cost());
        chips.push(bn254_add_assign);

        let bn254_double_assign = Chip::new(RiscvAir::Bn254Double(WeierstrassDoubleAssignChip::<
            SwCurve<Bn254Parameters>,
        >::new()));
        costs.insert(RiscvAirDiscriminants::Bn254Double, bn254_double_assign.cost());
        chips.push(bn254_double_assign);

        let bls12381_add = Chip::new(RiscvAir::Bls12381Add(WeierstrassAddAssignChip::<
            SwCurve<Bls12381Parameters>,
        >::new()));
        costs.insert(RiscvAirDiscriminants::Bls12381Add, bls12381_add.cost());
        chips.push(bls12381_add);

        let bls12381_double = Chip::new(RiscvAir::Bls12381Double(WeierstrassDoubleAssignChip::<
            SwCurve<Bls12381Parameters>,
        >::new()));
        costs.insert(RiscvAirDiscriminants::Bls12381Double, bls12381_double.cost());
        chips.push(bls12381_double);

        let uint256_mul = Chip::new(RiscvAir::Uint256Mul(Uint256MulChip::default()));
        costs.insert(RiscvAirDiscriminants::Uint256Mul, uint256_mul.cost());
        chips.push(uint256_mul);

        let bls12381_fp = Chip::new(RiscvAir::Bls12381Fp(FpOpChip::<Bls12381BaseField>::new()));
        costs.insert(RiscvAirDiscriminants::Bls12381Fp, bls12381_fp.cost());
        chips.push(bls12381_fp);

        let bls12381_fp2_addsub =
            Chip::new(RiscvAir::Bls12381Fp2AddSub(Fp2AddSubAssignChip::<Bls12381BaseField>::new()));
        costs.insert(RiscvAirDiscriminants::Bls12381Fp2AddSub, bls12381_fp2_addsub.cost());
        chips.push(bls12381_fp2_addsub);

        let bls12381_fp2_mul =
            Chip::new(RiscvAir::Bls12381Fp2Mul(Fp2MulAssignChip::<Bls12381BaseField>::new()));
        costs.insert(RiscvAirDiscriminants::Bls12381Fp2Mul, bls12381_fp2_mul.cost());
        chips.push(bls12381_fp2_mul);

        let bn254_fp = Chip::new(RiscvAir::Bn254Fp(FpOpChip::<Bn254BaseField>::new()));
        costs.insert(RiscvAirDiscriminants::Bn254Fp, bn254_fp.cost());
        chips.push(bn254_fp);

        let bn254_fp2_addsub =
            Chip::new(RiscvAir::Bn254Fp2AddSub(Fp2AddSubAssignChip::<Bn254BaseField>::new()));
        costs.insert(RiscvAirDiscriminants::Bn254Fp2AddSub, bn254_fp2_addsub.cost());
        chips.push(bn254_fp2_addsub);

        let bn254_fp2_mul =
            Chip::new(RiscvAir::Bn254Fp2Mul(Fp2MulAssignChip::<Bn254BaseField>::new()));
        costs.insert(RiscvAirDiscriminants::Bn254Fp2Mul, bn254_fp2_mul.cost());
        chips.push(bn254_fp2_mul);

        let bls12381_decompress =
            Chip::new(RiscvAir::Bls12381Decompress(WeierstrassDecompressChip::<
                SwCurve<Bls12381Parameters>,
            >::with_lexicographic_rule()));
        costs.insert(RiscvAirDiscriminants::Bls12381Decompress, bls12381_decompress.cost());
        chips.push(bls12381_decompress);

        let syscall_core = Chip::new(RiscvAir::SyscallCore(SyscallChip::core()));
        costs.insert(RiscvAirDiscriminants::SyscallCore, syscall_core.cost());
        chips.push(syscall_core);

        let syscall_precompile = Chip::new(RiscvAir::SyscallPrecompile(SyscallChip::precompile()));
        costs.insert(RiscvAirDiscriminants::SyscallPrecompile, syscall_precompile.cost());
        chips.push(syscall_precompile);

        let div_rem = Chip::new(RiscvAir::DivRem(DivRemChip::default()));
        costs.insert(RiscvAirDiscriminants::DivRem, div_rem.cost());
        chips.push(div_rem);

        let add_sub = Chip::new(RiscvAir::Add(AddSubChip::default()));
        costs.insert(RiscvAirDiscriminants::Add, add_sub.cost());
        chips.push(add_sub);

        let bitwise = Chip::new(RiscvAir::Bitwise(BitwiseChip::default()));
        costs.insert(RiscvAirDiscriminants::Bitwise, bitwise.cost());
        chips.push(bitwise);

        let mul = Chip::new(RiscvAir::Mul(MulChip::default()));
        costs.insert(RiscvAirDiscriminants::Mul, mul.cost());
        chips.push(mul);

        let shift_right = Chip::new(RiscvAir::ShiftRight(ShiftRightChip::default()));
        costs.insert(RiscvAirDiscriminants::ShiftRight, shift_right.cost());
        chips.push(shift_right);

        let shift_left = Chip::new(RiscvAir::ShiftLeft(ShiftLeft::default()));
        costs.insert(RiscvAirDiscriminants::ShiftLeft, shift_left.cost());
        chips.push(shift_left);

        let lt = Chip::new(RiscvAir::Lt(LtChip::default()));
        costs.insert(RiscvAirDiscriminants::Lt, lt.cost());
        chips.push(lt);

        let memory_global_init = Chip::new(RiscvAir::MemoryGlobalInit(MemoryGlobalChip::new(
            MemoryChipType::Initialize,
        )));
        costs.insert(RiscvAirDiscriminants::MemoryGlobalInit, memory_global_init.cost());
        chips.push(memory_global_init);

        let memory_global_finalize =
            Chip::new(RiscvAir::MemoryGlobalFinal(MemoryGlobalChip::new(MemoryChipType::Finalize)));
        costs.insert(RiscvAirDiscriminants::MemoryGlobalFinal, memory_global_finalize.cost());
        chips.push(memory_global_finalize);

        let memory_local = Chip::new(RiscvAir::MemoryLocal(MemoryLocalChip::new()));
        costs.insert(RiscvAirDiscriminants::MemoryLocal, memory_local.cost());
        chips.push(memory_local);

        let memory_program = Chip::new(RiscvAir::ProgramMemory(MemoryProgramChip::default()));
        costs.insert(RiscvAirDiscriminants::ProgramMemory, memory_program.cost());
        chips.push(memory_program);

        let byte = Chip::new(RiscvAir::ByteLookup(ByteChip::default()));
        costs.insert(RiscvAirDiscriminants::ByteLookup, byte.cost());
        chips.push(byte);

        (chips, costs)
    }

    /// Get the heights of the preprocessed chips for a given program.
    pub(crate) fn preprocessed_heights(program: &Program) -> Vec<(Self, usize)> {
        vec![
            (RiscvAir::Program(ProgramChip::default()), program.instructions.len()),
            (RiscvAir::ProgramMemory(MemoryProgramChip::default()), program.memory_image.len()),
            (RiscvAir::ByteLookup(ByteChip::default()), 1 << 16),
        ]
    }

    /// Get the heights of the chips for a given execution record.
    pub(crate) fn core_heights(record: &ExecutionRecord) -> Vec<(Self, usize)> {
        vec![
            (RiscvAir::Cpu(CpuChip::default()), record.cpu_events.len()),
            (RiscvAir::DivRem(DivRemChip::default()), record.divrem_events.len()),
            (
                RiscvAir::Add(AddSubChip::default()),
                record.add_events.len() + record.sub_events.len(),
            ),
            (RiscvAir::Bitwise(BitwiseChip::default()), record.bitwise_events.len()),
            (RiscvAir::Mul(MulChip::default()), record.mul_events.len()),
            (RiscvAir::ShiftRight(ShiftRightChip::default()), record.shift_right_events.len()),
            (RiscvAir::ShiftLeft(ShiftLeft::default()), record.shift_left_events.len()),
            (RiscvAir::Lt(LtChip::default()), record.lt_events.len()),
            (
                RiscvAir::MemoryLocal(MemoryLocalChip::new()),
                record
                    .get_local_mem_events()
                    .chunks(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
                    .into_iter()
                    .count(),
            ),
            (RiscvAir::SyscallCore(SyscallChip::core()), record.syscall_events.len()),
        ]
    }

    pub(crate) fn get_all_core_airs() -> Vec<Self> {
        vec![
            RiscvAir::Cpu(CpuChip::default()),
            RiscvAir::Add(AddSubChip::default()),
            RiscvAir::Bitwise(BitwiseChip::default()),
            RiscvAir::Mul(MulChip::default()),
            RiscvAir::DivRem(DivRemChip::default()),
            RiscvAir::Lt(LtChip::default()),
            RiscvAir::ShiftLeft(ShiftLeft::default()),
            RiscvAir::ShiftRight(ShiftRightChip::default()),
            RiscvAir::MemoryLocal(MemoryLocalChip::new()),
            RiscvAir::SyscallCore(SyscallChip::core()),
        ]
    }

    pub(crate) fn memory_init_final_airs() -> Vec<Self> {
        vec![
            RiscvAir::MemoryGlobalInit(MemoryGlobalChip::new(MemoryChipType::Initialize)),
            RiscvAir::MemoryGlobalFinal(MemoryGlobalChip::new(MemoryChipType::Finalize)),
        ]
    }

    pub(crate) fn get_memory_init_final_heights(record: &ExecutionRecord) -> Vec<(Self, usize)> {
        vec![
            (
                RiscvAir::MemoryGlobalInit(MemoryGlobalChip::new(Initialize)),
                record.global_memory_initialize_events.len(),
            ),
            (
                RiscvAir::MemoryGlobalFinal(MemoryGlobalChip::new(Finalize)),
                record.global_memory_finalize_events.len(),
            ),
        ]
    }

    pub(crate) fn get_all_precompile_airs() -> Vec<(Self, usize)> {
        let mut airs: HashSet<_> = Self::get_airs_and_costs().0.into_iter().collect();
        for core_air in Self::get_all_core_airs() {
            airs.remove(&core_air);
        }
        for memory_air in Self::memory_init_final_airs() {
            airs.remove(&memory_air);
        }
        airs.remove(&Self::SyscallPrecompile(SyscallChip::precompile()));

        // Remove the preprocessed chips.
        airs.remove(&Self::Program(ProgramChip::default()));
        airs.remove(&Self::ProgramMemory(MemoryProgramChip::default()));
        airs.remove(&Self::ByteLookup(ByteChip::default()));

        airs.into_iter()
            .map(|air| {
                let chip = Chip::new(air);
                let local_mem_events: usize = chip
                    .sends()
                    .iter()
                    .chain(chip.receives())
                    .filter(|interaction| {
                        interaction.kind == InteractionKind::Memory
                            && interaction.scope == InteractionScope::Local
                    })
                    .count();

                (chip.into_inner(), local_mem_events)
            })
            .collect()
    }

    pub(crate) fn rows_per_event(&self) -> usize {
        match self {
            Self::Sha256Compress(_) => 80,
            Self::Sha256Extend(_) => 48,
            Self::KeccakP(_) => 24,
            _ => 1,
        }
    }

    pub(crate) fn syscall_code(&self) -> SyscallCode {
        match self {
            Self::Bls12381Add(_) => SyscallCode::BLS12381_ADD,
            Self::Bn254Add(_) => SyscallCode::BN254_ADD,
            Self::Bn254Double(_) => SyscallCode::BN254_DOUBLE,
            Self::Bn254Fp(_) => SyscallCode::BN254_FP_ADD,
            Self::Bn254Fp2AddSub(_) => SyscallCode::BN254_FP2_ADD,
            Self::Bn254Fp2Mul(_) => SyscallCode::BN254_FP2_MUL,
            Self::Ed25519Add(_) => SyscallCode::ED_ADD,
            Self::Ed25519Decompress(_) => SyscallCode::ED_DECOMPRESS,
            Self::KeccakP(_) => SyscallCode::KECCAK_PERMUTE,
            Self::Secp256k1Add(_) => SyscallCode::SECP256K1_ADD,
            Self::Secp256k1Double(_) => SyscallCode::SECP256K1_DOUBLE,
            Self::Sha256Compress(_) => SyscallCode::SHA_COMPRESS,
            Self::Sha256Extend(_) => SyscallCode::SHA_EXTEND,
            Self::Uint256Mul(_) => SyscallCode::UINT256_MUL,
            Self::Bls12381Decompress(_) => SyscallCode::BLS12381_DECOMPRESS,
            Self::K256Decompress(_) => SyscallCode::SECP256K1_DECOMPRESS,
            Self::Bls12381Double(_) => SyscallCode::BLS12381_DOUBLE,
            Self::Bls12381Fp(_) => SyscallCode::BLS12381_FP_ADD,
            Self::Bls12381Fp2Mul(_) => SyscallCode::BLS12381_FP2_MUL,
            Self::Bls12381Fp2AddSub(_) => SyscallCode::BLS12381_FP2_ADD,
            Self::Add(_) => unreachable!("Invalid for core chip"),
            Self::Bitwise(_) => unreachable!("Invalid for core chip"),
            Self::DivRem(_) => unreachable!("Invalid for core chip"),
            Self::Cpu(_) => unreachable!("Invalid for core chip"),
            Self::MemoryGlobalInit(_) => unreachable!("Invalid for memory init/final"),
            Self::MemoryGlobalFinal(_) => unreachable!("Invalid for memory init/final"),
            Self::MemoryLocal(_) => unreachable!("Invalid for memory local"),
            Self::ProgramMemory(_) => unreachable!("Invalid for memory program"),
            Self::Program(_) => unreachable!("Invalid for core chip"),
            Self::Mul(_) => unreachable!("Invalid for core chip"),
            Self::Lt(_) => unreachable!("Invalid for core chip"),
            Self::ShiftRight(_) => unreachable!("Invalid for core chip"),
            Self::ShiftLeft(_) => unreachable!("Invalid for core chip"),
            Self::ByteLookup(_) => unreachable!("Invalid for core chip"),
            Self::SyscallCore(_) => unreachable!("Invalid for core chip"),
            Self::SyscallPrecompile(_) => unreachable!("Invalid for syscall precompile chip"),
        }
    }

    /// Get the height of the corresponding precompile chip.
    ///
    /// If the precompile is not included in the record, returns `None`. Otherwise, returns
    /// `Some(num_rows, num_local_mem_events)`, where `num_rows` is the number of rows of the
    /// corresponding chip and `num_local_mem_events` is the number of local memory events.
    pub(crate) fn get_precompile_heights(
        &self,
        record: &ExecutionRecord,
    ) -> Option<(usize, usize)> {
        record
            .precompile_events
            .get_events(self.syscall_code())
            .filter(|events| !events.is_empty())
            .map(|events| {
                (
                    events.len() * self.rows_per_event(),
                    events.get_local_mem_events().into_iter().count(),
                )
            })
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
        prove::<_, CpuProver<_, _>>(program, &stdin, BabyBearPoseidon2::new(), opts, None).unwrap();
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
            None,
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
