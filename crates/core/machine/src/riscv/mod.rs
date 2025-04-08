pub use riscv_chips::*;

use core::fmt;

use hashbrown::{HashMap, HashSet};
use p3_field::PrimeField32;
use sp1_core_executor::{ExecutionRecord, Program, RiscvAirId};
use sp1_curves::weierstrass::{bls12_381::Bls12381BaseField, bn254::Bn254BaseField};
use sp1_stark::{
    air::{InteractionScope, MachineAir, SP1_PROOF_NUM_PV_ELTS},
    Chip, InteractionKind, StarkGenericConfig, StarkMachine,
};
use strum_macros::{EnumDiscriminants, EnumIter};

use crate::{
    bytes::trace::NUM_ROWS as BYTE_CHIP_NUM_ROWS,
    control_flow::{AuipcChip, BranchChip, JumpChip},
    global::GlobalChip,
    memory::{MemoryChipType, MemoryInstructionsChip, MemoryLocalChip},
    shape::Shapeable,
    syscall::{
        instructions::SyscallInstrsChip,
        precompiles::fptower::{Fp2AddSubAssignChip, Fp2MulAssignChip, FpOpChip},
    },
};

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
                u256x2048_mul::U256x2048MulChip,
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
            secp256r1::Secp256r1Parameters, SwCurve,
        },
    };
}

/// The maximum log number of shards in core.
pub const MAX_LOG_NUMBER_OF_SHARDS: usize = 16;

/// The maximum number of shards in core.
pub const MAX_NUMBER_OF_SHARDS: usize = 1 << MAX_LOG_NUMBER_OF_SHARDS;

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
    /// An AIR for RISC-V memory instructions.
    Memory(MemoryInstructionsChip),
    /// An AIR for RISC-V AUIPC instruction.
    AUIPC(AuipcChip),
    /// An AIR for RISC-V branch instructions.
    Branch(BranchChip),
    /// An AIR for RISC-V jump instructions.
    Jump(JumpChip),
    /// An AIR for RISC-V ecall instructions.
    SyscallInstrs(SyscallInstrsChip),
    /// A lookup table for byte operations.
    ByteLookup(ByteChip<F>),
    /// A table for initializing the global memory state.
    MemoryGlobalInit(MemoryGlobalChip),
    /// A table for finalizing the global memory state.
    MemoryGlobalFinal(MemoryGlobalChip),
    /// A table for the local memory state.
    MemoryLocal(MemoryLocalChip),
    /// A table for all the syscall invocations.
    SyscallCore(SyscallChip),
    /// A table for all the precompile invocations.
    SyscallPrecompile(SyscallChip),
    /// A table for all the global interactions.
    Global(GlobalChip),
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
    /// A precompile for decompressing a point on the P256 curve.
    P256Decompress(WeierstrassDecompressChip<SwCurve<Secp256r1Parameters>>),
    /// A precompile for addition on the Elliptic curve secp256k1.
    Secp256k1Add(WeierstrassAddAssignChip<SwCurve<Secp256k1Parameters>>),
    /// A precompile for doubling a point on the Elliptic curve secp256k1.
    Secp256k1Double(WeierstrassDoubleAssignChip<SwCurve<Secp256k1Parameters>>),
    /// A precompile for addition on the Elliptic curve secp256r1.
    Secp256r1Add(WeierstrassAddAssignChip<SwCurve<Secp256r1Parameters>>),
    /// A precompile for doubling a point on the Elliptic curve secp256r1.
    Secp256r1Double(WeierstrassDoubleAssignChip<SwCurve<Secp256r1Parameters>>),
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
    /// A precompile for u256x2048 mul.
    U256x2048Mul(U256x2048MulChip),
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
    pub fn id(&self) -> RiscvAirId {
        RiscvAirId::from(RiscvAirDiscriminants::from(self))
    }

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
    pub fn costs() -> HashMap<String, u64> {
        let (_, costs) = Self::get_chips_and_costs();
        costs
    }

    /// Get all the different RISC-V AIRs and their costs.
    pub fn get_airs_and_costs() -> (Vec<Self>, HashMap<String, u64>) {
        let (chips, costs) = Self::get_chips_and_costs();
        (chips.into_iter().map(|chip| chip.into_inner()).collect(), costs)
    }

    /// Get all the different RISC-V chips and their costs.
    pub fn get_chips_and_costs() -> (Vec<Chip<F, Self>>, HashMap<String, u64>) {
        let mut costs: HashMap<String, u64> = HashMap::new();

        // The order of the chips is used to determine the order of trace generation.
        let mut chips = vec![];
        let cpu = Chip::new(RiscvAir::Cpu(CpuChip::default()));
        costs.insert(cpu.name(), cpu.cost());
        chips.push(cpu);

        let program = Chip::new(RiscvAir::Program(ProgramChip::default()));
        costs.insert(program.name(), program.cost());
        chips.push(program);

        let sha_extend = Chip::new(RiscvAir::Sha256Extend(ShaExtendChip::default()));
        costs.insert(sha_extend.name(), sha_extend.cost());
        chips.push(sha_extend);

        let sha_compress = Chip::new(RiscvAir::Sha256Compress(ShaCompressChip::default()));
        costs.insert(sha_compress.name(), sha_compress.cost());
        chips.push(sha_compress);

        let ed_add_assign = Chip::new(RiscvAir::Ed25519Add(EdAddAssignChip::<
            EdwardsCurve<Ed25519Parameters>,
        >::new()));
        costs.insert(ed_add_assign.name(), ed_add_assign.cost());
        chips.push(ed_add_assign);

        let ed_decompress = Chip::new(RiscvAir::Ed25519Decompress(EdDecompressChip::<
            Ed25519Parameters,
        >::default()));
        costs.insert(ed_decompress.name(), ed_decompress.cost());
        chips.push(ed_decompress);

        let k256_decompress = Chip::new(RiscvAir::K256Decompress(WeierstrassDecompressChip::<
            SwCurve<Secp256k1Parameters>,
        >::with_lsb_rule()));
        costs.insert(k256_decompress.name(), k256_decompress.cost());
        chips.push(k256_decompress);

        let secp256k1_add_assign = Chip::new(RiscvAir::Secp256k1Add(WeierstrassAddAssignChip::<
            SwCurve<Secp256k1Parameters>,
        >::new()));
        costs.insert(secp256k1_add_assign.name(), secp256k1_add_assign.cost());
        chips.push(secp256k1_add_assign);

        let secp256k1_double_assign =
            Chip::new(RiscvAir::Secp256k1Double(WeierstrassDoubleAssignChip::<
                SwCurve<Secp256k1Parameters>,
            >::new()));
        costs.insert(secp256k1_double_assign.name(), secp256k1_double_assign.cost());
        chips.push(secp256k1_double_assign);

        let p256_decompress = Chip::new(RiscvAir::P256Decompress(WeierstrassDecompressChip::<
            SwCurve<Secp256r1Parameters>,
        >::with_lsb_rule()));
        costs.insert(p256_decompress.name(), p256_decompress.cost());
        chips.push(p256_decompress);

        let secp256r1_add_assign = Chip::new(RiscvAir::Secp256r1Add(WeierstrassAddAssignChip::<
            SwCurve<Secp256r1Parameters>,
        >::new()));
        costs.insert(secp256r1_add_assign.name(), secp256r1_add_assign.cost());
        chips.push(secp256r1_add_assign);

        let secp256r1_double_assign =
            Chip::new(RiscvAir::Secp256r1Double(WeierstrassDoubleAssignChip::<
                SwCurve<Secp256r1Parameters>,
            >::new()));
        costs.insert(secp256r1_double_assign.name(), secp256r1_double_assign.cost());
        chips.push(secp256r1_double_assign);

        let keccak_permute = Chip::new(RiscvAir::KeccakP(KeccakPermuteChip::new()));
        costs.insert(keccak_permute.name(), keccak_permute.cost());
        chips.push(keccak_permute);

        let bn254_add_assign = Chip::new(RiscvAir::Bn254Add(WeierstrassAddAssignChip::<
            SwCurve<Bn254Parameters>,
        >::new()));
        costs.insert(bn254_add_assign.name(), bn254_add_assign.cost());
        chips.push(bn254_add_assign);

        let bn254_double_assign = Chip::new(RiscvAir::Bn254Double(WeierstrassDoubleAssignChip::<
            SwCurve<Bn254Parameters>,
        >::new()));
        costs.insert(bn254_double_assign.name(), bn254_double_assign.cost());
        chips.push(bn254_double_assign);

        let bls12381_add = Chip::new(RiscvAir::Bls12381Add(WeierstrassAddAssignChip::<
            SwCurve<Bls12381Parameters>,
        >::new()));
        costs.insert(bls12381_add.name(), bls12381_add.cost());
        chips.push(bls12381_add);

        let bls12381_double = Chip::new(RiscvAir::Bls12381Double(WeierstrassDoubleAssignChip::<
            SwCurve<Bls12381Parameters>,
        >::new()));
        costs.insert(bls12381_double.name(), bls12381_double.cost());
        chips.push(bls12381_double);

        let uint256_mul = Chip::new(RiscvAir::Uint256Mul(Uint256MulChip::default()));
        costs.insert(uint256_mul.name(), uint256_mul.cost());
        chips.push(uint256_mul);

        let u256x2048_mul = Chip::new(RiscvAir::U256x2048Mul(U256x2048MulChip::default()));
        costs.insert(u256x2048_mul.name(), u256x2048_mul.cost());
        chips.push(u256x2048_mul);

        let bls12381_fp = Chip::new(RiscvAir::Bls12381Fp(FpOpChip::<Bls12381BaseField>::new()));
        costs.insert(bls12381_fp.name(), bls12381_fp.cost());
        chips.push(bls12381_fp);

        let bls12381_fp2_addsub =
            Chip::new(RiscvAir::Bls12381Fp2AddSub(Fp2AddSubAssignChip::<Bls12381BaseField>::new()));
        costs.insert(bls12381_fp2_addsub.name(), bls12381_fp2_addsub.cost());
        chips.push(bls12381_fp2_addsub);

        let bls12381_fp2_mul =
            Chip::new(RiscvAir::Bls12381Fp2Mul(Fp2MulAssignChip::<Bls12381BaseField>::new()));
        costs.insert(bls12381_fp2_mul.name(), bls12381_fp2_mul.cost());
        chips.push(bls12381_fp2_mul);

        let bn254_fp = Chip::new(RiscvAir::Bn254Fp(FpOpChip::<Bn254BaseField>::new()));
        costs.insert(bn254_fp.name(), bn254_fp.cost());
        chips.push(bn254_fp);

        let bn254_fp2_addsub =
            Chip::new(RiscvAir::Bn254Fp2AddSub(Fp2AddSubAssignChip::<Bn254BaseField>::new()));
        costs.insert(bn254_fp2_addsub.name(), bn254_fp2_addsub.cost());
        chips.push(bn254_fp2_addsub);

        let bn254_fp2_mul =
            Chip::new(RiscvAir::Bn254Fp2Mul(Fp2MulAssignChip::<Bn254BaseField>::new()));
        costs.insert(bn254_fp2_mul.name(), bn254_fp2_mul.cost());
        chips.push(bn254_fp2_mul);

        let bls12381_decompress =
            Chip::new(RiscvAir::Bls12381Decompress(WeierstrassDecompressChip::<
                SwCurve<Bls12381Parameters>,
            >::with_lexicographic_rule()));
        costs.insert(bls12381_decompress.name(), bls12381_decompress.cost());
        chips.push(bls12381_decompress);

        let syscall_core = Chip::new(RiscvAir::SyscallCore(SyscallChip::core()));
        costs.insert(syscall_core.name(), syscall_core.cost());
        chips.push(syscall_core);

        let syscall_precompile = Chip::new(RiscvAir::SyscallPrecompile(SyscallChip::precompile()));
        costs.insert(syscall_precompile.name(), syscall_precompile.cost());
        chips.push(syscall_precompile);

        let div_rem = Chip::new(RiscvAir::DivRem(DivRemChip::default()));
        costs.insert(div_rem.name(), div_rem.cost());
        chips.push(div_rem);

        let add_sub = Chip::new(RiscvAir::Add(AddSubChip::default()));
        costs.insert(add_sub.name(), add_sub.cost());
        chips.push(add_sub);

        let bitwise = Chip::new(RiscvAir::Bitwise(BitwiseChip::default()));
        costs.insert(bitwise.name(), bitwise.cost());
        chips.push(bitwise);

        let mul = Chip::new(RiscvAir::Mul(MulChip::default()));
        costs.insert(mul.name(), mul.cost());
        chips.push(mul);

        let shift_right = Chip::new(RiscvAir::ShiftRight(ShiftRightChip::default()));
        costs.insert(shift_right.name(), shift_right.cost());
        chips.push(shift_right);

        let shift_left = Chip::new(RiscvAir::ShiftLeft(ShiftLeft::default()));
        costs.insert(shift_left.name(), shift_left.cost());
        chips.push(shift_left);

        let lt = Chip::new(RiscvAir::Lt(LtChip::default()));
        costs.insert(lt.name(), lt.cost());
        chips.push(lt);

        let memory_instructions = Chip::new(RiscvAir::Memory(MemoryInstructionsChip::default()));
        costs.insert(memory_instructions.name(), memory_instructions.cost());
        chips.push(memory_instructions);

        let auipc = Chip::new(RiscvAir::AUIPC(AuipcChip::default()));
        costs.insert(auipc.name(), auipc.cost());
        chips.push(auipc);

        let branch = Chip::new(RiscvAir::Branch(BranchChip::default()));
        costs.insert(branch.name(), branch.cost());
        chips.push(branch);

        let jump = Chip::new(RiscvAir::Jump(JumpChip::default()));
        costs.insert(jump.name(), jump.cost());
        chips.push(jump);

        let syscall_instrs = Chip::new(RiscvAir::SyscallInstrs(SyscallInstrsChip::default()));
        costs.insert(syscall_instrs.name(), syscall_instrs.cost());
        chips.push(syscall_instrs);

        let memory_global_init = Chip::new(RiscvAir::MemoryGlobalInit(MemoryGlobalChip::new(
            MemoryChipType::Initialize,
        )));
        costs.insert(memory_global_init.name(), memory_global_init.cost());
        chips.push(memory_global_init);

        let memory_global_finalize =
            Chip::new(RiscvAir::MemoryGlobalFinal(MemoryGlobalChip::new(MemoryChipType::Finalize)));
        costs.insert(memory_global_finalize.name(), memory_global_finalize.cost());
        chips.push(memory_global_finalize);

        let memory_local = Chip::new(RiscvAir::MemoryLocal(MemoryLocalChip::new()));
        costs.insert(memory_local.name(), memory_local.cost());
        chips.push(memory_local);

        let global = Chip::new(RiscvAir::Global(GlobalChip));
        costs.insert(global.name(), global.cost());
        chips.push(global);

        let byte = Chip::new(RiscvAir::ByteLookup(ByteChip::default()));
        costs.insert(byte.name(), byte.cost());
        chips.push(byte);

        assert_eq!(chips.len(), costs.len(), "chips and costs must have the same length",);

        (chips, costs)
    }

    /// Get the heights of the preprocessed chips for a given program.
    pub(crate) fn preprocessed_heights(program: &Program) -> Vec<(RiscvAirId, usize)> {
        vec![
            (RiscvAirId::Program, program.instructions.len()),
            (RiscvAirId::Byte, BYTE_CHIP_NUM_ROWS),
        ]
    }

    /// Get the heights of the chips for a given execution record.
    pub fn core_heights(record: &ExecutionRecord) -> Vec<(RiscvAirId, usize)> {
        record.core_heights()
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
            RiscvAir::Memory(MemoryInstructionsChip::default()),
            RiscvAir::AUIPC(AuipcChip::default()),
            RiscvAir::Branch(BranchChip::default()),
            RiscvAir::Jump(JumpChip::default()),
            RiscvAir::SyscallInstrs(SyscallInstrsChip::default()),
            RiscvAir::MemoryLocal(MemoryLocalChip::new()),
            RiscvAir::Global(GlobalChip),
            RiscvAir::SyscallCore(SyscallChip::core()),
        ]
    }

    pub(crate) fn memory_init_final_airs() -> Vec<Self> {
        vec![
            RiscvAir::MemoryGlobalInit(MemoryGlobalChip::new(MemoryChipType::Initialize)),
            RiscvAir::MemoryGlobalFinal(MemoryGlobalChip::new(MemoryChipType::Finalize)),
            RiscvAir::Global(GlobalChip),
        ]
    }

    /// Returns the upper bound of the number of memory events per row of each precompile. Used in
    /// shape-fitting.
    pub(crate) fn precompile_airs_with_memory_events_per_row(
    ) -> impl Iterator<Item = (RiscvAirId, usize)> {
        let mut airs: HashSet<_> = Self::get_airs_and_costs().0.into_iter().collect();

        // Remove the core airs.
        for core_air in Self::get_all_core_airs() {
            airs.remove(&core_air);
        }

        // Remove the memory init/finalize airs.
        for memory_air in Self::memory_init_final_airs() {
            airs.remove(&memory_air);
        }

        // Remove the syscall, program, and byte lookup airs.
        airs.remove(&Self::SyscallPrecompile(SyscallChip::precompile()));
        airs.remove(&Self::Program(ProgramChip::default()));
        airs.remove(&Self::ByteLookup(ByteChip::default()));

        airs.into_iter().map(|air| {
            let chip = Chip::new(air);
            let local_mem_events_per_row: usize = chip
                .sends()
                .iter()
                .chain(chip.receives())
                .filter(|interaction| {
                    interaction.kind == InteractionKind::Memory &&
                        interaction.scope == InteractionScope::Local
                })
                .count();

            (chip.into_inner().id(), local_mem_events_per_row)
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

impl<F: PrimeField32> fmt::Debug for RiscvAir<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl From<RiscvAirDiscriminants> for RiscvAirId {
    fn from(value: RiscvAirDiscriminants) -> Self {
        match value {
            RiscvAirDiscriminants::Program => RiscvAirId::Program,
            RiscvAirDiscriminants::Cpu => RiscvAirId::Cpu,
            RiscvAirDiscriminants::Add => RiscvAirId::AddSub,
            RiscvAirDiscriminants::Bitwise => RiscvAirId::Bitwise,
            RiscvAirDiscriminants::Mul => RiscvAirId::Mul,
            RiscvAirDiscriminants::DivRem => RiscvAirId::DivRem,
            RiscvAirDiscriminants::Lt => RiscvAirId::Lt,
            RiscvAirDiscriminants::ShiftLeft => RiscvAirId::ShiftLeft,
            RiscvAirDiscriminants::ShiftRight => RiscvAirId::ShiftRight,
            RiscvAirDiscriminants::Memory => RiscvAirId::MemoryInstrs,
            RiscvAirDiscriminants::AUIPC => RiscvAirId::Auipc,
            RiscvAirDiscriminants::Branch => RiscvAirId::Branch,
            RiscvAirDiscriminants::Jump => RiscvAirId::Jump,
            RiscvAirDiscriminants::SyscallInstrs => RiscvAirId::SyscallInstrs,
            RiscvAirDiscriminants::ByteLookup => RiscvAirId::Byte,
            RiscvAirDiscriminants::MemoryGlobalInit => RiscvAirId::MemoryGlobalInit,
            RiscvAirDiscriminants::MemoryGlobalFinal => RiscvAirId::MemoryGlobalFinalize,
            RiscvAirDiscriminants::MemoryLocal => RiscvAirId::MemoryLocal,
            RiscvAirDiscriminants::SyscallCore => RiscvAirId::SyscallCore,
            RiscvAirDiscriminants::SyscallPrecompile => RiscvAirId::SyscallPrecompile,
            RiscvAirDiscriminants::Global => RiscvAirId::Global,
            RiscvAirDiscriminants::Sha256Extend => RiscvAirId::ShaExtend,
            RiscvAirDiscriminants::Sha256Compress => RiscvAirId::ShaCompress,
            RiscvAirDiscriminants::Ed25519Add => RiscvAirId::EdAddAssign,
            RiscvAirDiscriminants::Ed25519Decompress => RiscvAirId::EdDecompress,
            RiscvAirDiscriminants::K256Decompress => RiscvAirId::Secp256k1Decompress,
            RiscvAirDiscriminants::P256Decompress => RiscvAirId::Secp256r1Decompress,
            RiscvAirDiscriminants::Secp256k1Add => RiscvAirId::Secp256k1AddAssign,
            RiscvAirDiscriminants::Secp256k1Double => RiscvAirId::Secp256k1DoubleAssign,
            RiscvAirDiscriminants::Secp256r1Add => RiscvAirId::Secp256r1AddAssign,
            RiscvAirDiscriminants::Secp256r1Double => RiscvAirId::Secp256r1DoubleAssign,
            RiscvAirDiscriminants::KeccakP => RiscvAirId::KeccakPermute,
            RiscvAirDiscriminants::Bn254Add => RiscvAirId::Bn254AddAssign,
            RiscvAirDiscriminants::Bn254Double => RiscvAirId::Bn254DoubleAssign,
            RiscvAirDiscriminants::Bls12381Add => RiscvAirId::Bls12381AddAssign,
            RiscvAirDiscriminants::Bls12381Double => RiscvAirId::Bls12381DoubleAssign,
            RiscvAirDiscriminants::Uint256Mul => RiscvAirId::Uint256MulMod,
            RiscvAirDiscriminants::U256x2048Mul => RiscvAirId::U256XU2048Mul,
            RiscvAirDiscriminants::Bls12381Decompress => RiscvAirId::Bls12381Decompress,
            RiscvAirDiscriminants::Bls12381Fp => RiscvAirId::Bls12381FpOpAssign,
            RiscvAirDiscriminants::Bls12381Fp2Mul => RiscvAirId::Bls12381Fp2MulAssign,
            RiscvAirDiscriminants::Bls12381Fp2AddSub => RiscvAirId::Bls12381Fp2AddSubAssign,
            RiscvAirDiscriminants::Bn254Fp => RiscvAirId::Bn254FpOpAssign,
            RiscvAirDiscriminants::Bn254Fp2Mul => RiscvAirId::Bn254Fp2MulAssign,
            RiscvAirDiscriminants::Bn254Fp2AddSub => RiscvAirId::Bn254Fp2AddSubAssign,
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
#[allow(clippy::print_stdout)]
pub mod tests {

    use crate::{
        io::SP1Stdin,
        riscv::RiscvAir,
        utils::{self, prove_core, run_test, setup_logger},
    };

    use crate::programs::tests::*;
    use hashbrown::HashMap;
    use itertools::Itertools;
    use p3_baby_bear::BabyBear;
    use sp1_core_executor::{Instruction, Opcode, Program, RiscvAirId, SP1Context};
    use sp1_stark::{
        air::MachineAir, baby_bear_poseidon2::BabyBearPoseidon2, CpuProver, MachineProver,
        SP1CoreOpts, StarkProvingKey, StarkVerifyingKey,
    };
    use strum::IntoEnumIterator;
    #[test]
    fn test_primitives_and_machine_air_names_match() {
        let chips = RiscvAir::<BabyBear>::chips();
        for (a, b) in chips.iter().zip_eq(RiscvAirId::iter()) {
            assert_eq!(a.name(), b.to_string());
        }
    }

    #[test]
    fn core_air_cost_consistency() {
        // Load air costs from file
        let file = std::fs::File::open("../executor/src/artifacts/rv32im_costs.json").unwrap();
        let costs: HashMap<String, u64> = serde_json::from_reader(file).unwrap();
        // Compare with costs computed by machine
        let machine_costs = RiscvAir::<BabyBear>::costs();
        assert_eq!(costs, machine_costs);
    }

    #[test]
    #[ignore]
    fn write_core_air_costs() {
        let costs = RiscvAir::<BabyBear>::costs();
        println!("{:?}", costs);
        // write to file
        // Create directory if it doesn't exist
        let dir = std::path::Path::new("../executor/src/artifacts");
        if !dir.exists() {
            std::fs::create_dir_all(dir).unwrap();
        }
        let file = std::fs::File::create(dir.join("rv32im_costs.json")).unwrap();
        serde_json::to_writer_pretty(file, &costs).unwrap();
    }

    #[test]
    fn test_simple_prove() {
        utils::setup_logger();
        let program = simple_program();
        let stdin = SP1Stdin::new();
        run_test::<CpuProver<_, _>>(program, stdin).unwrap();
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
                let stdin = SP1Stdin::new();
                run_test::<CpuProver<_, _>>(program, stdin).unwrap();
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
        let stdin = SP1Stdin::new();
        run_test::<CpuProver<_, _>>(program, stdin).unwrap();
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
        let stdin = SP1Stdin::new();
        run_test::<CpuProver<_, _>>(program, stdin).unwrap();
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
                let stdin = SP1Stdin::new();
                run_test::<CpuProver<_, _>>(program, stdin).unwrap();
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
            let stdin = SP1Stdin::new();
            run_test::<CpuProver<_, _>>(program, stdin).unwrap();
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
            let stdin = SP1Stdin::new();
            run_test::<CpuProver<_, _>>(program, stdin).unwrap();
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
                let stdin = SP1Stdin::new();
                run_test::<CpuProver<_, _>>(program, stdin).unwrap();
            }
        }
    }

    #[test]
    fn test_fibonacci_prove_simple() {
        setup_logger();
        let program = fibonacci_program();
        let stdin = SP1Stdin::new();
        run_test::<CpuProver<_, _>>(program, stdin).unwrap();
    }

    #[test]
    fn test_fibonacci_prove_checkpoints() {
        setup_logger();

        let program = fibonacci_program();
        let stdin = SP1Stdin::new();
        let mut opts = SP1CoreOpts::default();
        opts.shard_size = 1024;
        opts.shard_batch_size = 2;

        let config = BabyBearPoseidon2::new();
        let machine = RiscvAir::machine(config);
        let prover = CpuProver::new(machine);
        let (pk, vk) = prover.setup(&program);
        prove_core::<_, _>(
            &prover,
            &pk,
            &vk,
            program,
            &stdin,
            opts,
            SP1Context::default(),
            None,
            None,
        )
        .unwrap();
    }

    #[test]
    fn test_fibonacci_prove_batch() {
        setup_logger();
        let program = fibonacci_program();
        let stdin = SP1Stdin::new();

        let opts = SP1CoreOpts::default();
        let config = BabyBearPoseidon2::new();
        let machine = RiscvAir::machine(config);
        let prover = CpuProver::new(machine);
        let (pk, vk) = prover.setup(&program);
        prove_core::<_, _>(
            &prover,
            &pk,
            &vk,
            program,
            &stdin,
            opts,
            SP1Context::default(),
            None,
            None,
        )
        .unwrap();
    }

    #[test]
    fn test_simple_memory_program_prove() {
        setup_logger();
        let program = simple_memory_program();
        let stdin = SP1Stdin::new();
        run_test::<CpuProver<_, _>>(program, stdin).unwrap();
    }

    #[test]
    fn test_ssz_withdrawal() {
        setup_logger();
        let program = ssz_withdrawals_program();
        let stdin = SP1Stdin::new();
        run_test::<CpuProver<_, _>>(program, stdin).unwrap();
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
        assert_eq!(pk.local_only, deserialized_pk.local_only);

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
