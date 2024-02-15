use std::marker::PhantomData;

use crate::air::MachineAir;
pub use crate::air::SP1AirBuilder;
use crate::memory::MemoryChipKind;
use crate::runtime::ExecutionRecord;
use p3_air::Air;
use p3_air::BaseAir;
use p3_field::PrimeField32;

pub use riscv_chips::*;

pub(crate) mod riscv_chips {
    pub use crate::alu::AddChip;
    pub use crate::alu::BitwiseChip;
    pub use crate::alu::DivRemChip;
    pub use crate::alu::LtChip;
    pub use crate::alu::MulChip;
    pub use crate::alu::ShiftLeft;
    pub use crate::alu::ShiftRightChip;
    pub use crate::alu::SubChip;
    pub use crate::bytes::ByteChip;
    pub use crate::cpu::CpuChip;
    pub use crate::field::FieldLTUChip;
    pub use crate::memory::MemoryGlobalChip;
    pub use crate::program::ProgramChip;
    pub use crate::syscall::precompiles::blake3::Blake3CompressInnerChip;
    pub use crate::syscall::precompiles::edwards::EdAddAssignChip;
    pub use crate::syscall::precompiles::edwards::EdDecompressChip;
    pub use crate::syscall::precompiles::k256::K256DecompressChip;
    pub use crate::syscall::precompiles::keccak256::KeccakPermuteChip;
    pub use crate::syscall::precompiles::sha256::ShaCompressChip;
    pub use crate::syscall::precompiles::sha256::ShaExtendChip;
    pub use crate::syscall::precompiles::weierstrass::WeierstrassAddAssignChip;
    pub use crate::syscall::precompiles::weierstrass::WeierstrassDoubleAssignChip;
    pub use crate::utils::ec::edwards::ed25519::Ed25519Parameters;
    pub use crate::utils::ec::edwards::EdwardsCurve;
    pub use crate::utils::ec::weierstrass::secp256k1::Secp256k1Parameters;
    pub use crate::utils::ec::weierstrass::SWCurve;
}

pub enum RiscvAir<F> {
    /// An AIR that containts a preprocessed program table and a lookup for the instructions.
    Program(ProgramChip),
    /// An AIR for the RISC-V CPU. Each row represents a cpu cycle.
    Cpu(CpuChip),
    /// An AIR for the RISC-V Add instruction.
    Add(AddChip),
    /// An AIR for the RISC-V Sub instruction.
    Sub(SubChip),
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
    ByteLookup(ByteChip),
    /// An table for `less than` operation on field elements.
    FieldLTU(FieldLTUChip),
    /// A table for initializing the memory state.
    MemoryInit(MemoryGlobalChip),
    /// A table for finalizing the memory state.
    MemoryFinal(MemoryGlobalChip),
    /// A table for initializing the program memory.
    ProgramMemory(MemoryGlobalChip),

    ShaExtend(ShaExtendChip),
    ShaCompress(ShaCompressChip),
    Ed25519Add(EdAddAssignChip<EdwardsCurve<Ed25519Parameters>>),
    Ed25519Decompress(EdDecompressChip<Ed25519Parameters>),

    K256Decompress(K256DecompressChip),

    Secp256k1Add(WeierstrassAddAssignChip<SWCurve<Secp256k1Parameters>>),
    Secp256k1Double(WeierstrassDoubleAssignChip<SWCurve<Secp256k1Parameters>>),

    KeccakP(KeccakPermuteChip),

    Blake3Compress(Blake3CompressInnerChip),

    _Unreachable(PhantomData<F>),
}

impl<F: PrimeField32> RiscvAir<F> {
    pub fn included(&self, shard: &ExecutionRecord) -> bool {
        match self {
            RiscvAir::Program(_) => true,
            RiscvAir::Cpu(_) => true,
            RiscvAir::Add(_) => !shard.add_events.is_empty(),
            RiscvAir::Sub(_) => !shard.sub_events.is_empty(),
            RiscvAir::Bitwise(_) => !shard.bitwise_events.is_empty(),
            RiscvAir::Mul(_) => !shard.mul_events.is_empty(),
            RiscvAir::DivRem(_) => !shard.divrem_events.is_empty(),
            RiscvAir::Lt(_) => !shard.lt_events.is_empty(),
            RiscvAir::ShiftLeft(_) => !shard.shift_left_events.is_empty(),
            RiscvAir::ShiftRight(_) => !shard.shift_right_events.is_empty(),
            RiscvAir::ByteLookup(_) => !shard.byte_lookups.is_empty(),
            RiscvAir::FieldLTU(_) => !shard.field_events.is_empty(),
            RiscvAir::MemoryInit(_) => !shard.first_memory_record.is_empty(),
            RiscvAir::MemoryFinal(_) => !shard.last_memory_record.is_empty(),
            RiscvAir::ProgramMemory(_) => !shard.program_memory_record.is_empty(),
            RiscvAir::ShaExtend(_) => !shard.sha_extend_events.is_empty(),
            RiscvAir::ShaCompress(_) => !shard.sha_compress_events.is_empty(),
            RiscvAir::Ed25519Add(_) => !shard.ed_add_events.is_empty(),
            RiscvAir::Ed25519Decompress(_) => !shard.ed_decompress_events.is_empty(),
            RiscvAir::K256Decompress(_) => !shard.k256_decompress_events.is_empty(),
            RiscvAir::Secp256k1Add(_) => !shard.weierstrass_add_events.is_empty(),
            RiscvAir::Secp256k1Double(_) => !shard.weierstrass_double_events.is_empty(),
            RiscvAir::KeccakP(_) => !shard.keccak_permute_events.is_empty(),
            RiscvAir::Blake3Compress(_) => !shard.blake3_compress_inner_events.is_empty(),
            RiscvAir::_Unreachable(_) => unreachable!("Unreachable"),
        }
    }

    pub fn get_all() -> Vec<Self> {
        let mut chips = vec![];
        let program = ProgramChip::default();
        chips.push(RiscvAir::Program(program));
        let cpu = CpuChip::default();
        chips.push(RiscvAir::Cpu(cpu));
        let sha_extend = ShaExtendChip::default();
        chips.push(RiscvAir::ShaExtend(sha_extend));
        let sha_compress = ShaCompressChip::default();
        chips.push(RiscvAir::ShaCompress(sha_compress));
        let ed_add_assign = EdAddAssignChip::<EdwardsCurve<Ed25519Parameters>>::new();
        chips.push(RiscvAir::Ed25519Add(ed_add_assign));
        let ed_decompress = EdDecompressChip::<Ed25519Parameters>::default();
        chips.push(RiscvAir::Ed25519Decompress(ed_decompress));
        let k256_decompress = K256DecompressChip::default();
        chips.push(RiscvAir::K256Decompress(k256_decompress));
        let weierstrass_add_assign =
            WeierstrassAddAssignChip::<SWCurve<Secp256k1Parameters>>::new();
        chips.push(RiscvAir::Secp256k1Add(weierstrass_add_assign));
        let weierstrass_double_assign =
            WeierstrassDoubleAssignChip::<SWCurve<Secp256k1Parameters>>::new();
        chips.push(RiscvAir::Secp256k1Double(weierstrass_double_assign));
        let keccak_permute = KeccakPermuteChip::new();
        chips.push(RiscvAir::KeccakP(keccak_permute));
        let blake3_compress_inner = Blake3CompressInnerChip::new();
        chips.push(RiscvAir::Blake3Compress(blake3_compress_inner));
        let add = AddChip::default();
        chips.push(RiscvAir::Add(add));
        let sub = SubChip::default();
        chips.push(RiscvAir::Sub(sub));
        let bitwise = BitwiseChip::default();
        chips.push(RiscvAir::Bitwise(bitwise));
        let div_rem = DivRemChip::default();
        chips.push(RiscvAir::DivRem(div_rem));
        let mul = MulChip::default();
        chips.push(RiscvAir::Mul(mul));
        let shift_right = ShiftRightChip::default();
        chips.push(RiscvAir::ShiftRight(shift_right));
        let shift_left = ShiftLeft::default();
        chips.push(RiscvAir::ShiftLeft(shift_left));
        let lt = LtChip::default();
        chips.push(RiscvAir::Lt(lt));
        let field_ltu = FieldLTUChip::default();
        chips.push(RiscvAir::FieldLTU(field_ltu));
        let byte = ByteChip::default();
        chips.push(RiscvAir::ByteLookup(byte));
        let memory_init = MemoryGlobalChip::new(MemoryChipKind::Init);
        chips.push(RiscvAir::MemoryInit(memory_init));
        let memory_finalize = MemoryGlobalChip::new(MemoryChipKind::Finalize);
        chips.push(RiscvAir::MemoryFinal(memory_finalize));
        let program_memory_init = MemoryGlobalChip::new(MemoryChipKind::Program);
        chips.push(RiscvAir::ProgramMemory(program_memory_init));

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

impl<F: PrimeField32> BaseAir<F> for RiscvAir<F> {
    fn width(&self) -> usize {
        match self {
            RiscvAir::Program(p) => BaseAir::<F>::width(p),
            RiscvAir::Cpu(c) => BaseAir::<F>::width(c),
            RiscvAir::Add(a) => BaseAir::<F>::width(a),
            RiscvAir::Sub(s) => BaseAir::<F>::width(s),
            RiscvAir::Bitwise(b) => BaseAir::<F>::width(b),
            RiscvAir::Mul(m) => BaseAir::<F>::width(m),
            RiscvAir::DivRem(d) => BaseAir::<F>::width(d),
            RiscvAir::Lt(l) => BaseAir::<F>::width(l),
            RiscvAir::ShiftLeft(sl) => BaseAir::<F>::width(sl),
            RiscvAir::ShiftRight(sr) => BaseAir::<F>::width(sr),
            RiscvAir::ByteLookup(b) => BaseAir::<F>::width(b),
            RiscvAir::FieldLTU(f) => BaseAir::<F>::width(f),
            RiscvAir::MemoryInit(m) => BaseAir::<F>::width(m),
            RiscvAir::MemoryFinal(m) => BaseAir::<F>::width(m),
            RiscvAir::ProgramMemory(m) => BaseAir::<F>::width(m),
            RiscvAir::ShaExtend(s) => BaseAir::<F>::width(s),
            RiscvAir::ShaCompress(s) => BaseAir::<F>::width(s),
            RiscvAir::Ed25519Add(a) => BaseAir::<F>::width(a),
            RiscvAir::Ed25519Decompress(d) => BaseAir::<F>::width(d),
            RiscvAir::K256Decompress(d) => BaseAir::<F>::width(d),
            RiscvAir::Secp256k1Add(a) => BaseAir::<F>::width(a),
            RiscvAir::Secp256k1Double(d) => BaseAir::<F>::width(d),
            RiscvAir::KeccakP(p) => BaseAir::<F>::width(p),
            RiscvAir::Blake3Compress(c) => BaseAir::<F>::width(c),
            RiscvAir::_Unreachable(_) => unreachable!("Unreachable"),
        }
    }

    fn preprocessed_trace(&self) -> Option<p3_matrix::dense::RowMajorMatrix<F>> {
        match self {
            RiscvAir::Program(p) => p.preprocessed_trace(),
            RiscvAir::Cpu(c) => c.preprocessed_trace(),
            RiscvAir::Add(a) => a.preprocessed_trace(),
            RiscvAir::Sub(s) => s.preprocessed_trace(),
            RiscvAir::Bitwise(b) => b.preprocessed_trace(),
            RiscvAir::Mul(m) => m.preprocessed_trace(),
            RiscvAir::DivRem(d) => d.preprocessed_trace(),
            RiscvAir::Lt(l) => l.preprocessed_trace(),
            RiscvAir::ShiftLeft(sl) => sl.preprocessed_trace(),
            RiscvAir::ShiftRight(sr) => sr.preprocessed_trace(),
            RiscvAir::ByteLookup(b) => b.preprocessed_trace(),
            RiscvAir::FieldLTU(f) => f.preprocessed_trace(),
            RiscvAir::MemoryInit(m) => m.preprocessed_trace(),
            RiscvAir::MemoryFinal(m) => m.preprocessed_trace(),
            RiscvAir::ProgramMemory(m) => m.preprocessed_trace(),
            RiscvAir::ShaExtend(s) => s.preprocessed_trace(),
            RiscvAir::ShaCompress(s) => s.preprocessed_trace(),
            RiscvAir::Ed25519Add(a) => a.preprocessed_trace(),
            RiscvAir::Ed25519Decompress(d) => d.preprocessed_trace(),
            RiscvAir::K256Decompress(d) => d.preprocessed_trace(),
            RiscvAir::Secp256k1Add(a) => a.preprocessed_trace(),
            RiscvAir::Secp256k1Double(d) => d.preprocessed_trace(),
            RiscvAir::KeccakP(p) => p.preprocessed_trace(),
            RiscvAir::Blake3Compress(c) => c.preprocessed_trace(),
            RiscvAir::_Unreachable(_) => unreachable!("Unreachable"),
        }
    }
}

impl<F: PrimeField32> MachineAir<F> for RiscvAir<F> {
    fn name(&self) -> String {
        match self {
            RiscvAir::Program(p) => MachineAir::<F>::name(p),
            RiscvAir::Cpu(c) => MachineAir::<F>::name(c),
            RiscvAir::Add(a) => MachineAir::<F>::name(a),
            RiscvAir::Sub(s) => MachineAir::<F>::name(s),
            RiscvAir::Bitwise(b) => MachineAir::<F>::name(b),
            RiscvAir::Mul(m) => MachineAir::<F>::name(m),
            RiscvAir::DivRem(d) => MachineAir::<F>::name(d),
            RiscvAir::Lt(l) => MachineAir::<F>::name(l),
            RiscvAir::ShiftLeft(sl) => MachineAir::<F>::name(sl),
            RiscvAir::ShiftRight(sr) => MachineAir::<F>::name(sr),
            RiscvAir::ByteLookup(b) => MachineAir::<F>::name(b),
            RiscvAir::FieldLTU(f) => MachineAir::<F>::name(f),
            RiscvAir::MemoryInit(m) => MachineAir::<F>::name(m),
            RiscvAir::MemoryFinal(m) => MachineAir::<F>::name(m),
            RiscvAir::ProgramMemory(m) => MachineAir::<F>::name(m),
            RiscvAir::ShaExtend(s) => MachineAir::<F>::name(s),
            RiscvAir::ShaCompress(s) => MachineAir::<F>::name(s),
            RiscvAir::Ed25519Add(a) => MachineAir::<F>::name(a),
            RiscvAir::Ed25519Decompress(d) => MachineAir::<F>::name(d),
            RiscvAir::K256Decompress(d) => MachineAir::<F>::name(d),
            RiscvAir::Secp256k1Add(a) => MachineAir::<F>::name(a),
            RiscvAir::Secp256k1Double(d) => MachineAir::<F>::name(d),
            RiscvAir::KeccakP(p) => MachineAir::<F>::name(p),
            RiscvAir::Blake3Compress(c) => MachineAir::<F>::name(c),
            RiscvAir::_Unreachable(_) => unreachable!("Unreachable"),
        }
    }

    fn generate_trace(
        &self,
        input: &crate::runtime::ExecutionRecord,
        output: &mut crate::runtime::ExecutionRecord,
    ) -> p3_matrix::dense::RowMajorMatrix<F> {
        match self {
            RiscvAir::Program(p) => p.generate_trace(input, output),
            RiscvAir::Cpu(c) => c.generate_trace(input, output),
            RiscvAir::Add(a) => a.generate_trace(input, output),
            RiscvAir::Sub(s) => s.generate_trace(input, output),
            RiscvAir::Bitwise(b) => b.generate_trace(input, output),
            RiscvAir::Mul(m) => m.generate_trace(input, output),
            RiscvAir::DivRem(d) => d.generate_trace(input, output),
            RiscvAir::Lt(l) => l.generate_trace(input, output),
            RiscvAir::ShiftLeft(sl) => sl.generate_trace(input, output),
            RiscvAir::ShiftRight(sr) => sr.generate_trace(input, output),
            RiscvAir::ByteLookup(b) => b.generate_trace(input, output),
            RiscvAir::FieldLTU(f) => f.generate_trace(input, output),
            RiscvAir::MemoryInit(m) => m.generate_trace(input, output),
            RiscvAir::MemoryFinal(m) => m.generate_trace(input, output),
            RiscvAir::ProgramMemory(m) => m.generate_trace(input, output),
            RiscvAir::ShaExtend(s) => s.generate_trace(input, output),
            RiscvAir::ShaCompress(s) => s.generate_trace(input, output),
            RiscvAir::Ed25519Add(a) => a.generate_trace(input, output),
            RiscvAir::Ed25519Decompress(d) => d.generate_trace(input, output),
            RiscvAir::K256Decompress(d) => d.generate_trace(input, output),
            RiscvAir::Secp256k1Add(a) => a.generate_trace(input, output),
            RiscvAir::Secp256k1Double(d) => d.generate_trace(input, output),
            RiscvAir::KeccakP(p) => p.generate_trace(input, output),
            RiscvAir::Blake3Compress(c) => c.generate_trace(input, output),
            RiscvAir::_Unreachable(_) => unreachable!("Unreachable"),
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            RiscvAir::Program(p) => MachineAir::<F>::preprocessed_width(p),
            RiscvAir::Cpu(c) => MachineAir::<F>::preprocessed_width(c),
            RiscvAir::Add(a) => MachineAir::<F>::preprocessed_width(a),
            RiscvAir::Sub(s) => MachineAir::<F>::preprocessed_width(s),
            RiscvAir::Bitwise(b) => MachineAir::<F>::preprocessed_width(b),
            RiscvAir::Mul(m) => MachineAir::<F>::preprocessed_width(m),
            RiscvAir::DivRem(d) => MachineAir::<F>::preprocessed_width(d),
            RiscvAir::Lt(l) => MachineAir::<F>::preprocessed_width(l),
            RiscvAir::ShiftLeft(sl) => MachineAir::<F>::preprocessed_width(sl),
            RiscvAir::ShiftRight(sr) => MachineAir::<F>::preprocessed_width(sr),
            RiscvAir::ByteLookup(b) => MachineAir::<F>::preprocessed_width(b),
            RiscvAir::FieldLTU(f) => MachineAir::<F>::preprocessed_width(f),
            RiscvAir::MemoryInit(m) => MachineAir::<F>::preprocessed_width(m),
            RiscvAir::MemoryFinal(m) => MachineAir::<F>::preprocessed_width(m),
            RiscvAir::ProgramMemory(m) => MachineAir::<F>::preprocessed_width(m),
            RiscvAir::ShaExtend(s) => MachineAir::<F>::preprocessed_width(s),
            RiscvAir::ShaCompress(s) => MachineAir::<F>::preprocessed_width(s),
            RiscvAir::Ed25519Add(a) => MachineAir::<F>::preprocessed_width(a),
            RiscvAir::Ed25519Decompress(d) => MachineAir::<F>::preprocessed_width(d),
            RiscvAir::K256Decompress(d) => MachineAir::<F>::preprocessed_width(d),
            RiscvAir::Secp256k1Add(a) => MachineAir::<F>::preprocessed_width(a),
            RiscvAir::Secp256k1Double(d) => MachineAir::<F>::preprocessed_width(d),
            RiscvAir::KeccakP(p) => MachineAir::<F>::preprocessed_width(p),
            RiscvAir::Blake3Compress(c) => MachineAir::<F>::preprocessed_width(c),
            RiscvAir::_Unreachable(_) => unreachable!("Unreachable"),
        }
    }

    fn generate_preprocessed_trace(
        &self,
        program: &crate::runtime::Program,
    ) -> Option<p3_matrix::dense::RowMajorMatrix<F>> {
        match self {
            RiscvAir::Program(p) => p.generate_preprocessed_trace(program),
            RiscvAir::Cpu(c) => c.generate_preprocessed_trace(program),
            RiscvAir::Add(a) => a.generate_preprocessed_trace(program),
            RiscvAir::Sub(s) => s.generate_preprocessed_trace(program),
            RiscvAir::Bitwise(b) => b.generate_preprocessed_trace(program),
            RiscvAir::Mul(m) => m.generate_preprocessed_trace(program),
            RiscvAir::DivRem(d) => d.generate_preprocessed_trace(program),
            RiscvAir::Lt(l) => l.generate_preprocessed_trace(program),
            RiscvAir::ShiftLeft(sl) => sl.generate_preprocessed_trace(program),
            RiscvAir::ShiftRight(sr) => sr.generate_preprocessed_trace(program),
            RiscvAir::ByteLookup(b) => b.generate_preprocessed_trace(program),
            RiscvAir::FieldLTU(f) => f.generate_preprocessed_trace(program),
            RiscvAir::MemoryInit(m) => m.generate_preprocessed_trace(program),
            RiscvAir::MemoryFinal(m) => m.generate_preprocessed_trace(program),
            RiscvAir::ProgramMemory(m) => m.generate_preprocessed_trace(program),
            RiscvAir::ShaExtend(s) => s.generate_preprocessed_trace(program),
            RiscvAir::ShaCompress(s) => s.generate_preprocessed_trace(program),
            RiscvAir::Ed25519Add(a) => a.generate_preprocessed_trace(program),
            RiscvAir::Ed25519Decompress(d) => d.generate_preprocessed_trace(program),
            RiscvAir::K256Decompress(d) => d.generate_preprocessed_trace(program),
            RiscvAir::Secp256k1Add(a) => a.generate_preprocessed_trace(program),
            RiscvAir::Secp256k1Double(d) => d.generate_preprocessed_trace(program),
            RiscvAir::KeccakP(p) => p.generate_preprocessed_trace(program),
            RiscvAir::Blake3Compress(c) => c.generate_preprocessed_trace(program),
            RiscvAir::_Unreachable(_) => unreachable!("Unreachable"),
        }
    }
}

impl<AB: SP1AirBuilder> Air<AB> for RiscvAir<AB::F>
where
    AB::F: PrimeField32,
{
    fn eval(&self, builder: &mut AB) {
        match self {
            RiscvAir::Program(p) => p.eval(builder),
            RiscvAir::Cpu(c) => c.eval(builder),
            RiscvAir::Add(a) => a.eval(builder),
            RiscvAir::Sub(s) => s.eval(builder),
            RiscvAir::Bitwise(b) => b.eval(builder),
            RiscvAir::Mul(m) => m.eval(builder),
            RiscvAir::DivRem(d) => d.eval(builder),
            RiscvAir::Lt(l) => l.eval(builder),
            RiscvAir::ShiftLeft(sl) => sl.eval(builder),
            RiscvAir::ShiftRight(sr) => sr.eval(builder),
            RiscvAir::ByteLookup(b) => b.eval(builder),
            RiscvAir::FieldLTU(f) => f.eval(builder),
            RiscvAir::MemoryInit(m) => m.eval(builder),
            RiscvAir::MemoryFinal(m) => m.eval(builder),
            RiscvAir::ProgramMemory(m) => m.eval(builder),
            RiscvAir::ShaExtend(s) => s.eval(builder),
            RiscvAir::ShaCompress(s) => s.eval(builder),
            RiscvAir::Ed25519Add(a) => a.eval(builder),
            RiscvAir::Ed25519Decompress(d) => d.eval(builder),
            RiscvAir::K256Decompress(d) => d.eval(builder),
            RiscvAir::Secp256k1Add(a) => a.eval(builder),
            RiscvAir::Secp256k1Double(d) => d.eval(builder),
            RiscvAir::KeccakP(p) => p.eval(builder),
            RiscvAir::Blake3Compress(c) => c.eval(builder),
            RiscvAir::_Unreachable(_) => unreachable!("Unreachable"),
        }
    }
}
