use crate::air::MachineAir;
pub use crate::air::SP1AirBuilder;
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

pub enum RiscvAir {
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
}

impl<F: PrimeField32> BaseAir<F> for RiscvAir {
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
        }
    }
}

impl<F: PrimeField32> MachineAir<F> for RiscvAir {
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
        }
    }
}

impl<AB: SP1AirBuilder> Air<AB> for RiscvAir
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
        }
    }
}
