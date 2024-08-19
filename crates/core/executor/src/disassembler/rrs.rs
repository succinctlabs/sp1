use rrs_lib::{
    instruction_formats::{BType, IType, ITypeCSR, ITypeShamt, JType, RType, SType, UType},
    process_instruction, InstructionProcessor,
};

use crate::{Instruction, Opcode, Register};

impl Instruction {
    /// Create a new [`Instruction`] from an R-type instruction.
    #[must_use]
    pub const fn from_r_type(opcode: Opcode, dec_insn: &RType) -> Self {
        Self::new(
            opcode,
            dec_insn.rd as u32,
            dec_insn.rs1 as u32,
            dec_insn.rs2 as u32,
            false,
            false,
        )
    }

    /// Create a new [`Instruction`] from an I-type instruction.
    #[must_use]
    pub const fn from_i_type(opcode: Opcode, dec_insn: &IType) -> Self {
        Self::new(opcode, dec_insn.rd as u32, dec_insn.rs1 as u32, dec_insn.imm as u32, false, true)
    }

    /// Create a new [`Instruction`] from an I-type instruction with a shamt.
    #[must_use]
    pub const fn from_i_type_shamt(opcode: Opcode, dec_insn: &ITypeShamt) -> Self {
        Self::new(opcode, dec_insn.rd as u32, dec_insn.rs1 as u32, dec_insn.shamt, false, true)
    }

    /// Create a new [`Instruction`] from an S-type instruction.
    #[must_use]
    pub const fn from_s_type(opcode: Opcode, dec_insn: &SType) -> Self {
        Self::new(
            opcode,
            dec_insn.rs2 as u32,
            dec_insn.rs1 as u32,
            dec_insn.imm as u32,
            false,
            true,
        )
    }

    /// Create a new [`Instruction`] from a B-type instruction.
    #[must_use]
    pub const fn from_b_type(opcode: Opcode, dec_insn: &BType) -> Self {
        Self::new(
            opcode,
            dec_insn.rs1 as u32,
            dec_insn.rs2 as u32,
            dec_insn.imm as u32,
            false,
            true,
        )
    }

    /// Create a new [`Instruction`] that is not implemented.
    #[must_use]
    pub const fn unimp() -> Self {
        Self::new(Opcode::UNIMP, 0, 0, 0, true, true)
    }

    /// Returns if the [`Instruction`] is an R-type instruction.
    #[inline]
    #[must_use]
    pub const fn is_r_type(&self) -> bool {
        !self.imm_c
    }

    /// Returns whether the [`Instruction`] is an I-type instruction.
    #[inline]
    #[must_use]
    pub const fn is_i_type(&self) -> bool {
        self.imm_c
    }

    /// Decode the [`Instruction`] in the R-type format.
    #[inline]
    #[must_use]
    pub fn r_type(&self) -> (Register, Register, Register) {
        (
            Register::from_u32(self.op_a),
            Register::from_u32(self.op_b),
            Register::from_u32(self.op_c),
        )
    }

    /// Decode the [`Instruction`] in the I-type format.
    #[inline]
    #[must_use]
    pub fn i_type(&self) -> (Register, Register, u32) {
        (Register::from_u32(self.op_a), Register::from_u32(self.op_b), self.op_c)
    }

    /// Decode the [`Instruction`] in the S-type format.
    #[inline]
    #[must_use]
    pub fn s_type(&self) -> (Register, Register, u32) {
        (Register::from_u32(self.op_a), Register::from_u32(self.op_b), self.op_c)
    }

    /// Decode the [`Instruction`] in the B-type format.
    #[inline]
    #[must_use]
    pub fn b_type(&self) -> (Register, Register, u32) {
        (Register::from_u32(self.op_a), Register::from_u32(self.op_b), self.op_c)
    }

    /// Decode the [`Instruction`] in the J-type format.
    #[inline]
    #[must_use]
    pub fn j_type(&self) -> (Register, u32) {
        (Register::from_u32(self.op_a), self.op_b)
    }

    /// Decode the [`Instruction`] in the U-type format.
    #[inline]
    #[must_use]
    pub fn u_type(&self) -> (Register, u32) {
        (Register::from_u32(self.op_a), self.op_b)
    }
}

/// A transpiler that converts the 32-bit encoded instructions into instructions.
pub(crate) struct InstructionTranspiler;

impl InstructionProcessor for InstructionTranspiler {
    type InstructionResult = Instruction;

    fn process_add(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::ADD, &dec_insn)
    }

    fn process_addi(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::ADD, &dec_insn)
    }

    fn process_sub(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::SUB, &dec_insn)
    }

    fn process_xor(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::XOR, &dec_insn)
    }

    fn process_xori(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::XOR, &dec_insn)
    }

    fn process_or(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::OR, &dec_insn)
    }

    fn process_ori(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::OR, &dec_insn)
    }

    fn process_and(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::AND, &dec_insn)
    }

    fn process_andi(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::AND, &dec_insn)
    }

    fn process_sll(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::SLL, &dec_insn)
    }

    fn process_slli(&mut self, dec_insn: ITypeShamt) -> Self::InstructionResult {
        Instruction::from_i_type_shamt(Opcode::SLL, &dec_insn)
    }

    fn process_srl(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::SRL, &dec_insn)
    }

    fn process_srli(&mut self, dec_insn: ITypeShamt) -> Self::InstructionResult {
        Instruction::from_i_type_shamt(Opcode::SRL, &dec_insn)
    }

    fn process_sra(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::SRA, &dec_insn)
    }

    fn process_srai(&mut self, dec_insn: ITypeShamt) -> Self::InstructionResult {
        Instruction::from_i_type_shamt(Opcode::SRA, &dec_insn)
    }

    fn process_slt(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::SLT, &dec_insn)
    }

    fn process_slti(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::SLT, &dec_insn)
    }

    fn process_sltu(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::SLTU, &dec_insn)
    }

    fn process_sltui(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::SLTU, &dec_insn)
    }

    fn process_lb(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::LB, &dec_insn)
    }

    fn process_lh(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::LH, &dec_insn)
    }

    fn process_lw(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::LW, &dec_insn)
    }

    fn process_lbu(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::LBU, &dec_insn)
    }

    fn process_lhu(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::LHU, &dec_insn)
    }

    fn process_sb(&mut self, dec_insn: SType) -> Self::InstructionResult {
        Instruction::from_s_type(Opcode::SB, &dec_insn)
    }

    fn process_sh(&mut self, dec_insn: SType) -> Self::InstructionResult {
        Instruction::from_s_type(Opcode::SH, &dec_insn)
    }

    fn process_sw(&mut self, dec_insn: SType) -> Self::InstructionResult {
        Instruction::from_s_type(Opcode::SW, &dec_insn)
    }

    fn process_beq(&mut self, dec_insn: BType) -> Self::InstructionResult {
        Instruction::from_b_type(Opcode::BEQ, &dec_insn)
    }

    fn process_bne(&mut self, dec_insn: BType) -> Self::InstructionResult {
        Instruction::from_b_type(Opcode::BNE, &dec_insn)
    }

    fn process_blt(&mut self, dec_insn: BType) -> Self::InstructionResult {
        Instruction::from_b_type(Opcode::BLT, &dec_insn)
    }

    fn process_bge(&mut self, dec_insn: BType) -> Self::InstructionResult {
        Instruction::from_b_type(Opcode::BGE, &dec_insn)
    }

    fn process_bltu(&mut self, dec_insn: BType) -> Self::InstructionResult {
        Instruction::from_b_type(Opcode::BLTU, &dec_insn)
    }

    fn process_bgeu(&mut self, dec_insn: BType) -> Self::InstructionResult {
        Instruction::from_b_type(Opcode::BGEU, &dec_insn)
    }

    fn process_jal(&mut self, dec_insn: JType) -> Self::InstructionResult {
        Instruction::new(Opcode::JAL, dec_insn.rd as u32, dec_insn.imm as u32, 0, true, true)
    }

    fn process_jalr(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::new(
            Opcode::JALR,
            dec_insn.rd as u32,
            dec_insn.rs1 as u32,
            dec_insn.imm as u32,
            false,
            true,
        )
    }

    fn process_lui(&mut self, dec_insn: UType) -> Self::InstructionResult {
        // LUI instructions are handled in a special way inside the zkVM.
        //
        // Notably, LUI instructions are converted to an SLL instruction with `imm_b` and `imm_c`
        // turned on. Additionally the `op_c` should be set to 12.
        Instruction::new(Opcode::ADD, dec_insn.rd as u32, 0, dec_insn.imm as u32, true, true)
    }

    /// AUIPC instructions have the third operand set to imm << 12.
    fn process_auipc(&mut self, dec_insn: UType) -> Self::InstructionResult {
        Instruction::new(
            Opcode::AUIPC,
            dec_insn.rd as u32,
            dec_insn.imm as u32,
            dec_insn.imm as u32,
            true,
            true,
        )
    }

    fn process_ecall(&mut self) -> Self::InstructionResult {
        Instruction::new(
            Opcode::ECALL,
            Register::X5 as u32,
            Register::X10 as u32,
            Register::X11 as u32,
            false,
            false,
        )
    }

    fn process_ebreak(&mut self) -> Self::InstructionResult {
        Instruction::new(Opcode::EBREAK, 0, 0, 0, false, false)
    }

    fn process_mul(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::MUL, &dec_insn)
    }

    fn process_mulh(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::MULH, &dec_insn)
    }

    fn process_mulhu(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::MULHU, &dec_insn)
    }

    fn process_mulhsu(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::MULHSU, &dec_insn)
    }

    fn process_div(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::DIV, &dec_insn)
    }

    fn process_divu(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::DIVU, &dec_insn)
    }

    fn process_rem(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::REM, &dec_insn)
    }

    fn process_remu(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::REMU, &dec_insn)
    }

    fn process_csrrc(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::unimp()
    }

    fn process_csrrci(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::unimp()
    }

    fn process_csrrs(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::unimp()
    }

    fn process_csrrsi(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::unimp()
    }

    fn process_csrrw(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::unimp()
    }

    fn process_csrrwi(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::unimp()
    }

    fn process_fence(&mut self, _: IType) -> Self::InstructionResult {
        Instruction::unimp()
    }

    fn process_mret(&mut self) -> Self::InstructionResult {
        Instruction::unimp()
    }

    fn process_wfi(&mut self) -> Self::InstructionResult {
        Instruction::unimp()
    }
}

/// Transpile the [`Instruction`]s from the 32-bit encoded instructions.
///
/// # Panics
///
/// This function will return an error if the [`Instruction`] cannot be processed.
#[must_use]
pub(crate) fn transpile(instructions_u32: &[u32]) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    let mut transpiler = InstructionTranspiler;
    for instruction_u32 in instructions_u32 {
        let instruction = process_instruction(&mut transpiler, *instruction_u32).unwrap();
        instructions.push(instruction);
    }
    instructions
}
