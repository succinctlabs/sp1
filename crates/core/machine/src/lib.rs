#![allow(
    clippy::new_without_default,
    clippy::field_reassign_with_default,
    clippy::unnecessary_cast,
    clippy::cast_abs_to_unsigned,
    clippy::needless_range_loop,
    clippy::type_complexity,
    clippy::unnecessary_unwrap,
    clippy::default_constructed_unit_structs,
    clippy::box_default,
    clippy::assign_op_pattern,
    deprecated,
    incomplete_features
)]
#![warn(unused_extern_crates)]
#[macro_use]
extern crate static_assertions;

pub mod adapter;
pub mod air;
pub mod alu;
pub mod bytes;
pub mod control_flow;
pub mod executor;
pub mod global;
pub mod io;
pub mod memory;
pub mod operations;
pub mod program;
pub mod range;
pub mod riscv;
pub mod syscall;
pub mod utils;
pub mod utype;

use air::SP1CoreAirBuilder;
use memory::MemoryAccessCols;
use operations::{AddressSlicePageProtOperation, IsZeroOperation, TrapOperation};
use program::instruction::InstructionCols;
use slop_air::AirBuilder;
use slop_algebra::AbstractField;
pub use sp1_core_executor::{SupervisorMode, UserMode};
use sp1_derive::AlignedBorrow;
use std::{fmt::Debug, marker::PhantomData};
use struct_reflection::{StructReflection, StructReflectionHelper};

pub trait TrustMode: Send + Sync + 'static {
    const IS_TRUSTED: bool;
    type AdapterCols<T>: StructReflectionHelper;
    type SyscallInstrCols<T>: StructReflectionHelper;
    type SliceProtCols<T>: StructReflectionHelper;
    type AluX0SelectorCols<T>: StructReflectionHelper;
    type TrapCodeCols<T>: StructReflectionHelper;
}

#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
/// Strcut that represents an empty set of columns for a given type `T`.
///
/// The struct existis to facilitate the implementation traits needed for columns.
pub struct EmptyCols<T>(PhantomData<T>);

impl<T> StructReflection for EmptyCols<T> {
    fn struct_reflection() -> Option<Vec<String>> {
        None
    }
}

impl TrustMode for SupervisorMode {
    const IS_TRUSTED: bool = true;
    type AdapterCols<T> = EmptyCols<T>;
    type SyscallInstrCols<T> = EmptyCols<T>;
    type SliceProtCols<T> = EmptyCols<T>;
    type AluX0SelectorCols<T> = EmptyCols<T>;
    type TrapCodeCols<T> = EmptyCols<T>;
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy, StructReflection)]
#[repr(C)]
pub struct UserModeReaderCols<T> {
    pub is_trusted: T,
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy, StructReflection)]
#[repr(C)]
pub struct UserModeSyscallInstrCols<T> {
    pub is_sig_return: IsZeroOperation<T>,
    pub next_pc_record: MemoryAccessCols<T>,
    pub trap_operation: TrapOperation<T>,
    pub is_not_trap: IsZeroOperation<T>,
    pub is_page_protect: IsZeroOperation<T>,
    pub trap_code: T,
    pub addresses: [[T; 3]; 3],
}

/// Selector columns for the AluX0 chip in User mode.
///
/// Each field is a boolean selector for one ALU opcode. Exactly one must be set per real row.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy, StructReflection)]
#[repr(C)]
pub struct AluX0OpcodeSelectors<T> {
    pub instr_type: T,
    pub base_opcode: T,
    pub funct3: T,
    pub funct7: T,
    pub is_add: T,
    pub is_sub: T,
    pub is_mul: T,
    pub is_mulh: T,
    pub is_mulhsu: T,
    pub is_mulhu: T,
    pub is_div: T,
    pub is_divu: T,
    pub is_rem: T,
    pub is_remu: T,
    pub is_sll: T,
    pub is_srl: T,
    pub is_sra: T,
    pub is_xor: T,
    pub is_or: T,
    pub is_and: T,
    pub is_slt: T,
    pub is_sltu: T,
    pub is_addi: T,
    pub is_addw: T,
    pub is_subw: T,
    pub is_sllw: T,
    pub is_srlw: T,
    pub is_sraw: T,
    pub is_mulw: T,
    pub is_divw: T,
    pub is_divuw: T,
    pub is_remw: T,
    pub is_remuw: T,
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy, StructReflection)]
#[repr(C)]
pub struct UserModeTrapCodeCols<T> {
    pub trap_code: T,
}

impl TrustMode for UserMode {
    const IS_TRUSTED: bool = false;
    type AdapterCols<T> = UserModeReaderCols<T>;
    type SyscallInstrCols<T> = UserModeSyscallInstrCols<T>;
    type SliceProtCols<T> = AddressSlicePageProtOperation<T>;
    type AluX0SelectorCols<T> = AluX0OpcodeSelectors<T>;
    type TrapCodeCols<T> = UserModeTrapCodeCols<T>;
}

fn eval_untrusted_program<AB: SP1CoreAirBuilder>(
    builder: &mut AB,
    pc: [impl Into<AB::Expr>; 3],
    instruction: InstructionCols<AB::Expr>,
    instruction_field_consts: [AB::Expr; 4],
    clk: [AB::Expr; 2],
    is_real: AB::Expr,
    adapter_cols: UserModeReaderCols<AB::Var>,
) {
    builder.send_instruction_fetch(
        pc,
        instruction,
        instruction_field_consts,
        clk,
        is_real.clone() - adapter_cols.is_trusted,
    );

    let is_untrusted = is_real.clone() - adapter_cols.is_trusted;
    builder.assert_bool(adapter_cols.is_trusted);
    builder.assert_bool(is_untrusted.clone());

    // If the row is running an untrusted program, the page protection checks must be on.
    let public_values = builder.extract_public_values();
    builder.when(is_untrusted.clone()).assert_one(public_values.is_untrusted_programs_enabled);
}

/// Evaluate AluX0 opcode selectors for User mode.
///
/// Asserts all selectors are boolean, returns `[instr_type, base_opcode, funct3, funct7]`
/// computed as linear combinations of selectors and constants.
///
/// The `imm_c` flag (from ALUTypeReader) determines whether the register or immediate
/// form of the instruction encoding is used.
fn eval_alu_x0_selectors<AB: SP1CoreAirBuilder>(
    builder: &mut AB,
    selectors: AluX0OpcodeSelectors<AB::Var>,
    imm_c: AB::Expr,
    is_real: AB::Expr,
) {
    use rrs_lib::instruction_formats::{OPCODE_OP, OPCODE_OP_32, OPCODE_OP_IMM, OPCODE_OP_IMM_32};
    use sp1_core_executor::InstructionType;

    // Assert all selectors are boolean.
    builder.assert_bool(selectors.is_add);
    builder.assert_bool(selectors.is_sub);
    builder.assert_bool(selectors.is_mul);
    builder.assert_bool(selectors.is_mulh);
    builder.assert_bool(selectors.is_mulhsu);
    builder.assert_bool(selectors.is_mulhu);
    builder.assert_bool(selectors.is_div);
    builder.assert_bool(selectors.is_divu);
    builder.assert_bool(selectors.is_rem);
    builder.assert_bool(selectors.is_remu);
    builder.assert_bool(selectors.is_sll);
    builder.assert_bool(selectors.is_srl);
    builder.assert_bool(selectors.is_sra);
    builder.assert_bool(selectors.is_xor);
    builder.assert_bool(selectors.is_or);
    builder.assert_bool(selectors.is_and);
    builder.assert_bool(selectors.is_slt);
    builder.assert_bool(selectors.is_sltu);
    builder.assert_bool(selectors.is_addi);
    builder.assert_bool(selectors.is_addw);
    builder.assert_bool(selectors.is_subw);
    builder.assert_bool(selectors.is_sllw);
    builder.assert_bool(selectors.is_srlw);
    builder.assert_bool(selectors.is_sraw);
    builder.assert_bool(selectors.is_mulw);
    builder.assert_bool(selectors.is_divw);
    builder.assert_bool(selectors.is_divuw);
    builder.assert_bool(selectors.is_remw);
    builder.assert_bool(selectors.is_remuw);

    // Assert exactly one selector is set when is_real.
    let selector_sum: AB::Expr = selectors.is_add
        + selectors.is_sub
        + selectors.is_mul
        + selectors.is_mulh
        + selectors.is_mulhsu
        + selectors.is_mulhu
        + selectors.is_div
        + selectors.is_divu
        + selectors.is_rem
        + selectors.is_remu
        + selectors.is_sll
        + selectors.is_srl
        + selectors.is_sra
        + selectors.is_xor
        + selectors.is_or
        + selectors.is_and
        + selectors.is_slt
        + selectors.is_sltu
        + selectors.is_addi
        + selectors.is_addw
        + selectors.is_subw
        + selectors.is_sllw
        + selectors.is_srlw
        + selectors.is_sraw
        + selectors.is_mulw
        + selectors.is_divw
        + selectors.is_divuw
        + selectors.is_remw
        + selectors.is_remuw;
    builder.assert_bool(selector_sum.clone());
    builder.when(is_real.clone()).assert_one(selector_sum.clone());
    builder.when_not(is_real.clone()).assert_zero(selector_sum.clone());

    // Helper: group selectors by their register-form base_opcode.
    // OPCODE_OP (0x33): ADD, SUB, MUL..REMU, SLL, SRL, SRA, XOR, OR, AND, SLT, SLTU
    let is_op: AB::Expr = selectors.is_add
        + selectors.is_sub
        + selectors.is_mul
        + selectors.is_mulh
        + selectors.is_mulhsu
        + selectors.is_mulhu
        + selectors.is_div
        + selectors.is_divu
        + selectors.is_rem
        + selectors.is_remu
        + selectors.is_sll
        + selectors.is_srl
        + selectors.is_sra
        + selectors.is_xor
        + selectors.is_or
        + selectors.is_and
        + selectors.is_slt
        + selectors.is_sltu;

    // OPCODE_OP_32 (0x3b): ADDW, SUBW, SLLW, SRLW, SRAW, MULW..REMUW
    let is_op_32: AB::Expr = selectors.is_addw
        + selectors.is_subw
        + selectors.is_sllw
        + selectors.is_srlw
        + selectors.is_sraw
        + selectors.is_mulw
        + selectors.is_divw
        + selectors.is_divuw
        + selectors.is_remw
        + selectors.is_remuw;

    // OPCODE_OP_IMM (0x13): ADDI, and imm variants of SLL..SLTU
    // OPCODE_OP_IMM_32 (0x1b): imm variants of ADDW, SLLW, SRLW, SRAW

    // Opcodes that have an immediate variant with OPCODE_OP_IMM:
    let has_imm_op_imm: AB::Expr = selectors.is_sll
        + selectors.is_srl
        + selectors.is_sra
        + selectors.is_xor
        + selectors.is_or
        + selectors.is_and
        + selectors.is_slt
        + selectors.is_sltu
        + selectors.is_addi;

    // Opcodes that have an immediate variant with OPCODE_OP_IMM_32:
    let has_imm_op_imm_32: AB::Expr =
        selectors.is_addw + selectors.is_sllw + selectors.is_srlw + selectors.is_sraw;

    // --- base_opcode ---
    // reg form: is_op * OPCODE_OP + is_op_32 * OPCODE_OP_32 + is_addi * OPCODE_OP_IMM
    // imm form: has_imm_op_imm * OPCODE_OP_IMM + has_imm_op_imm_32 * OPCODE_OP_IMM_32
    let is_addi: AB::Expr = selectors.is_addi.into();
    let reg_base_opcode: AB::Expr = is_op.clone() * AB::F::from_canonical_u32(OPCODE_OP)
        + is_op_32.clone() * AB::F::from_canonical_u32(OPCODE_OP_32)
        + is_addi.clone() * AB::F::from_canonical_u32(OPCODE_OP_IMM);

    let imm_base_opcode: AB::Expr = has_imm_op_imm * AB::F::from_canonical_u32(OPCODE_OP_IMM)
        + has_imm_op_imm_32 * AB::F::from_canonical_u32(OPCODE_OP_IMM_32);

    let base_opcode: AB::Expr =
        (is_real.clone() - imm_c.clone()) * reg_base_opcode + imm_c.clone() * imm_base_opcode;

    // --- instr_type ---
    // reg form: RType for everything except ADDI (IType)
    // imm form: depends on opcode group
    let reg_instr_type: AB::Expr = (is_op + is_op_32)
        * AB::F::from_canonical_u32(InstructionType::RType as u32)
        + is_addi * AB::F::from_canonical_u32(InstructionType::IType as u32);

    // ITypeShamt imm: SLL, SRL, SRA
    let is_shamt: AB::Expr = selectors.is_sll + selectors.is_srl + selectors.is_sra;
    // ITypeShamt32 imm: SLLW, SRLW, SRAW
    let is_shamt32: AB::Expr = selectors.is_sllw + selectors.is_srlw + selectors.is_sraw;
    // IType imm: XOR, OR, AND, SLT, SLTU, ADDI, ADDW
    let is_itype_imm: AB::Expr = selectors.is_xor
        + selectors.is_or
        + selectors.is_and
        + selectors.is_slt
        + selectors.is_sltu
        + selectors.is_addi
        + selectors.is_addw;

    let imm_instr_type: AB::Expr = is_shamt
        * AB::F::from_canonical_u32(InstructionType::ITypeShamt as u32)
        + is_shamt32 * AB::F::from_canonical_u32(InstructionType::ITypeShamt32 as u32)
        + is_itype_imm * AB::F::from_canonical_u32(InstructionType::IType as u32);

    let instr_type: AB::Expr =
        (is_real.clone() - imm_c.clone()) * reg_instr_type + imm_c.clone() * imm_instr_type;

    // --- funct3 ---
    // Same for both reg and imm forms.
    // funct3 = 0b000: ADD, SUB, ADDI, MUL, ADDW, SUBW, MULW (contribute 0, omitted)
    let funct3: AB::Expr =
        // funct3 = 0b001: MULH, SLL, SLLW
        (selectors.is_mulh
            + selectors.is_sll
            + selectors.is_sllw)
            * AB::F::from_canonical_u32(0b001)
        // funct3 = 0b010: MULHSU, SLT
        + (selectors.is_mulhsu + selectors.is_slt)
            * AB::F::from_canonical_u32(0b010)
        // funct3 = 0b011: MULHU, SLTU
        + (selectors.is_mulhu + selectors.is_sltu)
            * AB::F::from_canonical_u32(0b011)
        // funct3 = 0b100: DIV, XOR, DIVW
        + (selectors.is_div
            + selectors.is_xor
            + selectors.is_divw)
            * AB::F::from_canonical_u32(0b100)
        // funct3 = 0b101: DIVU, SRL, SRA, DIVUW, SRLW, SRAW
        + (selectors.is_divu
            + selectors.is_srl
            + selectors.is_sra
            + selectors.is_divuw
            + selectors.is_srlw
            + selectors.is_sraw)
            * AB::F::from_canonical_u32(0b101)
        // funct3 = 0b110: REM, OR, REMW
        + (selectors.is_rem
            + selectors.is_or
            + selectors.is_remw)
            * AB::F::from_canonical_u32(0b110)
        // funct3 = 0b111: REMU, AND, REMUW
        + (selectors.is_remu
            + selectors.is_and
            + selectors.is_remuw)
            * AB::F::from_canonical_u32(0b111);

    // --- funct7 ---
    // Only present in register form.
    // funct7 = 0b0000000 (0): ADD, SLL, SRL, XOR, OR, AND, SLT, SLTU, ADDW, SLLW, SRLW
    //   (these contribute 0, so omitted)
    // funct7 = 0b0100000 (32): SUB, SRA, SUBW, SRAW
    // funct7 = 0b0000001 (1): MUL, MULH, MULHSU, MULHU, DIV, DIVU, REM, REMU,
    //                          MULW, DIVW, DIVUW, REMW, REMUW
    let funct7: AB::Expr =
        // funct7 = 32
        (selectors.is_sub
            + selectors.is_sra
            + selectors.is_subw
            + selectors.is_sraw)
            * AB::F::from_canonical_u32(0b0100000)
        // funct7 = 1
        + (selectors.is_mul
            + selectors.is_mulh
            + selectors.is_mulhsu
            + selectors.is_mulhu
            + selectors.is_div
            + selectors.is_divu
            + selectors.is_rem
            + selectors.is_remu
            + selectors.is_mulw
            + selectors.is_divw
            + selectors.is_divuw
            + selectors.is_remw
            + selectors.is_remuw)
            * AB::F::from_canonical_u32(0b0000001);

    builder.assert_eq(selectors.instr_type, instr_type);
    builder.assert_eq(selectors.base_opcode, base_opcode);
    builder.assert_eq(selectors.funct3, funct3);
    builder.assert_eq(selectors.funct7, funct7);
}

// Re-export the `SP1RecursionProof` struct from sp1_core_machine.
//
// This is done to avoid a circular dependency between sp1_core_machine and sp1_core_executor, and
// enable crates that depend on sp1_core_machine to import the `SP1RecursionProof` type directly.
pub mod recursion {
    pub use sp1_core_executor::SP1RecursionProof;
}

#[cfg(test)]
pub mod programs {
    #[allow(dead_code)]
    #[allow(missing_docs)]
    pub mod tests {
        use sp1_core_executor::{add_halt, Instruction, Opcode, Program};

        pub use test_artifacts::{
            FIBONACCI_ELF, KECCAK_PERMUTE_ELF, PANIC_ELF, SECP256R1_ADD_ELF, SECP256R1_DOUBLE_ELF,
            SSZ_WITHDRAWALS_ELF, U256XU2048_MUL_ELF,
        };

        #[must_use]
        pub fn simple_program() -> Program {
            let mut instructions = vec![
                Instruction::new(Opcode::ADDI, 29, 0, 5, false, true),
                Instruction::new(Opcode::ADDI, 30, 0, 37, false, true),
                Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
            ];
            add_halt(&mut instructions);
            Program::new(instructions, 0, 0)
        }

        /// Get the fibonacci program.
        ///
        /// # Panics
        ///
        /// This function will panic if the program fails to load.
        #[must_use]
        pub fn fibonacci_program() -> Program {
            Program::from(&FIBONACCI_ELF).unwrap()
        }

        /// Get the secp256r1 add program.
        ///
        /// # Panics
        ///
        /// This function will panic if the program fails to load.
        #[must_use]
        pub fn secp256r1_add_program() -> Program {
            Program::from(&SECP256R1_ADD_ELF).unwrap()
        }

        /// Get the secp256r1 double program.
        ///
        /// # Panics
        ///
        /// This function will panic if the program fails to load.
        #[must_use]
        pub fn secp256r1_double_program() -> Program {
            Program::from(&SECP256R1_DOUBLE_ELF).unwrap()
        }

        /// Get the SSZ withdrawals program.
        ///
        /// # Panics
        ///
        /// This function will panic if the program fails to load.
        #[must_use]
        pub fn ssz_withdrawals_program() -> Program {
            Program::from(&SSZ_WITHDRAWALS_ELF).unwrap()
        }

        /// Get the keccak permute program.
        ///
        /// # Panics
        ///
        /// This function will panic if the program fails to load.
        #[must_use]
        pub fn keccak_permute_program() -> Program {
            Program::from(&KECCAK_PERMUTE_ELF).unwrap()
        }

        /// Get the panic program.
        ///
        /// # Panics
        ///
        /// This function will panic if the program fails to load.
        #[must_use]
        pub fn panic_program() -> Program {
            Program::from(&PANIC_ELF).unwrap()
        }

        #[must_use]
        #[allow(clippy::unreadable_literal)]
        pub fn simple_memory_program() -> Program {
            let instructions = vec![
                Instruction::new(Opcode::ADDI, 29, 0, 0x12348765, false, true),
                // SW and LW
                Instruction::new(Opcode::SW, 29, 0, 0x27654320, false, true),
                Instruction::new(Opcode::LW, 28, 0, 0x27654320, false, true),
                // LBU
                Instruction::new(Opcode::LBU, 27, 0, 0x27654320, false, true),
                Instruction::new(Opcode::LBU, 26, 0, 0x27654321, false, true),
                Instruction::new(Opcode::LBU, 25, 0, 0x27654322, false, true),
                Instruction::new(Opcode::LBU, 24, 0, 0x27654323, false, true),
                // LB
                Instruction::new(Opcode::LB, 23, 0, 0x27654320, false, true),
                Instruction::new(Opcode::LB, 22, 0, 0x27654321, false, true),
                // LHU
                Instruction::new(Opcode::LHU, 21, 0, 0x27654320, false, true),
                Instruction::new(Opcode::LHU, 20, 0, 0x27654322, false, true),
                // LU
                Instruction::new(Opcode::LH, 19, 0, 0x27654320, false, true),
                Instruction::new(Opcode::LH, 18, 0, 0x27654322, false, true),
                // SB
                Instruction::new(Opcode::ADDI, 17, 0, 0x38276525, false, true),
                // Save the value 0x12348765 into address 0x43627530
                Instruction::new(Opcode::SW, 29, 0, 0x43627530, false, true),
                Instruction::new(Opcode::SB, 17, 0, 0x43627530, false, true),
                Instruction::new(Opcode::LW, 16, 0, 0x43627530, false, true),
                Instruction::new(Opcode::SB, 17, 0, 0x43627531, false, true),
                Instruction::new(Opcode::LW, 15, 0, 0x43627530, false, true),
                Instruction::new(Opcode::SB, 17, 0, 0x43627532, false, true),
                Instruction::new(Opcode::LW, 14, 0, 0x43627530, false, true),
                Instruction::new(Opcode::SB, 17, 0, 0x43627533, false, true),
                Instruction::new(Opcode::LW, 13, 0, 0x43627530, false, true),
                // SH
                // Save the value 0x12348765 into address 0x43627530
                Instruction::new(Opcode::SW, 29, 0, 0x43627530, false, true),
                Instruction::new(Opcode::SH, 17, 0, 0x43627530, false, true),
                Instruction::new(Opcode::LW, 12, 0, 0x43627530, false, true),
                Instruction::new(Opcode::SH, 17, 0, 0x43627532, false, true),
                Instruction::new(Opcode::LW, 11, 0, 0x43627530, false, true),
            ];
            Program::new(instructions, 0, 0)
        }
    }
}
