/// A macro to implement ALU operations for the riscv transpiler.
///
/// All operations are binary and accept two operands, possibly an immediate or register.
#[macro_export]
macro_rules! impl_risc_alu {
    ($self:expr, $rd:expr, $rs1:expr, $rs2:expr, $temp_a:expr, $temp_b:expr, $code:block) => {{
        $self.emit_risc_operand_load($rs1, $temp_a);
        $self.emit_risc_operand_load($rs2, $temp_b);
        $code
        $self.emit_risc_register_store($temp_a, None, $rd);
    }};
}

/// Generic immediate optimization macro
#[macro_export]
macro_rules! impl_imm_opt {
    ($self:expr, $rd:expr, $rs1:expr, $rs2:expr, $imm_code:block, $reg_code:block) => {{
        use $crate::RiscOperand;
        match $rs2 {
            RiscOperand::Immediate(imm) => {
                $self.emit_risc_operand_load($rs1, TEMP_A);
                $imm_code
                $self.emit_risc_register_store(TEMP_A, None, $rd);
            }
            _ => {
                $self.emit_risc_operand_load($rs1, TEMP_A);
                $self.emit_risc_operand_load($rs2, TEMP_B);
                $reg_code
                $self.emit_risc_register_store(TEMP_A, None, $rd);
            }
        }
    }};
}

/// Optimized ALU macro that handles immediate operands efficiently
#[macro_export]
macro_rules! impl_alu_imm_opt {
    ($self:expr, $rd:expr, $rs1:expr, $rs2:expr, $op:ident) => {
        match $rs2 {
            RiscOperand::Immediate(imm) => {
                $self.emit_risc_operand_load($rs1, TEMP_A);
                dynasm! { $self; .arch x64; $op Rq(TEMP_A), imm as i32 };
                $self.emit_risc_register_store(TEMP_A, None, $rd);
            }
            _ => {
                $self.emit_risc_operand_load($rs1, TEMP_A);
                $self.emit_risc_operand_load($rs2, TEMP_B);
                dynasm! { $self; .arch x64; $op Rq(TEMP_A), Rq(TEMP_B) };
                $self.emit_risc_register_store(TEMP_A, None, $rd);
            }
        }
    };
}

/// Optimized 32-bit ALU operations with sign extension  
#[macro_export]
macro_rules! impl_alu32_imm_opt {
    ($self:expr, $rd:expr, $rs1:expr, $rs2:expr, $op:ident) => {
        match $rs2 {
            RiscOperand::Immediate(imm) => {
                $self.emit_risc_operand_load($rs1, TEMP_A);
                dynasm! { $self; .arch x64; $op Rd(TEMP_A), imm as i32; movsxd Rq(TEMP_A), Rd(TEMP_A) };
                $self.emit_risc_register_store(TEMP_A, None, $rd);
            }
            _ => {
                $self.emit_risc_operand_load($rs1, TEMP_A);
                $self.emit_risc_operand_load($rs2, TEMP_B);
                dynasm! { $self; .arch x64; $op Rd(TEMP_A), Rd(TEMP_B); movsxd Rq(TEMP_A), Rd(TEMP_A) };
                $self.emit_risc_register_store(TEMP_A, None, $rd);
            }
        }
    };
}

/// Optimized 32-bit shift operations with sign extension
#[macro_export]
macro_rules! impl_shift32_imm_opt {
    ($self:expr, $rd:expr, $rs1:expr, $rs2:expr, $op:ident) => {
        match $rs2 {
            RiscOperand::Immediate(imm) => {
                $self.emit_risc_operand_load($rs1, TEMP_A);
                dynasm! { $self; .arch x64; $op Rd(TEMP_A), (imm & 0x1F) as i8; movsxd Rq(TEMP_A), Rd(TEMP_A) };
                $self.emit_risc_register_store(TEMP_A, None, $rd);
            }
            _ => {
                $self.emit_risc_operand_load($rs1, TEMP_A);
                $self.emit_risc_operand_load($rs2, Rq::RCX as u8);
                dynasm! { $self; .arch x64; $op Rd(TEMP_A), cl; movsxd Rq(TEMP_A), Rd(TEMP_A) };
                $self.emit_risc_register_store(TEMP_A, None, $rd);
            }
        }
    };
}

/// Perform x64 operation with a variable length integer, optimize for code size
#[macro_export]
macro_rules! do_opt_imm_var {
    ($self:expr, $op:ident, $target:expr, $imm:expr) => {
        if $imm as i64 == ($imm as i8) as i64 {
            dynasm! { $self; .arch x64; $op Rq($target), BYTE $imm as i8 };
        } else if $imm as i64 == ($imm as i32) as i64 {
            dynasm! { $self; .arch x64; $op Rq($target), $imm as i32 };
        } else {
            panic!("Value {} cannot be expressed in 32-bit!", $imm);
        }
    };
}

/// Perform x64 operation to load a variable length integer, optimize for code size
#[macro_export]
macro_rules! do_load_imm_var {
    ($self:expr, $target:expr, $imm:expr) => {
        if $imm as i64 == ($imm as i32) as i64 {
            if ($target as u8) < 8 {
                // dynasm would insert an unnecessary REX prefix if we use
                // x64 as the `arch` value. Using x86 as `arch` value strips
                // the prefix. The generated code sequence still work, but
                // shorter.
                dynasm! { $self; .arch x86; mov Rd($target), $imm as i32 };
            } else {
                dynasm! { $self; .arch x64; mov Rd($target), $imm as i32 };
            }
        } else {
            dynasm! { $self; .arch x64; mov Rq($target), QWORD $imm as i64 };
        }
    };
}
