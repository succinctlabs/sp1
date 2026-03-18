#![allow(clippy::fn_to_numeric_cast)]

use super::{TranspilerBackend, CONTEXT, MEMORY_PTR, PC_OFFSET, TEMP_A, TEMP_B};
use crate::{
    impl_alu32_imm_opt, impl_alu_imm_opt, impl_risc_alu, impl_shift32_imm_opt, ComputeInstructions,
    ControlFlowInstructions, JitContext, MemoryInstructions, RiscOperand, RiscRegister,
    RiscvTranspiler, SystemInstructions,
};
use dynasmrt::{dynasm, x64::Rq, DynasmApi, DynasmLabelApi};

impl ComputeInstructions for TranspilerBackend {
    fn add(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        // lhs <- lhs + rhs (64-bit)
        impl_alu_imm_opt!(self, rd, rs1, rs2, add);
    }

    fn mul(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        // rd <- rs1 * rs2 (64-bit)
        impl_risc_alu!(self, rd, rs1, rs2, TEMP_A, TEMP_B, {
            dynasm! {
                self;
                .arch x64;
                imul Rq(TEMP_A), Rq(TEMP_B)
            }
        })
    }

    fn and(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        // rd <- rs1 & rs2 (64-bit)
        impl_alu_imm_opt!(self, rd, rs1, rs2, and);
    }

    fn or(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        // rd <- rs1 | rs2 (64-bit)
        impl_alu_imm_opt!(self, rd, rs1, rs2, or);
    }

    fn xor(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        // rd <- rs1 ^ rs2 (64-bit)
        impl_alu_imm_opt!(self, rd, rs1, rs2, xor);
    }

    fn div(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        // X86 uses [RAX::RDX] for the 64-bit divide operation.
        // So we need to sign extend the lhs into RDX.
        //
        // The quotient is stored in RAX, and the remainder is stored in RDX.
        //
        // We can just write the quotient back into lhs, and the remainder is discarded.
        self.emit_risc_operand_load(rs1, Rq::RAX as u8); // Load dividend directly into RAX
        self.emit_risc_operand_load(rs2, TEMP_B);
        dynasm! {
            self;
            .arch x64;

            // ------------------------------------
            // 1. Skip fault on div-by-zero
            // ------------------------------------
            test Rq(TEMP_B), Rq(TEMP_B);  // ZF=1 if rhs == 0
            jz   >div_by_zero;

            // Check for signed overflow (i64::MIN / -1)
            mov  rcx, -9223372036854775808;  // i64::MIN
            cmp  rax, rcx;
            jne  >no_overflow;
            cmp  Rq(TEMP_B), -1;
            jne  >no_overflow;

            // ------------------------------------
            // 2. Handle overflow: i64::MIN / -1 = i64::MIN (wrapping)
            // ------------------------------------
            mov  rax, -9223372036854775808; // Result is i64::MIN
            jmp >done;

            no_overflow:;
            // ------------------------------------
            // 3. Perform signed divide
            // ------------------------------------
            // dividend already in RAX (loaded directly)
            cqo;                          // sign-extend RAX into RDX (64-bit)
            idiv Rq(TEMP_B);              // quotient → RAX, remainder → RDX
            // quotient already in RAX
            jmp >done;

            // ------------------------------------
            // 4. if rhs == 0
            // ------------------------------------
            div_by_zero:;
            mov  rax, -1;                 // quotient = -1 (RISC-V spec for signed div by zero)

            done:
        }
        self.emit_risc_register_store(Rq::RAX as u8, None, rd);
    }

    fn divu(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        // lhs <- lhs / rhs   (unsigned 64-bit; u64::MAX if rhs == 0)
        // clobbers: RAX, RDX
        self.emit_risc_operand_load(rs1, Rq::RAX as u8); // Load dividend directly into RAX
        self.emit_risc_operand_load(rs2, TEMP_B);
        dynasm! {
            self;
            .arch x64;

            // ----- skip fault on div-by-zero -----
            test Rq(TEMP_B), Rq(TEMP_B);   // ZF = 1 when rhs == 0
            jz   >div_by_zero;

            // ----- perform unsigned divide -----
            // dividend already in RAX (loaded directly)
            xor  rdx, rdx;                 // zero-extend: RDX = 0
            div  Rq(TEMP_B);               // unsigned divide: RDX:RAX / rhs
            // quotient already in RAX
            jmp  >done;

            // ----- rhs == 0 -----
            div_by_zero:;
            mov  rax, -1;                  // quotient = u64::MAX (0xFFFFFFFFFFFFFFFF)

            done:
        }
        self.emit_risc_register_store(Rq::RAX as u8, None, rd);
    }

    fn mulh(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        // Signed multiply high: returns upper 64 bits of rs1 * rs2
        // x86 imul for high multiply requires RAX and produces result in RDX
        self.emit_risc_operand_load(rs1, Rq::RAX as u8); // Load multiplicand directly into RAX
        self.emit_risc_operand_load(rs2, TEMP_B);
        dynasm! {
            self;
            .arch x64;

            // multiplicand already in RAX (loaded directly)
            imul Rq(TEMP_B)          // signed 64×64 → 128; high → RDX
            // high 64 bits already in RDX
        }
        self.emit_risc_register_store(Rq::RDX as u8, None, rd);
    }

    fn mulhu(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        // Unsigned multiply high: returns upper 64 bits of rs1 * rs2
        // x86 mul for high multiply requires RAX and produces result in RDX
        self.emit_risc_operand_load(rs1, Rq::RAX as u8); // Load multiplicand directly into RAX
        self.emit_risc_operand_load(rs2, TEMP_B);
        dynasm! {
            self;
            .arch x64;

            // multiplicand already in RAX (loaded directly)
            mul  Rq(TEMP_B)          // unsigned 64×64 → 128; high → RDX
            // high 64 bits already in RDX
        }
        self.emit_risc_register_store(Rq::RDX as u8, None, rd);
    }

    fn mulhsu(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        // Mixed multiply high: signed rs1 * unsigned rs2, returns upper 64 bits
        self.emit_risc_operand_load(rs1, Rq::RAX as u8); // Load signed multiplicand directly into RAX
        self.emit_risc_operand_load(rs2, TEMP_B);
        dynasm! {
            self;
            .arch x64;

            // ──────────────────────────────────────────────────────────────
            // 1. Move the **signed** left-hand operand (`TEMP_A`) into RAX.
            //    ✦ The x86-64 `mul` instruction always uses RAX as its implicit
            //      64-bit source operand, so we must place `TEMP_A` there first.
            // ──────────────────────────────────────────────────────────────
            // multiplicand already in RAX (optimized load)

            // ──────────────────────────────────────────────────────────────
            // 2. Preserve a second copy of `TEMP_A` in RCX.
            //    ✦ The upcoming `mul` clobbers both RAX and RDX, erasing any
            //      trace of the original sign.  We save `TEMP_A` in RCX so that
            //      we can later decide whether the fix-up for a *negative*
            //      multiplicand is required.
            // ──────────────────────────────────────────────────────────────
            mov rcx, rax;

            // ──────────────────────────────────────────────────────────────
            // 3. Unsigned 64×64-bit multiply:
            //    mul Rq(TEMP_B)
            //    ✦ Computes  RDX:RAX = (unsigned)RAX × (unsigned)TEMP_B.
            //      The high 64 bits of the 128-bit product land in RDX.
            // ──────────────────────────────────────────────────────────────
            mul Rq(TEMP_B);

            // ──────────────────────────────────────────────────────────────
            // 4. Determine whether the *original* `TEMP_A` was negative.
            //    ✦ `test rcx, rcx` sets the sign flag from RCX (the saved `TEMP_A`).
            //    ✦ If the sign flag is *clear* (`TEMP_A` ≥ 0), we can skip the
            //      correction step because the high half already matches the
            //      semantics of the RISC-V MULHSU instruction.
            // ──────────────────────────────────────────────────────────────
            test rcx, rcx;
            jns >store_high;          // Jump if `TEMP_A` was non-negative.

            // ──────────────────────────────────────────────────────────────
            // 5. Fix-up for negative `TEMP_A` (signed × unsigned semantics):
            //    ✦ For a negative multiplicand, the unsigned `mul` delivered a
            //      product that is *2⁶⁴* too large in the high word.  Subtracting
            //      `TEMP_B` from RDX removes that excess and yields the correct
            //      signed-high result.
            // ──────────────────────────────────────────────────────────────
            sub rdx, Rq(TEMP_B);

            // ──────────────────────────────────────────────────────────────
            // 6. Write the corrected high 64 bits back to the destination
            //    RISC register specified by `TEMP_A`.
            // ──────────────────────────────────────────────────────────────
            store_high:
            // result already in RDX
        }
        self.emit_risc_register_store(Rq::RDX as u8, None, rd);
    }

    /// Signed remainder: `rd = rs1 % rs2`  
    /// *RISC-V rule*: if `rs2 == 0`, the result must be **0** (no fault).
    fn rem(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        impl_risc_alu!(self, rd, rs1, rs2, TEMP_A, TEMP_B, {
            dynasm! {
                self;
                .arch x64;

                // ──────────────────────────────────────────────────────────────
                // 0. Guard: if divisor is 0, skip the IDIV and return dividend
                // ──────────────────────────────────────────────────────────────
                test Rq(TEMP_B), Rq(TEMP_B);        // ZF = 1  ⇒  TEMP_B == 0
                jz   >by_zero;                // jump to fix-up path

                // ──────────────────────────────────────────────────────────────
                // 1. Check for signed overflow (i64::MIN % -1)
                // ──────────────────────────────────────────────────────────────
                mov  rcx, -9223372036854775808; // Load i64::MIN into RCX
                cmp  Rq(TEMP_A), rcx;             // Check if dividend == i64::MIN
                jne  >no_overflow;
                cmp  Rq(TEMP_B), -1;              // Check if divisor == -1
                jne  >no_overflow;

                // ──────────────────────────────────────────────────────────────
                // Handle overflow: i64::MIN % -1 = 0 (wrapping)
                // ──────────────────────────────────────────────────────────────
                xor  Rq(TEMP_A), Rq(TEMP_A);        // TEMP_A = 0
                jmp  >done;

                no_overflow:;
                // ──────────────────────────────────────────────────────────────
                // 2. Prepare the **signed** 64-bit dividend in EDX:EAX
                //    -------------------------------------------------
                //    • EAX ← low 32 bits of TEMP_A
                //    • CDQ  sign-extends EAX into EDX
                //      → EDX:EAX now holds the two's-complement 64-bit value a
                // ──────────────────────────────────────────────────────────────
                mov  rax, Rq(TEMP_A);            // RAX = a  (signed 64-bit)
                cqo;                          // RDX = sign(a)

                // ──────────────────────────────────────────────────────────────
                // 3. Signed divide:          a  /  b
                //    -------------------------------------------------
                //    • idiv r/m32   performs  (EDX:EAX) ÷ TEMP_B
                //      – Quotient  → EAX   (ignored)
                //      – Remainder → EDX   (what RISC-V REM returns)
                // ──────────────────────────────────────────────────────────────
                idiv Rq(TEMP_B);                 // signed divide

                // ──────────────────────────────────────────────────────────────
                // 4. Write the remainder (EDX) back to the destination register
                // ──────────────────────────────────────────────────────────────
                mov  Rq(TEMP_A), rdx;            // TEMP_A = remainder
                jmp  >done;

                // ──────────────────────────────────────────────────────────────
                // Divisor == 0  →  result must be dividend (RISC-V spec)
                // ──────────────────────────────────────────────────────────────
                by_zero:;
                // TEMP_A already contains the dividend, no change needed

                done:
            }
        })
    }

    fn remu(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        impl_risc_alu!(self, rd, rs1, rs2, TEMP_A, TEMP_B, {
            dynasm! {
                self;
                .arch x64;

                // ──────────────────────────────────────────────────────────────
                // 0. Guard against /0 → result = dividend (TEMP_A)
                // ──────────────────────────────────────────────────────────────
                test Rq(TEMP_B), Rq(TEMP_B);
                jz   >by_zero;

                // ──────────────────────────────────────────────────────────────
                // 1. Prepare the **unsigned** 128-bit dividend in RDX:RAX
                //    -------------------------------------------------
                //    • Zero-extend TEMP_A into RDX:RAX.
                // ──────────────────────────────────────────────────────────────
                mov  rax, Rq(TEMP_A);
                xor  rdx, rdx;

                // ──────────────────────────────────────────────────────────────
                // 2. Unsigned divide:       a  /  b
                //    -------------------------------------------------
                //    • div r/m64   performs  (RDX:RAX) ÷ TEMP_B
                //      – Quotient  → RAX   (unused)
                //      – Remainder → RDX   (what RISC-V REMU wants)
                // ──────────────────────────────────────────────────────────────
                div  Rq(TEMP_B);

                // ──────────────────────────────────────────────────────────────
                // 3. Write the remainder back to the destination register.
                // ──────────────────────────────────────────────────────────────
                mov  Rq(TEMP_A), rdx;
                jmp  >done;

                // ──────────────────────────────────────────────────────────────
                // Divisor == 0  →  result must be dividend (RISC-V spec)
                // ──────────────────────────────────────────────────────────────
                by_zero:;
                // TEMP_A already contains the dividend, no change needed

                done:
            }
        })
    }

    fn sll(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        // We only can use the lower 6 bits for the shift count in 64-bit mode.
        // In RV64I, this is also true!
        //
        // CL is an alias for the lower byte of RCX.
        match rs2 {
            RiscOperand::Immediate(imm) => {
                self.emit_risc_operand_load(rs1, TEMP_A);
                dynasm! {
                    self;
                    .arch x64;
                    // Direct immediate shift (lower 6 bits automatically masked by x86)
                    shl Rq(TEMP_A), (imm & 0x3F) as i8
                }
                self.emit_risc_register_store(TEMP_A, None, rd);
            }
            _ => {
                self.emit_risc_operand_load(rs1, TEMP_A);
                self.emit_risc_operand_load(rs2, Rq::RCX as u8);
                dynasm! {
                    self;
                    .arch x64;
                    // ──────────────────────────────────────────────────────────────
                    // 1. Shift count is already in RCX (loaded directly).
                    //    • Only the low 6 bits are used for 64-bit operands,
                    //      which matches the RISC-V spec for RV64.
                    // ──────────────────────────────────────────────────────────────

                    // ──────────────────────────────────────────────────────────────
                    // 2. Logical left shift:
                    //      Rq(TEMP_A) ← Rq(TEMP_A) << (CL & 0x3F)
                    //    • `shl` fills zeros from the right as it shifts left.
                    // ──────────────────────────────────────────────────────────────
                    shl  Rq(TEMP_A), cl         // variable-count shift
                }
                self.emit_risc_register_store(TEMP_A, None, rd);
            }
        }
    }

    fn sra(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        match rs2 {
            RiscOperand::Immediate(imm) => {
                self.emit_risc_operand_load(rs1, TEMP_A);
                dynasm! {
                    self;
                    .arch x64;
                    // Direct immediate arithmetic right shift
                    sar Rq(TEMP_A), (imm & 0x3F) as i8
                }
                self.emit_risc_register_store(TEMP_A, None, rd);
            }
            _ => {
                self.emit_risc_operand_load(rs1, TEMP_A);
                self.emit_risc_operand_load(rs2, Rq::RCX as u8);
                dynasm! {
                    self;
                    .arch x64;
                    // ──────────────────────────────────────────────────────────────
                    // 1. Shift count is already in RCX (loaded directly).
                    //    • Only the low 6 bits are used for 64-bit operands,
                    //      which matches the RISC-V spec for RV64.
                    // ──────────────────────────────────────────────────────────────

                    // ──────────────────────────────────────────────────────────────
                    // 2. Arithmetic right shift:
                    //      Rq(TEMP_A) ← (signed)Rq(TEMP_A) >> (CL & 0x3F)
                    //    • `sar` replicates the sign bit as it shifts, so
                    //      negative values stay negative after the operation.
                    // ──────────────────────────────────────────────────────────────
                    sar  Rq(TEMP_A), cl         // variable-count shift
                }
                self.emit_risc_register_store(TEMP_A, None, rd);
            }
        }
    }

    fn srl(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        match rs2 {
            RiscOperand::Immediate(imm) => {
                self.emit_risc_operand_load(rs1, TEMP_A);
                dynasm! {
                    self;
                    .arch x64;
                    // Direct immediate logical right shift
                    shr Rq(TEMP_A), (imm & 0x3F) as i8
                }
                self.emit_risc_register_store(TEMP_A, None, rd);
            }
            _ => {
                self.emit_risc_operand_load(rs1, TEMP_A);
                self.emit_risc_operand_load(rs2, Rq::RCX as u8);
                dynasm! {
                    self;
                    .arch x64;
                    // ──────────────────────────────────────────────────────────────
                    // 1. Shift count is already in RCX (loaded directly).
                    // ──────────────────────────────────────────────────────────────

                    // ──────────────────────────────────────────────────────────────
                    // 2. Logical right shift:
                    //      Rq(TEMP_A) ← (unsigned)Rq(TEMP_A) >> (CL & 0x3F)
                    //    • `shr` always inserts zeros from the left, regardless
                    //      of the operand's sign.
                    // ──────────────────────────────────────────────────────────────
                    shr  Rq(TEMP_A), cl
                }
                self.emit_risc_register_store(TEMP_A, None, rd);
            }
        }
    }

    fn slt(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        match rs2 {
            RiscOperand::Immediate(imm) => {
                self.emit_risc_operand_load(rs1, TEMP_A);
                dynasm! {
                    self;
                    .arch x64;

                    cmp Rq(TEMP_A), imm;

                    // ──────────────────────────────────────────────────────────────
                    // 2. setl  r/m8
                    //    • Writes   1  to the target byte if  (SF ≠ OF)
                    //      which is the signed "less than" condition.
                    //    • We store straight into the low-byte of TEMP_A —
                    //      dynasm's `Rb()` gives us that alias.
                    // ──────────────────────────────────────────────────────────────
                    setl Rb(TEMP_A);               // byte = 1 if TEMP_A < imm (signed)

                    // ──────────────────────────────────────────────────────────────
                    // 3. Zero-extend that byte back to a full 32-bit register so
                    //    that the RISC register ends up with 0x0000_0000 or 0x0000_0001.
                    // ──────────────────────────────────────────────────────────────
                    movzx Rq(TEMP_A), Rb(TEMP_A)     // Rd(TEMP_A) = 0 or 1
                }
                self.emit_risc_register_store(TEMP_A, None, rd);
            }
            _ => {
                self.emit_risc_operand_load(rs1, TEMP_A);
                self.emit_risc_operand_load(rs2, TEMP_B);
                dynasm! {
                    self;
                    .arch x64;

                    cmp Rq(TEMP_A), Rq(TEMP_B);

                    // ──────────────────────────────────────────────────────────────
                    // 2. setl  r/m8
                    //    • Writes   1  to the target byte if  (SF ≠ OF)
                    //      which is the signed "less than" condition.
                    //    • We store straight into the low-byte of TEMP_A —
                    //      dynasm's `Rb()` gives us that alias.
                    // ──────────────────────────────────────────────────────────────
                    setl Rb(TEMP_A);               // byte = 1 if TEMP_A < TEMP_B (signed)

                    // ──────────────────────────────────────────────────────────────
                    // 3. Zero-extend that byte back to a full 32-bit register so
                    //    that the RISC register ends up with 0x0000_0000 or 0x0000_0001.
                    // ──────────────────────────────────────────────────────────────
                    movzx Rq(TEMP_A), Rb(TEMP_A)     // Rd(TEMP_A) = 0 or 1
                }
                self.emit_risc_register_store(TEMP_A, None, rd);
            }
        }
    }

    fn sltu(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        match rs2 {
            RiscOperand::Immediate(imm) => {
                self.emit_risc_operand_load(rs1, TEMP_A);
                dynasm! {
                    self;
                    .arch x64;

                    cmp Rq(TEMP_A), imm;

                    // ------------------------------------
                    // `setb` ("below") checks the Carry Flag (CF):
                    //   CF = 1  iff  TEMP_A < imm  in an *unsigned* sense.
                    // ------------------------------------
                    setb Rb(TEMP_A);

                    // ------------------------------------
                    // Zero-extend to 32 bits (0 or 1).
                    // ------------------------------------
                    movzx Rq(TEMP_A), Rb(TEMP_A)
                }
                self.emit_risc_register_store(TEMP_A, None, rd);
            }
            _ => {
                self.emit_risc_operand_load(rs1, TEMP_A);
                self.emit_risc_operand_load(rs2, TEMP_B);
                dynasm! {
                    self;
                    .arch x64;

                    cmp Rq(TEMP_A), Rq(TEMP_B);

                    // ------------------------------------
                    // `setb` ("below") checks the Carry Flag (CF):
                    //   CF = 1  iff  TEMP_A < TEMP_B  in an *unsigned* sense.
                    // ------------------------------------
                    setb Rb(TEMP_A);

                    // ------------------------------------
                    // Zero-extend to 32 bits (0 or 1).
                    // ------------------------------------
                    movzx Rq(TEMP_A), Rb(TEMP_A)
                }
                self.emit_risc_register_store(TEMP_A, None, rd);
            }
        }
    }

    fn sub(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        // rd <- rs1 - rs2 (64-bit)
        impl_risc_alu!(self, rd, rs1, rs2, TEMP_A, TEMP_B, {
            dynasm! {
                self;
                .arch x64;
                sub Rq(TEMP_A), Rq(TEMP_B)
            }
        })
    }

    fn addw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        // addw performs 32-bit addition on lower 32 bits, then sign-extends result to 64 bits
        impl_alu32_imm_opt!(self, rd, rs1, rs2, add);
    }

    fn subw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        // subw performs 32-bit subtraction on lower 32 bits, then sign-extends result to 64 bits
        impl_risc_alu!(self, rd, rs1, rs2, TEMP_A, TEMP_B, {
            dynasm! {
                self;
                .arch x64;
                sub Rd(TEMP_A), Rd(TEMP_B);
                movsxd Rq(TEMP_A), Rd(TEMP_A)
            }
        })
    }

    fn sllw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        // sllw performs 32-bit shift left, then sign-extends result to 64 bits
        impl_shift32_imm_opt!(self, rd, rs1, rs2, shl);
    }

    fn srlw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        // srlw performs logical right shift on lower 32 bits, then sign-extends result to 64 bits
        impl_shift32_imm_opt!(self, rd, rs1, rs2, shr);
    }

    fn sraw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        // sraw performs arithmetic right shift on lower 32 bits, then sign-extends result to 64
        // bits
        impl_shift32_imm_opt!(self, rd, rs1, rs2, sar);
    }

    fn mulw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        // mulw performs 32-bit multiplication, then sign-extends result to 64 bits
        impl_risc_alu!(self, rd, rs1, rs2, TEMP_A, TEMP_B, {
            dynasm! {
                self;
                .arch x64;

                // Perform 32-bit multiplication
                imul Rd(TEMP_A), Rd(TEMP_B);

                // Sign-extend the 32-bit result to 64 bits
                movsxd Rq(TEMP_A), Rd(TEMP_A)
            }
        });
    }

    fn divw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        // divw performs 32-bit signed division, then sign-extends result to 64 bits
        self.emit_risc_operand_load(rs1, Rq::RAX as u8); // Load dividend directly into RAX
        self.emit_risc_operand_load(rs2, TEMP_B);
        dynasm! {
            self;
            .arch x64;

            // Check for division by zero
            test Rd(TEMP_B), Rd(TEMP_B);
            jz >div_by_zero;

            // Handle 32-bit overflow case on x86-64: INT_MIN / -1 traps (#DE)
            cmp eax, i32::MIN;               // dividend == INT_MIN?
            jne >do_div;
            cmp Rd(TEMP_B), -1;              // divisor == -1?
            jne >do_div;
            mov eax, i32::MIN;               // result = INT_MIN
            movsxd rax, eax;                 // sign-extend to 64-bit
            jmp >done;

            do_div:;
            // Perform signed 32-bit divide
            // dividend already in EAX (loaded directly into RAX)
            cdq;                           // sign-extend EAX into EDX
            idiv Rd(TEMP_B);               // quotient → EAX
            movsxd rax, eax;               // sign-extend result to 64 bits
            jmp >done;

            // Handle overflow: i32::MIN / -1 = i32::MIN (wrapping)
            overflow:;
            mov rax, i32::MIN;
            jmp >done;

            div_by_zero:;
            // For RV64I, divw by zero returns 0xFFFFFFFFFFFFFFFF (-1 sign-extended)
            mov rax, -1;

            done:
        }
        self.emit_risc_register_store(Rq::RAX as u8, None, rd);
    }

    fn divuw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        // divuw performs 32-bit unsigned division, then sign-extends result to 64 bits
        self.emit_risc_operand_load(rs1, Rq::RAX as u8); // Load dividend directly into RAX
        self.emit_risc_operand_load(rs2, TEMP_B);
        dynasm! {
            self;
            .arch x64;

            // Check for division by zero
            test Rd(TEMP_B), Rd(TEMP_B);
            jz >div_by_zero;

            // Perform unsigned 32-bit divide
            // dividend already in EAX (loaded directly into RAX)
            xor edx, edx;               // zero-extend
            div Rd(TEMP_B);                // quotient → EAX
            movsxd rax, eax;               // sign-extend result to 64 bits
            jmp >done;

            div_by_zero:;
            // For RV64I, divuw by zero returns 0xFFFFFFFFFFFFFFFF (-1 sign-extended)
            mov rax, -1;

            done:
        }
        self.emit_risc_register_store(Rq::RAX as u8, None, rd);
    }

    fn remw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        // remw performs 32-bit signed remainder, then sign-extends result to 64 bits
        self.emit_risc_operand_load(rs1, Rq::RAX as u8); // Load dividend directly into RAX
        self.emit_risc_operand_load(rs2, TEMP_B);
        dynasm! {
            self;
            .arch x64;

            // Check for division by zero
            test Rd(TEMP_B), Rd(TEMP_B);
            jz >rem_by_zero;

            // Handle 32-bit overflow case on x86-64: INT_MIN / -1 traps (#DE)
            cmp eax, i32::MIN;   // dividend == INT_MIN?
            jne >do_div;
            cmp Rd(TEMP_B), -1;              // divisor == -1?
            jne >do_div;
            mov eax, i32::MIN;   // result = INT_MIN
            movsxd rax, eax;                 // sign-extend to 64-bit
            jmp >done;

            do_div:;
            // Perform signed 32-bit remainder
            // dividend already in EAX (loaded directly into RAX)
            cdq;                        // sign-extend EAX into EDX
            idiv Rd(TEMP_B);               // remainder → EDX
            movsxd rdx, edx;               // sign-extend result to 64 bits
            jmp >done;

            // Handle overflow: i32::MIN % -1 = 0 (wrapping)
            overflow:;
            xor rdx, rdx;                  // remainder = 0
            jmp >done;

            rem_by_zero:;
            // For RV64I, remw by zero returns the dividend (RAX) sign-extended
            movsxd rdx, eax;

            done:
        }
        self.emit_risc_register_store(Rq::RDX as u8, None, rd);
    }

    fn remuw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        // remuw performs 32-bit unsigned remainder, then sign-extends result to 64 bits
        self.emit_risc_operand_load(rs1, Rq::RAX as u8); // Load dividend directly into RAX
        self.emit_risc_operand_load(rs2, TEMP_B);
        dynasm! {
            self;
            .arch x64;

            // Check for division by zero
            test Rd(TEMP_B), Rd(TEMP_B);
            jz >rem_by_zero;

            // Perform unsigned 32-bit remainder
            // dividend already in EAX (loaded directly into RAX)
            xor edx, edx;               // zero-extend (clear upper 32 bits)
            div Rd(TEMP_B);                // remainder → EDX
            movsxd rdx, edx;               // sign-extend result to 64 bits
            jmp >done;

            rem_by_zero:;
            // For RV64I, remuw by zero returns the dividend (RAX) sign-extended
            movsxd rdx, eax;

            done:
        }
        self.emit_risc_register_store(Rq::RDX as u8, None, rd);
    }

    fn auipc(&mut self, rd: RiscRegister, imm: u64) {
        // rd <- pc + imm

        // ------------------------------------
        // 1. Copy the current PC into TEMP_A
        // 2. Increment the PC by the immediate.
        // ------------------------------------
        let value = self.pc_current.wrapping_add(imm);

        // Store the result in the destination register.
        self.emit_risc_register_store(TEMP_A, Some(value), rd);
    }

    fn lui(&mut self, rd: RiscRegister, imm: u64) {
        // rd <- imm << 12
        // LUI loads a 20-bit immediate shifted left by 12 bits into the destination register
        dynasm! {
            self;
            .arch x64;

            mov Rq(TEMP_A), imm as i32
        }

        // Store the result in the destination register.
        self.emit_risc_register_store(TEMP_A, None, rd);
    }
}

impl ControlFlowInstructions for TranspilerBackend {
    fn jal(&mut self, rd: RiscRegister, imm: u64) {
        // Mark that a control flow instruction has been inserted.
        self.control_flow_instruction_inserted = true;

        let target_pc = self.pc_current.wrapping_add(imm);
        let next_pc = self.pc_current.wrapping_add(4);

        // Store the current PC + 4 into the destination register.
        self.emit_risc_register_store(TEMP_A, Some(next_pc), rd);

        // Adjust the PC store in the context by the immediate.
        self.update_pc(TEMP_B, target_pc);

        // Add the base amount of cycles for the instruction.
        self.bump_clk();

        // We know the jump target at transpile time, we can issue jump
        // to it directly, skipping jump table
        self.end_branch(Some(target_pc));
    }

    fn jalr(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64) {
        // Mark that a control flow instruction has been inserted.
        self.control_flow_instruction_inserted = true;

        // ------------------------------------
        // 1. If rs1 is immediate, we can do fast jumping
        // ------------------------------------
        let jump_target = self.reg_values.get(&rs1).map(|rs1_imm| rs1_imm.wrapping_add(imm));

        // ------------------------------------
        // 2. Update PC value
        // ------------------------------------
        self.emit_risc_operand_load(rs1.into(), TEMP_A);
        dynasm! {
            self;
            .arch x64;

            add Rq(TEMP_A), imm as i32;
            mov QWORD [Rq(CONTEXT) + PC_OFFSET], Rq(TEMP_A)
        }

        // ------------------------------------
        // 3. Compute & store next PC into rd.
        // ------------------------------------
        let next_pc = self.pc_current + 4;
        self.emit_risc_register_store(TEMP_B, Some(next_pc), rd);

        // Add the base amount of cycles for the instruction.
        self.bump_clk();

        self.end_branch(jump_target);
    }

    fn beq(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64) {
        // Mark that a control flow instruction has been inserted.
        self.control_flow_instruction_inserted = true;

        // Add the base amount of cycles for the instruction.
        self.bump_clk();

        self.emit_risc_operand_load(rs1.into(), TEMP_A);
        self.emit_risc_operand_load(rs2.into(), TEMP_B);

        let branched_target = self.pc_current.wrapping_add(imm);
        let not_branched_target = self.pc_current.wrapping_add(4);

        // Compare the registers
        dynasm! {
            self;
            .arch x64;

            // Check if rs1 == rs2
            cmp Rq(TEMP_A), Rq(TEMP_B);
            // If rs1 != rs2, jump to not_branched, since that would imply !(rs1 == rs2)
            jne >not_branched
        }
        // ------------------------------------
        // Branched:
        // 0. Bump the pc by the immediate.
        // ------------------------------------
        self.update_pc(Rq::RAX as u8, branched_target);
        self.end_branch(Some(branched_target));

        dynasm! {
            self;
            .arch x64;

            // ------------------------------------
            // Not branched:
            // ------------------------------------
            not_branched:
        }
        // ------------------------------------
        // 1. Bump the pc by 4
        // ------------------------------------
        self.update_pc(Rq::RAX as u8, not_branched_target);
        self.end_branch(Some(not_branched_target));
    }

    fn bge(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64) {
        // Mark that a control flow instruction has been inserted.
        self.control_flow_instruction_inserted = true;

        // Add the base amount of cycles for the instruction.
        self.bump_clk();

        self.emit_risc_operand_load(rs1.into(), TEMP_A);
        self.emit_risc_operand_load(rs2.into(), TEMP_B);

        let branched_target = self.pc_current.wrapping_add(imm);
        let not_branched_target = self.pc_current.wrapping_add(4);

        dynasm! {
            self;
            .arch x64;

            // Check if rs1 == rs2
            cmp Rq(TEMP_A), Rq(TEMP_B);
            // If rs1 < rs2, jump to not_branched, since that would imply !(rs1 >= rs2)
            jl >not_branched
        }
        // ------------------------------------
        // Branched:
        // 0. Bump the pc by the immediate.
        // ------------------------------------
        self.update_pc(Rq::RAX as u8, branched_target);
        self.end_branch(Some(branched_target));

        dynasm! {
            self;
            .arch x64;

            // ------------------------------------
            // Not branched:
            // ------------------------------------
            not_branched:
        }
        // ------------------------------------
        // 1. Bump the pc by 4
        // ------------------------------------
        self.update_pc(Rq::RAX as u8, not_branched_target);
        self.end_branch(Some(not_branched_target));
    }

    fn bgeu(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64) {
        // Mark that a control flow instruction has been inserted.
        self.control_flow_instruction_inserted = true;

        // Add the base amount of cycles for the instruction.
        self.bump_clk();

        self.emit_risc_operand_load(rs1.into(), TEMP_A);
        self.emit_risc_operand_load(rs2.into(), TEMP_B);

        let branched_target = self.pc_current.wrapping_add(imm);
        let not_branched_target = self.pc_current.wrapping_add(4);

        dynasm! {
            self;
            .arch x64;

            cmp Rq(TEMP_A), Rq(TEMP_B);
            // If rs1 < rs2, jump to not_branched, since that would imply !(rs1 >= rs2)
            jb >not_branched
        }
        // ------------------------------------
        // Branched:
        // 0. Bump the pc by the immediate.
        // ------------------------------------
        self.update_pc(Rq::RAX as u8, branched_target);
        self.end_branch(Some(branched_target));

        dynasm! {
            self;
            .arch x64;

            // ------------------------------------
            // Not branched:
            // ------------------------------------
            not_branched:
        }
        // ------------------------------------
        // 1. Bump the pc by 4
        // ------------------------------------
        self.update_pc(Rq::RAX as u8, not_branched_target);
        self.end_branch(Some(not_branched_target));
    }

    fn blt(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64) {
        // Mark that a control flow instruction has been inserted.
        self.control_flow_instruction_inserted = true;

        // Add the base amount of cycles for the instruction.
        self.bump_clk();

        self.emit_risc_operand_load(rs1.into(), TEMP_A);
        self.emit_risc_operand_load(rs2.into(), TEMP_B);

        let branched_target = self.pc_current.wrapping_add(imm);
        let not_branched_target = self.pc_current.wrapping_add(4);

        dynasm! {
            self;
            .arch x64;

            // ------------------------------------
            // Compare the two registers.
            //
            cmp Rq(TEMP_A), Rq(TEMP_B);   // signed compare
            jge >not_branched             // rs1 ≥ rs2  →  skip
        }
        // ------------------------------------
        // Branched:
        // 0. Bump the pc by the immediate.
        // ------------------------------------
        self.update_pc(Rq::RAX as u8, branched_target);
        self.end_branch(Some(branched_target));

        dynasm! {
            self;
            .arch x64;

            // ------------------------------------
            // Not branched:
            // ------------------------------------
            not_branched:
        }
        // ------------------------------------
        // 1. Bump the pc by 4
        // ------------------------------------
        self.update_pc(Rq::RAX as u8, not_branched_target);
        self.end_branch(Some(not_branched_target));
    }

    fn bltu(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64) {
        // Mark that a control flow instruction has been inserted.
        self.control_flow_instruction_inserted = true;

        // Add the base amount of cycles for the instruction.
        self.bump_clk();

        self.emit_risc_operand_load(rs1.into(), TEMP_A);
        self.emit_risc_operand_load(rs2.into(), TEMP_B);

        let branched_target = self.pc_current.wrapping_add(imm);
        let not_branched_target = self.pc_current.wrapping_add(4);

        dynasm! {
            self;
            .arch x64;
            cmp Rq(TEMP_A), Rq(TEMP_B);   // unsigned compare
            jae >not_branched             // rs1 ≥ rs2 (unsigned) → skip
        }
        // ------------------------------------
        // Branched:
        // 0. Bump the pc by the immediate.
        // ------------------------------------
        self.update_pc(Rq::RAX as u8, branched_target);
        self.end_branch(Some(branched_target));

        dynasm! {
            self;
            .arch x64;

            // ------------------------------------
            // Not branched:
            // ------------------------------------
            not_branched:
        }
        // ------------------------------------
        // 1. Bump the pc by 4
        // ------------------------------------
        self.update_pc(Rq::RAX as u8, not_branched_target);
        self.end_branch(Some(not_branched_target));
    }

    fn bne(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64) {
        // Mark that a control flow instruction has been inserted.
        self.control_flow_instruction_inserted = true;

        // Add the base amount of cycles for the instruction.
        self.bump_clk();

        self.emit_risc_operand_load(rs1.into(), TEMP_A);
        self.emit_risc_operand_load(rs2.into(), TEMP_B);

        let branched_target = self.pc_current.wrapping_add(imm);
        let not_branched_target = self.pc_current.wrapping_add(4);

        dynasm! {
            self;
            .arch x64;
            cmp Rq(TEMP_A), Rq(TEMP_B);   // sets ZF
            je  >not_branched             // rs1 == rs2  →  skip
        }
        // ------------------------------------
        // Branched:
        // 0. Bump the pc by the immediate.
        // ------------------------------------
        self.update_pc(Rq::RAX as u8, branched_target);
        self.end_branch(Some(branched_target));

        dynasm! {
            self;
            .arch x64;

            // ------------------------------------
            // Not branched:
            // ------------------------------------
            not_branched:
        }
        // ------------------------------------
        // 1. Bump the pc by 4
        // ------------------------------------
        self.update_pc(Rq::RAX as u8, not_branched_target);
        self.end_branch(Some(not_branched_target));
    }
}

impl MemoryInstructions for TranspilerBackend {
    fn lb(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64) {
        self.may_early_exit = true;

        // ------------------------------------
        // Load in the base address and the phy sical memory pointer.
        // ------------------------------------
        self.emit_risc_operand_load(rs1.into(), TEMP_A);

        dynasm! {
            self;
            .arch x64;

            // ------------------------------------
            // Add the immediate to the base address
            // Scaled to account for the entry size.
            //
            // TEMP_A = rs1 + imm = addr
            // ------------------------------------
            add Rq(TEMP_A), imm as i32;

            // ------------------------------------
            // Store the intra-word offset.
            // ------------------------------------
            mov rax, Rq(TEMP_A);
            and rax, 7;

            // ------------------------------------
            // Align to the start of the word.
            //
            // Scale to account for the entry size.
            // ------------------------------------
            and Rq(TEMP_A), -8;
            shl Rq(TEMP_A), 1;

            // ------------------------------------
            // Add the risc32 byte offset to the physical memory pointer
            //
            // TEMP_A = addr + physical_memory_pointer
            // ------------------------------------
            add Rq(TEMP_A), Rq(MEMORY_PTR);

            // ------------------------------------
            // 4. Load byte → sign-extend to 32 bits
            //
            // TEMP_B = clk
            // TEMP_A = addr + physical_memory_pointer
            // [addr + physical_memory_pointer] = clk
            // TEMP_A = [addr + physical_memory_pointer + 8]
            // ------------------------------------
            movsx Rq(TEMP_A), BYTE [Rq(TEMP_A) + 8 + rax]
        }

        // 4. Write back to destination register
        self.emit_risc_register_store(TEMP_A, None, rd);
    }

    fn lbu(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64) {
        self.may_early_exit = true;

        // ------------------------------------
        // Load in the base address
        // and the physical memory pointer.
        // ------------------------------------
        self.emit_risc_operand_load(rs1.into(), TEMP_A);

        dynasm! {
            self;
            .arch x64;

            // ------------------------------------
            // Add the immediate to the base address
            //
            // TEMP_A = rs1 + imm = addr
            // ------------------------------------
            add Rq(TEMP_A), imm as i32;

            // ------------------------------------
            // Store the intra-word offset.
            // ------------------------------------
            mov rax, Rq(TEMP_A);
            and rax, 7;

            // ------------------------------------
            // Align to the start of the word.
            //
            // Scale to account for the entry size.
            // ------------------------------------
            and Rq(TEMP_A), -8;
            shl Rq(TEMP_A), 1;

            // ------------------------------------
            // Add the risc32 byte offset to the physical memory pointer
            //
            // TEMP_A = addr + physical_memory_pointer
            // ------------------------------------
            add Rq(TEMP_A), Rq(MEMORY_PTR);

            // ------------------------------------
            // Load byte → zero-extend to 32 bits
            // ------------------------------------
            movzx Rq(TEMP_A), BYTE [Rq(TEMP_A) + 8 + rax]
        }

        self.emit_risc_register_store(TEMP_A, None, rd);
    }

    fn lh(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64) {
        self.may_early_exit = true;

        // ------------------------------------
        // Load in the base address
        // and the physical memory pointer.
        // ------------------------------------
        self.emit_risc_operand_load(rs1.into(), TEMP_A);

        dynasm! {
            self;
            .arch x64;

            // ------------------------------------
            // Add the immediate to the base address
            //
            // TEMP_A = rs1 + imm = addr
            // ------------------------------------
            add Rq(TEMP_A), imm as i32;

             // ------------------------------------
            // Store the intra-word offset.
            // ------------------------------------
            mov rax, Rq(TEMP_A);
            and rax, 7;

            // ------------------------------------
            // Align to the start of the word.
            //
            // Scale to account for the entry size.
            // ------------------------------------
            and Rq(TEMP_A), -8;
            shl Rq(TEMP_A), 1;

            // ------------------------------------
            // Add the risc32 byte offset to the physical memory pointer
            //
            // TEMP_A = addr + physical_memory_pointer
            // ------------------------------------
            add Rq(TEMP_A), Rq(MEMORY_PTR);

            // ------------------------------------
            // Load half-word → sign-extend to 32 bits
            // ------------------------------------
            movsx Rq(TEMP_A), WORD [Rq(TEMP_A) + 8 + rax]
        }

        self.emit_risc_register_store(TEMP_A, None, rd);
    }

    fn lhu(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64) {
        self.may_early_exit = true;

        // ------------------------------------
        //  Load in the base address
        //  and the physical memory pointer.
        // ------------------------------------
        self.emit_risc_operand_load(rs1.into(), TEMP_A);

        dynasm! {
            self;
            .arch x64;

            // ------------------------------------
            // Add the immediate to the base address
            //
            // TEMP_A = rs1 + imm = addr
            // ------------------------------------
            add Rq(TEMP_A), imm as i32;

            // ------------------------------------
            // Store the intra-word offset.
            // ------------------------------------
            mov rax, Rq(TEMP_A);
            and rax, 7;

            // ------------------------------------
            // Align to the start of the word.
            //
            // Scale to account for the entry size.
            // ------------------------------------
            and Rq(TEMP_A), -8;
            shl Rq(TEMP_A), 1;

            // ------------------------------------
            // Add the risc32 byte offset to the physical memory pointer
            //
            // TEMP_A = addr + physical_memory_pointer
            // ------------------------------------
            add Rq(TEMP_A), Rq(MEMORY_PTR);

            // ------------------------------------
            // Load 16 bits, zero-extend to 32 bits
            // ------------------------------------
            movzx Rq(TEMP_A), WORD [Rq(TEMP_A) + 8 + rax]
        }

        self.emit_risc_register_store(TEMP_A, None, rd);
    }

    fn lw(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64) {
        self.may_early_exit = true;

        // ------------------------------------
        // Load the base address into TEMP_A
        // and physical memory pointer into TEMP_B
        // ------------------------------------
        self.emit_risc_operand_load(rs1.into(), TEMP_A);

        dynasm! {
            self;
            .arch x64;

            // ------------------------------------
            // Add the immediate to the base address
            //
            // TEMP_A = rs1 + imm = addr
            // ------------------------------------
            add Rq(TEMP_A), imm as i32;

            // ------------------------------------
            // Store the intra-word offset.
            // ------------------------------------
            mov rax, Rq(TEMP_A);
            and rax, 7;

            // ------------------------------------
            // Align to the start of the word.
            //
            // Scale to account for the entry size.
            // ------------------------------------
            and Rq(TEMP_A), -8;
            shl Rq(TEMP_A), 1;

            // ------------------------------------
            // 3. Add the risc32 byte offset to the physical memory pointer
            //
            // TEMP_A = addr + physical_memory_pointer
            // ------------------------------------
            add Rq(TEMP_A), Rq(MEMORY_PTR);

            // ------------------------------------
            // 4. Load the word from physical memory into TEMP_A (sign-extended to 64-bit)
            // ------------------------------------
            movsxd Rq(TEMP_A), DWORD [Rq(TEMP_A) + 8 + rax]
        }

        // ------------------------------------
        // 5. Store the result in the destination register.
        // ------------------------------------
        self.emit_risc_register_store(TEMP_A, None, rd);
    }

    fn lwu(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64) {
        self.may_early_exit = true;

        // ------------------------------------
        // Load the base address into TEMP_A
        // and physical memory pointer into TEMP_B
        // ------------------------------------
        self.emit_risc_operand_load(rs1.into(), TEMP_A);

        dynasm! {
            self;
            .arch x64;

            // ------------------------------------
            // Add the immediate to the base address
            //
            // TEMP_A = rs1 + imm = addr
            // ------------------------------------
            add Rq(TEMP_A), imm as i32;

            // ------------------------------------
            // Store the intra-word offset.
            // ------------------------------------
            mov rax, Rq(TEMP_A);
            and rax, 7;

            // ------------------------------------
            // Align to the start of the word.
            //
            // Scale to account for the entry size.
            // ------------------------------------
            and Rq(TEMP_A), -8;
            shl Rq(TEMP_A), 1;

            // ------------------------------------
            // 3. Add the risc32 byte offset to the physical memory pointer
            //
            // TEMP_A = addr + physical_memory_pointer
            // ------------------------------------
            add Rq(TEMP_A), Rq(MEMORY_PTR);

            // ------------------------------------
            // 4. Load the word from physical memory into TEMP_B (zero-extended to 64-bit)
            // ------------------------------------
            mov Rd(TEMP_A), DWORD [Rq(TEMP_A) + 8 + rax]
        }

        // ------------------------------------
        // 5. Store the result in the destination register.
        // ------------------------------------
        self.emit_risc_register_store(TEMP_A, None, rd);
    }

    fn ld(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64) {
        self.may_early_exit = true;

        // ------------------------------------
        // 1. Load the base address into TEMP_A
        // and physical memory pointer into TEMP_B
        // ------------------------------------
        self.emit_risc_operand_load(rs1.into(), TEMP_A);

        dynasm! {
            self;
            .arch x64;

            // ------------------------------------
            //  Add the immediate to the base address
            //
            // TEMP_A = rs1 + imm = addr
            // ------------------------------------
            add Rq(TEMP_A), imm as i32;

            // ------------------------------------
            // Scale to account for the entry size.
            //
            // Assume the addr is properly aligned.
            // ------------------------------------
            shl Rq(TEMP_A), 1;

            // ------------------------------------
            // Add the risc byte offset to the physical memory pointer
            //
            // TEMP_A = addr + physical_memory_pointer
            // ------------------------------------
            add Rq(TEMP_A), Rq(MEMORY_PTR);

            // ------------------------------------
            // Load the word from physical memory into TEMP_A
            // ------------------------------------
            mov Rq(TEMP_A), QWORD [Rq(TEMP_A) + 8]
        }

        // ------------------------------------
        // Store the result in the destination register.
        // ------------------------------------
        self.emit_risc_register_store(TEMP_A, None, rd);
    }

    fn sb(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64) {
        self.may_early_exit = true;

        // ------------------------------------
        // Load the base address into TEMP_A
        // and physical memory pointer into TEMP_B
        // ------------------------------------
        self.emit_risc_operand_load(rs1.into(), TEMP_A);

        dynasm! {
            self;
            .arch x64;

            // ------------------------------------
            // Add the immediate to the base address
            // ------------------------------------
            add Rq(TEMP_A), imm as i32;

            // ------------------------------------
            // Store the intra-word offset.
            // ------------------------------------
            mov rax, Rq(TEMP_A);
            and rax, 7;

            // ------------------------------------
            // Align to the start of the word.
            //
            // Scale to account for the entry size.
            // ------------------------------------
            and Rq(TEMP_A), -8;
            shl Rq(TEMP_A), 1;

            // ------------------------------------
            // Add the risc32 byte offset to the physical memory pointer
            // ------------------------------------
            add Rq(TEMP_A), Rq(MEMORY_PTR)
        }

        // ------------------------------------
        // Load the word from the RISC register into TEMP_B
        // ------------------------------------
        self.emit_risc_operand_load(rs2.into(), TEMP_B);

        // ------------------------------------
        // Store the word into physical memory
        // ------------------------------------
        dynasm! {
            self;
            .arch x64;

            mov BYTE [Rq(TEMP_A) + 8 + rax], Rb(TEMP_B)
        }
    }

    fn sh(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64) {
        self.may_early_exit = true;

        // ------------------------------------
        // Load the base address into TEMP_A
        // and physical memory pointer into TEMP_B
        // ------------------------------------
        self.emit_risc_operand_load(rs1.into(), TEMP_A);

        dynasm! {
            self;
            .arch x64;

            // ------------------------------------
            // Add the immediate to the base address
            // ------------------------------------
            add Rq(TEMP_A), imm as i32;

            // ------------------------------------
            // Store the intra-word offset.
            // ------------------------------------
            mov rax, Rq(TEMP_A);
            and rax, 7;

            // ------------------------------------
            // Align to the start of the word.
            // Scale to account for the entry size.
            // ------------------------------------
            and Rq(TEMP_A), -8;
            shl Rq(TEMP_A), 1;

            // ------------------------------------
            // Add the risc32 byte offset to the physical memory pointer
            // ------------------------------------
            add Rq(TEMP_A), Rq(MEMORY_PTR)
        }

        // ------------------------------------
        // Load the word from the RISC register into TEMP_B
        // ------------------------------------
        self.emit_risc_operand_load(rs2.into(), TEMP_B);

        // ------------------------------------
        // Store the word into physical memory
        // ------------------------------------
        dynasm! {
            self;
            .arch x64;

            mov WORD [Rq(TEMP_A) + 8 + rax], Rw(TEMP_B)
        }
    }

    fn sw(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64) {
        self.may_early_exit = true;

        // ------------------------------------
        // Load the base address into TEMP_A
        // and physical memory pointer into TEMP_B
        // ------------------------------------
        self.emit_risc_operand_load(rs1.into(), TEMP_A);

        dynasm! {
            self;
            .arch x64;

            // ------------------------------------
            // Add the immediate to the base address
            // ------------------------------------
            add Rq(TEMP_A), imm as i32;

            // ------------------------------------
            // Store the intra-word offset.
            // ------------------------------------
            mov rax, Rq(TEMP_A);
            and rax, 7;

            // ------------------------------------
            // Align to the start of the word.
            // Scale to account for the entry size.
            // ------------------------------------
            and Rq(TEMP_A), -8;
            shl Rq(TEMP_A), 1;

            // ------------------------------------
            // Add the risc32 byte offset to the physical memory pointer
            // ------------------------------------
            add Rq(TEMP_A), Rq(MEMORY_PTR)
        }

        // ------------------------------------
        // Load the word from the RISC register into TEMP_B
        // ------------------------------------
        self.emit_risc_operand_load(rs2.into(), TEMP_B);

        // ------------------------------------
        // Store the word into physical memory
        // ------------------------------------
        dynasm! {
            self;
            .arch x64;

            mov DWORD [Rq(TEMP_A) + 8 + rax], Rd(TEMP_B)
        }
    }

    fn sd(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64) {
        self.may_early_exit = true;

        // ------------------------------------
        // Load the base address into TEMP_A
        // and physical memory pointer into TEMP_B
        // ------------------------------------
        self.emit_risc_operand_load(rs1.into(), TEMP_A);

        dynasm! {
            self;
            .arch x64;

            // ------------------------------------
            // Add the immediate to the base address
            // ------------------------------------
            add Rq(TEMP_A), imm as i32;

            // ------------------------------------
            // Scale to account for the entry size.
            //
            // Assume the addr is properly aligned.
            // ------------------------------------
            shl Rq(TEMP_A), 1;

            // ------------------------------------
            // 3. Add the risc32 byte offset to the physical memory pointer
            // ------------------------------------
            add Rq(TEMP_A), Rq(MEMORY_PTR)
        }

        // ------------------------------------
        // Load the word from the RISC register into TEMP_B
        // ------------------------------------
        self.emit_risc_operand_load(rs2.into(), TEMP_B);

        // ------------------------------------
        // Store the word into physical memory
        // ------------------------------------
        dynasm! {
            self;
            .arch x64;

            mov QWORD [Rq(TEMP_A) + 8], Rq(TEMP_B)
        }
    }
}

impl SystemInstructions for TranspilerBackend {
    fn ecall(&mut self) {
        // Mark that a control flow instruction has been inserted.
        self.control_flow_instruction_inserted = true;
        self.may_early_exit = true;

        // Load the JitContext pointer into the argument register.
        dynasm! {
            self;
            .arch x64;
            mov rdi, Rq(CONTEXT)
        };

        // `sp1_ecall_handler` bumps PC for syscalls. So we just need
        // to set current PC.
        self.update_pc(TEMP_A, self.pc_current);

        self.call_extern_fn_raw(self.ecall_handler as _);

        // The ecall returns a u64 in RAX.
        self.emit_risc_register_store(Rq::RAX as u8, None, RiscRegister::X5);

        // Add the base amount of cycles for the instruction.
        self.bump_clk();

        self.end_branch(None);
    }

    fn unimp(&mut self) {
        extern "C" fn unimp(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("Unimplemented instruction at pc: {}", ctx.pc);
        }

        self.update_pc(TEMP_A, self.pc_current);
        self.call_extern_fn(unimp);
    }
}
