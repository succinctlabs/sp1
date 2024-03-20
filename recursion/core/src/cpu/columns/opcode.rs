use sp1_derive::AlignedBorrow;

/// Selectors for the opcode.
///
/// This contains selectors for the different opcodes corresponding to variants of the [`Opcode`]
/// enum.
#[derive(AlignedBorrow, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct OpcodeSelectorCols<T> {
    // Arithmetic field instructions.
    pub is_add: T,
    pub is_sub: T,
    pub is_mul: T,

    // Arithmetic field extension operations.
    pub is_eadd: T,
    pub is_esub: T,
    pub is_emul: T,
    pub is_ediv: T,

    // Mixed arithmetic operations.
    pub is_efadd: T,
    pub is_efsub: T,
    pub is_efmul: T,
    pub is_efdiv: T,

    // Memory instructions.
    pub is_lw: T,
    pub is_sw: T,
    pub is_le: T,
    pub is_se: T,

    // Branch instructions.
    pub is_beq: T,
    pub is_bne: T,
    pub is_ebeq: T,
    pub is_ebne: T,

    // Jump instructions.
    pub is_jal: T,
    pub is_jalr: T,

    // System instructions.
    pub is_trap: T,
    pub is_noop: T,
}
