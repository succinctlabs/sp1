use std::fmt::Debug;
use std::mem::size_of;

use crate::{
    symbolic_expr_ef::SymbolicExprEF, symbolic_expr_f::SymbolicExprF,
    symbolic_var_ef::SymbolicVarEF, symbolic_var_f::SymbolicVarF, CUDA_P3_EVAL_EF_CONSTANTS,
    CUDA_P3_EVAL_F_CONSTANTS, EF, F,
};

pub const INSTRUCTION_32_SIZE: usize = size_of::<Instruction32>();
pub const INSTRUCTION_16_SIZE: usize = size_of::<Instruction16>();

#[derive(Clone, Copy)]
pub struct Instruction32 {
    pub opcode: u8,
    pub b_variant: u8,
    pub c_variant: u8,
    pub a: u32,
    pub b: u32,
    pub c: u32,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Instruction16 {
    pub opcode: u8,
    pub b_variant: u8,
    pub c_variant: u8,
    pub a: u16,
    pub b: u16,
    pub c: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum Opcode {
    Empty = 0,

    FAssignC = 1,
    FAssignV = 2,
    FAssignE = 3,

    FAddVC = 4,
    FAddVV = 5,
    FAddVE = 6,

    FAddEC = 7,
    FAddEV = 8,
    FAddEE = 9,
    FAddAssignE = 10,

    FSubVC = 11,
    FSubVV = 12,
    FSubVE = 13,

    FSubEC = 14,
    FSubEV = 15,
    FSubEE = 16,
    FSubAssignE = 17,

    FMulVC = 18,
    FMulVV = 19,
    FMulVE = 20,

    FMulEC = 21,
    FMulEV = 22,
    FMulEE = 23,
    FMulAssignE = 24,

    FNegE = 25,

    EAssignC = 26,
    EAssignV = 27,
    EAssignE = 28,

    EAddVC = 29,
    EAddVV = 30,
    EAddVE = 31,

    EAddEC = 32,
    EAddEV = 33,
    EAddEE = 34,
    EAddAssignE = 35,

    ESubVC = 36,
    ESubVV = 37,
    ESubVE = 38,

    ESubEC = 39,
    ESubEV = 40,
    ESubEE = 41,
    ESubAssignE = 42,

    EMulVC = 43,
    EMulVV = 44,
    EMulVE = 45,

    EMulEC = 46,
    EMulEV = 47,
    EMulEE = 48,
    EMulAssignE = 49,

    ENegE = 50,

    EFFromE = 51,
    EFAddEE = 52,
    EFAddAssignE = 53,
    EFSubEE = 54,
    EFSubAssignE = 55,
    EFMulEE = 56,
    EFMulAssignE = 57,
    EFAsBaseSlice = 58,

    FAssertZero = 59,
    EAssertZero = 60,
}

impl Opcode {
    pub fn is_f_assign(&self) -> bool {
        let value = *self as u8;
        (1..26).contains(&value) || value == 59
    }

    pub fn is_e_assign(&self) -> bool {
        let value = *self as u8;
        (26..59).contains(&value) || value == 60
    }

    pub fn is_f_arg1(&self) -> bool {
        matches!(
            self,
            Opcode::FAssignE
                | Opcode::FAddEC
                | Opcode::FAddEV
                | Opcode::FAddEE
                | Opcode::FAddAssignE
                | Opcode::FSubEC
                | Opcode::FSubEV
                | Opcode::FSubEE
                | Opcode::FSubAssignE
                | Opcode::FMulEC
                | Opcode::FMulEV
                | Opcode::FMulEE
                | Opcode::FMulAssignE
                | Opcode::FNegE
                | Opcode::EFFromE
                | Opcode::EFAddAssignE
                | Opcode::EFSubAssignE
                | Opcode::EFMulAssignE
        )
    }

    pub fn is_f_arg2(&self) -> bool {
        matches!(
            self,
            Opcode::FAddVE
                | Opcode::FAddEE
                | Opcode::FSubVE
                | Opcode::FSubEE
                | Opcode::FMulVE
                | Opcode::FMulEE
                | Opcode::EFAddEE
                | Opcode::EFSubEE
                | Opcode::EFMulEE
        )
    }

    pub fn is_e_arg1(&self) -> bool {
        matches!(
            self,
            Opcode::EAssignE
                | Opcode::EAddEC
                | Opcode::EAddEV
                | Opcode::EAddEE
                | Opcode::EAddAssignE
                | Opcode::ESubEC
                | Opcode::ESubEV
                | Opcode::ESubEE
                | Opcode::ESubAssignE
                | Opcode::EMulEC
                | Opcode::EMulEV
                | Opcode::EMulEE
                | Opcode::EMulAssignE
                | Opcode::ENegE
                | Opcode::EFAddEE
                | Opcode::EFSubEE
                | Opcode::EFMulEE
        )
    }

    pub fn is_e_arg2(&self) -> bool {
        matches!(
            self,
            Opcode::EAddVE
                | Opcode::EAddEE
                | Opcode::ESubVE
                | Opcode::ESubEE
                | Opcode::EMulVE
                | Opcode::EMulEE
        )
    }
}

impl From<u8> for Opcode {
    fn from(value: u8) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

impl Instruction32 {
    pub fn f_assign_c(a: SymbolicExprF, b: F) -> Self {
        let b = f_constant(b);
        Self { opcode: Opcode::FAssignC as u8, a: a.data(), b_variant: 0, b, c_variant: 0, c: 0 }
    }

    pub fn f_assign_v(a: SymbolicExprF, b: SymbolicVarF) -> Self {
        Self {
            opcode: Opcode::FAssignV as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c: 0,
        }
    }

    pub fn f_assign_e(a: SymbolicExprF, b: SymbolicExprF) -> Self {
        Self {
            opcode: Opcode::FAssignE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c: 0,
        }
    }

    pub fn f_add_vc(a: SymbolicExprF, b: SymbolicVarF, c: F) -> Self {
        let c = f_constant(c);
        Self {
            opcode: Opcode::FAddVC as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c,
        }
    }

    pub fn f_add_vv(a: SymbolicExprF, b: SymbolicVarF, c: SymbolicVarF) -> Self {
        Self {
            opcode: Opcode::FAddVV as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn f_add_ve(a: SymbolicExprF, b: SymbolicVarF, c: SymbolicExprF) -> Self {
        Self {
            opcode: Opcode::FAddVE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn f_add_ec(a: SymbolicExprF, b: SymbolicExprF, c: F) -> Self {
        let c = f_constant(c);
        Self {
            opcode: Opcode::FAddEC as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c,
        }
    }

    pub fn f_add_ev(a: SymbolicExprF, b: SymbolicExprF, c: SymbolicVarF) -> Self {
        Self {
            opcode: Opcode::FAddEV as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn f_add_ee(a: SymbolicExprF, b: SymbolicExprF, c: SymbolicExprF) -> Self {
        Self {
            opcode: Opcode::FAddEE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn f_add_assign_e(a: SymbolicExprF, b: SymbolicExprF) -> Self {
        Self {
            opcode: Opcode::FAddAssignE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c: 0,
        }
    }

    pub fn f_sub_vc(a: SymbolicExprF, b: SymbolicVarF, c: F) -> Self {
        let c = f_constant(c);
        Self {
            opcode: Opcode::FSubVC as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c,
        }
    }

    pub fn f_sub_vv(a: SymbolicExprF, b: SymbolicVarF, c: SymbolicVarF) -> Self {
        Self {
            opcode: Opcode::FSubVV as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn f_sub_ve(a: SymbolicExprF, b: SymbolicVarF, c: SymbolicExprF) -> Self {
        Self {
            opcode: Opcode::FSubVE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn f_sub_ec(a: SymbolicExprF, b: SymbolicExprF, c: F) -> Self {
        let c = f_constant(c);
        Self {
            opcode: Opcode::FSubEC as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c,
        }
    }

    pub fn f_sub_ev(a: SymbolicExprF, b: SymbolicExprF, c: SymbolicVarF) -> Self {
        Self {
            opcode: Opcode::FSubEV as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn f_sub_ee(a: SymbolicExprF, b: SymbolicExprF, c: SymbolicExprF) -> Self {
        Self {
            opcode: Opcode::FSubEE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn f_sub_assign_e(a: SymbolicExprF, b: SymbolicExprF) -> Self {
        Self {
            opcode: Opcode::FSubAssignE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c: 0,
        }
    }

    pub fn f_mul_vc(a: SymbolicExprF, b: SymbolicVarF, c: F) -> Self {
        let c = f_constant(c);
        Self {
            opcode: Opcode::FMulVC as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c,
        }
    }

    pub fn f_mul_vv(a: SymbolicExprF, b: SymbolicVarF, c: SymbolicVarF) -> Self {
        Self {
            opcode: Opcode::FMulVV as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn f_mul_ve(a: SymbolicExprF, b: SymbolicVarF, c: SymbolicExprF) -> Self {
        Self {
            opcode: Opcode::FMulVE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c: c.data(),
        }
    }

    pub fn f_mul_ec(a: SymbolicExprF, b: SymbolicExprF, c: F) -> Self {
        let c = f_constant(c);
        Self {
            opcode: Opcode::FMulEC as u8,
            a: a.data(),
            b_variant: 0,
            b: b.data(),
            c_variant: 0,
            c,
        }
    }

    pub fn f_mul_ev(a: SymbolicExprF, b: SymbolicExprF, c: SymbolicVarF) -> Self {
        Self {
            opcode: Opcode::FMulEV as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn f_mul_ee(a: SymbolicExprF, b: SymbolicExprF, c: SymbolicExprF) -> Self {
        Self {
            opcode: Opcode::FMulEE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn f_mul_assign_e(a: SymbolicExprF, b: SymbolicExprF) -> Self {
        Self {
            opcode: Opcode::FMulAssignE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c: 0,
        }
    }

    pub fn f_neg_e(a: SymbolicExprF, b: SymbolicExprF) -> Self {
        Self {
            opcode: Opcode::FNegE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c: 0,
        }
    }

    pub fn e_assign_c(a: SymbolicExprEF, b: EF) -> Self {
        let b = ef_constant(b);
        Self { opcode: Opcode::EAssignC as u8, a: a.data(), b_variant: 0, b, c_variant: 0, c: 0 }
    }

    pub fn e_assign_v(a: SymbolicExprEF, b: SymbolicVarEF) -> Self {
        Self {
            opcode: Opcode::EAssignV as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c: 0,
        }
    }

    pub fn e_assign_e(a: SymbolicExprEF, b: SymbolicExprEF) -> Self {
        Self {
            opcode: Opcode::EAssignE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c: 0,
        }
    }

    pub fn e_add_vc(a: SymbolicExprEF, b: SymbolicVarEF, c: EF) -> Self {
        let c = ef_constant(c);
        Self {
            opcode: Opcode::EAddVC as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c,
        }
    }

    pub fn e_add_vv(a: SymbolicExprEF, b: SymbolicVarEF, c: SymbolicVarEF) -> Self {
        Self {
            opcode: Opcode::EAddVV as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn e_add_ve(a: SymbolicExprEF, b: SymbolicVarEF, c: SymbolicExprEF) -> Self {
        Self {
            opcode: Opcode::EAddVE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn e_add_ec(a: SymbolicExprEF, b: SymbolicExprEF, c: EF) -> Self {
        let c = ef_constant(c);
        Self {
            opcode: Opcode::EAddEC as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c,
        }
    }

    pub fn e_add_ev(a: SymbolicExprEF, b: SymbolicExprEF, c: SymbolicVarEF) -> Self {
        Self {
            opcode: Opcode::EAddEV as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn e_add_ee(a: SymbolicExprEF, b: SymbolicExprEF, c: SymbolicExprEF) -> Self {
        Self {
            opcode: Opcode::EAddEE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn e_add_assign_e(a: SymbolicExprEF, b: SymbolicExprEF) -> Self {
        Self {
            opcode: Opcode::EAddAssignE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c: 0,
        }
    }

    pub fn e_sub_vc(a: SymbolicExprEF, b: SymbolicVarEF, c: EF) -> Self {
        let c = ef_constant(c);
        Self {
            opcode: Opcode::ESubVC as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c,
        }
    }

    pub fn e_sub_vv(a: SymbolicExprEF, b: SymbolicVarEF, c: SymbolicVarEF) -> Self {
        Self {
            opcode: Opcode::ESubVV as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn e_sub_ve(a: SymbolicExprEF, b: SymbolicVarEF, c: SymbolicExprEF) -> Self {
        Self {
            opcode: Opcode::ESubVE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn e_sub_ec(a: SymbolicExprEF, b: SymbolicExprEF, c: EF) -> Self {
        let c = ef_constant(c);
        Self {
            opcode: Opcode::ESubEC as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c,
        }
    }

    pub fn e_sub_ev(a: SymbolicExprEF, b: SymbolicExprEF, c: SymbolicVarEF) -> Self {
        Self {
            opcode: Opcode::ESubEV as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn e_sub_ee(a: SymbolicExprEF, b: SymbolicExprEF, c: SymbolicExprEF) -> Self {
        Self {
            opcode: Opcode::ESubEE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn e_sub_assign_e(a: SymbolicExprEF, b: SymbolicExprEF) -> Self {
        Self {
            opcode: Opcode::ESubAssignE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c: 0,
        }
    }

    pub fn e_mul_vc(a: SymbolicExprEF, b: SymbolicVarEF, c: EF) -> Self {
        let c = ef_constant(c);
        Self {
            opcode: Opcode::EMulVC as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c,
        }
    }

    pub fn e_mul_vv(a: SymbolicExprEF, b: SymbolicVarEF, c: SymbolicVarEF) -> Self {
        Self {
            opcode: Opcode::EMulVV as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn e_mul_ve(a: SymbolicExprEF, b: SymbolicVarEF, c: SymbolicExprEF) -> Self {
        Self {
            opcode: Opcode::EMulVE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn e_mul_ec(a: SymbolicExprEF, b: SymbolicExprEF, c: EF) -> Self {
        let c = ef_constant(c);
        Self {
            opcode: Opcode::EMulEC as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c,
        }
    }

    pub fn e_mul_ev(a: SymbolicExprEF, b: SymbolicExprEF, c: SymbolicVarEF) -> Self {
        Self {
            opcode: Opcode::EMulEV as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn e_mul_ee(a: SymbolicExprEF, b: SymbolicExprEF, c: SymbolicExprEF) -> Self {
        Self {
            opcode: Opcode::EMulEE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn e_mul_assign_e(a: SymbolicExprEF, b: SymbolicExprEF) -> Self {
        Self {
            opcode: Opcode::EMulAssignE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c: 0,
        }
    }

    pub fn e_neg_e(a: SymbolicExprEF, b: SymbolicExprEF) -> Self {
        Self {
            opcode: Opcode::ENegE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c: 0,
        }
    }

    pub fn ef_from_e(a: SymbolicExprEF, b: SymbolicExprF) -> Self {
        Self {
            opcode: Opcode::EFFromE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c: 0,
        }
    }

    pub fn ef_add_ee(a: SymbolicExprEF, b: SymbolicExprEF, c: SymbolicExprF) -> Self {
        Self {
            opcode: Opcode::EFAddEE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn ef_add_assign_e(a: SymbolicExprEF, b: SymbolicExprF) -> Self {
        Self {
            opcode: Opcode::EFAddAssignE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c: 0,
        }
    }

    pub fn ef_sub_ee(a: SymbolicExprEF, b: SymbolicExprEF, c: SymbolicExprF) -> Self {
        Self {
            opcode: Opcode::EFSubEE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn ef_sub_assign_e(a: SymbolicExprEF, b: SymbolicExprF) -> Self {
        Self {
            opcode: Opcode::EFSubAssignE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c: 0,
        }
    }

    pub fn ef_mul_ee(a: SymbolicExprEF, b: SymbolicExprEF, c: SymbolicExprF) -> Self {
        Self {
            opcode: Opcode::EFMulEE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: c.variant(),
            c: c.data(),
        }
    }

    pub fn ef_mul_assign_e(a: SymbolicExprEF, b: SymbolicExprF) -> Self {
        Self {
            opcode: Opcode::EFMulAssignE as u8,
            a: a.data(),
            b_variant: b.variant(),
            b: b.data(),
            c_variant: 0,
            c: 0,
        }
    }

    pub fn f_assert_zero(a: SymbolicExprF) -> Self {
        Self {
            opcode: Opcode::FAssertZero as u8,
            a: a.data(),
            b_variant: 0,
            b: 0,
            c_variant: 0,
            c: 0,
        }
    }

    pub fn e_assert_zero(a: SymbolicExprEF) -> Self {
        Self {
            opcode: Opcode::EAssertZero as u8,
            a: a.data(),
            b_variant: 0,
            b: 0,
            c_variant: 0,
            c: 0,
        }
    }
}

impl Default for Instruction32 {
    fn default() -> Self {
        Self { opcode: Opcode::Empty as u8, a: 0, b_variant: 0, b: 0, c_variant: 0, c: 0 }
    }
}

impl Debug for Instruction32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let opcode = Opcode::from(self.opcode);
        write!(
            f,
            "Instruction {{ opcode: {:?}, a: {}, b_variant: {}, b: {}, c_variant: {}, c: {} }}",
            opcode, self.a, self.b_variant, self.b, self.c_variant, self.c
        )
    }
}

pub fn f_constant(c: F) -> u32 {
    let mut tmp = CUDA_P3_EVAL_F_CONSTANTS.lock().unwrap();
    if let Some(pos) = tmp.iter().position(|&x| x == c) {
        pos as u32
    } else {
        tmp.push(c);
        (tmp.len() - 1) as u32
    }
}

pub fn ef_constant(c: EF) -> u32 {
    let mut tmp = CUDA_P3_EVAL_EF_CONSTANTS.lock().unwrap();
    if let Some(pos) = tmp.iter().position(|&x| x == c) {
        pos as u32
    } else {
        tmp.push(c);
        (tmp.len() - 1) as u32
    }
}
