// Include common aliases as specified by the RISC-V assembly handebook.
//
// see https://riscv.org/wp-content/uploads/2019/06/riscv-spec.pdf chapter 26.

pub const ZERO: Register = Register::X0;
pub const RA: Register = Register::X1;
pub const SP: Register = Register::X2;
pub const GP: Register = Register::X3;
pub const TP: Register = Register::X4;
pub const T0: Register = Register::X5;
pub const T1: Register = Register::X6;
pub const T2: Register = Register::X7;
pub const S0: Register = Register::X8;
pub const S1: Register = Register::X9;
pub const A0: Register = Register::X10;
pub const A1: Register = Register::X11;
pub const A2: Register = Register::X12;
pub const A3: Register = Register::X13;
pub const A4: Register = Register::X14;
pub const A5: Register = Register::X15;
pub const A6: Register = Register::X16;
pub const A7: Register = Register::X17;
pub const S2: Register = Register::X18;
pub const S3: Register = Register::X19;
pub const S4: Register = Register::X20;
pub const S5: Register = Register::X21;
pub const S6: Register = Register::X22;
pub const S7: Register = Register::X23;
pub const S8: Register = Register::X24;
pub const S9: Register = Register::X25;
pub const S10: Register = Register::X26;
pub const S11: Register = Register::X27;
pub const T3: Register = Register::X28;
pub const T4: Register = Register::X29;
pub const T5: Register = Register::X30;
pub const T6: Register = Register::X31;

/// A register stores a 32-bit value used by operations.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Register {
    X0 = 0,
    X1 = 1,
    X2 = 2,
    X3 = 3,
    X4 = 4,
    X5 = 5,
    X6 = 6,
    X7 = 7,
    X8 = 8,
    X9 = 9,
    X10 = 10,
    X11 = 11,
    X12 = 12,
    X13 = 13,
    X14 = 14,
    X15 = 15,
    X16 = 16,
    X17 = 17,
    X18 = 18,
    X19 = 19,
    X20 = 20,
    X21 = 21,
    X22 = 22,
    X23 = 23,
    X24 = 24,
    X25 = 25,
    X26 = 26,
    X27 = 27,
    X28 = 28,
    X29 = 29,
    X30 = 30,
    X31 = 31,
}

impl Register {
    #[inline(always)]
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Register::X0,
            1 => Register::X1,
            2 => Register::X2,
            3 => Register::X3,
            4 => Register::X4,
            5 => Register::X5,
            6 => Register::X6,
            7 => Register::X7,
            8 => Register::X8,
            9 => Register::X9,
            10 => Register::X10,
            11 => Register::X11,
            12 => Register::X12,
            13 => Register::X13,
            14 => Register::X14,
            15 => Register::X15,
            16 => Register::X16,
            17 => Register::X17,
            18 => Register::X18,
            19 => Register::X19,
            20 => Register::X20,
            21 => Register::X21,
            22 => Register::X22,
            23 => Register::X23,
            24 => Register::X24,
            25 => Register::X25,
            26 => Register::X26,
            27 => Register::X27,
            28 => Register::X28,
            29 => Register::X29,
            30 => Register::X30,
            31 => Register::X31,
            _ => panic!("invalid register {}", value),
        }
    }
}
