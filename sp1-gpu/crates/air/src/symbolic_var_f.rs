use std::fmt::Debug;
use std::ops::{Add, Mul, Sub};

use crate::instruction::f_constant;
use crate::{instruction::Instruction32, symbolic_expr_f::SymbolicExprF, CUDA_P3_EVAL_CODE, F};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolicVarF {
    Empty,
    Constant(u32),
    PreprocessedLocal(u32),
    PreprocessedNext(u32),
    MainLocal(u32),
    MainNext(u32),
    IsFirstRow,
    IsLastRow,
    IsTransition,
    PublicValue(u32),
    GlobalCumulativeSum(u32),
}

impl SymbolicVarF {
    pub fn empty() -> Self {
        Self::Empty
    }

    pub fn constant(f: F) -> Self {
        let f = f_constant(f);
        Self::Constant(f)
    }

    pub fn preprocessed_local(idx: u32) -> Self {
        Self::PreprocessedLocal(idx)
    }

    pub fn preprocessed_next(idx: u32) -> Self {
        Self::PreprocessedNext(idx)
    }

    pub fn main_local(idx: u32) -> Self {
        Self::MainLocal(idx)
    }

    pub fn main_next(idx: u32) -> Self {
        Self::MainNext(idx)
    }

    pub fn is_first_row() -> Self {
        Self::IsFirstRow
    }

    pub fn is_last_row() -> Self {
        Self::IsLastRow
    }

    pub fn is_transition() -> Self {
        Self::IsTransition
    }

    pub fn public_value(idx: u32) -> Self {
        Self::PublicValue(idx)
    }

    pub fn global_cumulative_sum(idx: u32) -> Self {
        Self::GlobalCumulativeSum(idx)
    }

    pub fn variant(&self) -> u8 {
        match self {
            Self::Empty => 0x00,
            Self::Constant(_) => 0x01,
            Self::PreprocessedLocal(_) => 0x02,
            Self::PreprocessedNext(_) => 0x03,
            Self::MainLocal(_) => 0x04,
            Self::MainNext(_) => 0x05,
            Self::IsFirstRow => 0x06,
            Self::IsLastRow => 0x07,
            Self::IsTransition => 0x08,
            Self::PublicValue(_) => 0x09,
            Self::GlobalCumulativeSum(_) => 0x0A,
        }
    }

    pub fn data(&self) -> u32 {
        match self {
            Self::Empty => 0,
            Self::Constant(f) => *f,
            Self::PreprocessedLocal(idx) => *idx,
            Self::PreprocessedNext(idx) => *idx,
            Self::MainLocal(idx) => *idx,
            Self::MainNext(idx) => *idx,
            Self::IsFirstRow => 0,
            Self::IsLastRow => 0,
            Self::IsTransition => 0,
            Self::PublicValue(idx) => *idx,
            Self::GlobalCumulativeSum(idx) => *idx,
        }
    }
}

impl From<SymbolicVarF> for SymbolicExprF {
    // #[instrument(skip_all, level = "trace", name = "From<SymbolicVarF> for SymbolicExprF")]
    fn from(val: SymbolicVarF) -> Self {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_assign_v(output, val));
        drop(code);
        output
    }
}

impl Add<F> for SymbolicVarF {
    type Output = SymbolicExprF;

    // #[instrument(skip_all, level = "trace", name = "Add<F> for SymbolicVarF")]
    fn add(self, rhs: F) -> Self::Output {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_add_vc(output, self, rhs));
        drop(code);
        output
    }
}

impl Add<SymbolicVarF> for SymbolicVarF {
    type Output = SymbolicExprF;

    // #[instrument(skip_all, level = "trace", name = "Add<SymbolicVarF> for SymbolicVarF")]
    fn add(self, rhs: SymbolicVarF) -> Self::Output {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_add_vv(output, self, rhs));
        drop(code);
        output
    }
}

impl Add<SymbolicExprF> for SymbolicVarF {
    type Output = SymbolicExprF;

    // #[instrument(skip_all, level = "trace", name = "Add<SymbolicExprF> for SymbolicVarF")]
    fn add(self, rhs: SymbolicExprF) -> Self::Output {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_add_ve(output, self, rhs));
        drop(code);
        output
    }
}

impl Sub<F> for SymbolicVarF {
    type Output = SymbolicExprF;

    // #[instrument(skip_all, level = "trace", name = "Sub<F> for SymbolicVarF")]
    fn sub(self, rhs: F) -> Self::Output {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_sub_vc(output, self, rhs));
        drop(code);
        output
    }
}

impl Sub<SymbolicVarF> for SymbolicVarF {
    type Output = SymbolicExprF;

    // #[instrument(skip_all, level = "trace", name = "Sub<SymbolicVarF> for SymbolicVarF")]
    fn sub(self, rhs: SymbolicVarF) -> Self::Output {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_sub_vv(output, self, rhs));
        drop(code);
        output
    }
}

impl Sub<SymbolicExprF> for SymbolicVarF {
    type Output = SymbolicExprF;

    // #[instrument(skip_all, level = "trace", name = "Sub<SymbolicExprF> for SymbolicVarF")]
    fn sub(self, rhs: SymbolicExprF) -> Self::Output {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_sub_ve(output, self, rhs));
        drop(code);
        output
    }
}

impl Mul<F> for SymbolicVarF {
    type Output = SymbolicExprF;

    // #[instrument(skip_all, level = "trace", name = "Mul<F> for SymbolicVarF")]
    fn mul(self, rhs: F) -> Self::Output {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_mul_vc(output, self, rhs));
        drop(code);
        output
    }
}

impl Mul<SymbolicVarF> for SymbolicVarF {
    type Output = SymbolicExprF;

    // #[instrument(skip_all, level = "trace", name = "Mul<SymbolicVarF> for SymbolicVarF")]
    fn mul(self, rhs: SymbolicVarF) -> Self::Output {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_mul_vv(output, self, rhs));
        drop(code);
        output
    }
}

impl Mul<SymbolicExprF> for SymbolicVarF {
    type Output = SymbolicExprF;

    // #[instrument(skip_all, level = "trace", name = "Mul<SymbolicExprF> for SymbolicVarF")]
    fn mul(self, rhs: SymbolicExprF) -> Self::Output {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_mul_ve(output, self, rhs));
        drop(code);
        output
    }
}
