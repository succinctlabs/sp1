use std::fmt::Debug;
use std::ops::{Add, Mul, Sub};

use crate::{instruction::Instruction32, symbolic_expr_ef::SymbolicExprEF, CUDA_P3_EVAL_CODE, EF};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolicVarEF {
    Empty,
    PermutationLocal(u32),
    PermutationNext(u32),
    PermutationChallenge(u32),
    CumulativeSum(u32),
}

impl SymbolicVarEF {
    // #[instrument(skip_all, level = "trace", name = "Empty for SymbolicVarEF")]
    pub fn empty() -> Self {
        Self::Empty
    }

    // #[instrument(skip_all, level = "trace", name = "PermutationLocal for SymbolicVarEF")]
    pub fn permutation_local(idx: u32) -> Self {
        Self::PermutationLocal(idx)
    }

    // #[instrument(skip_all, level = "trace", name = "PermutationNext for SymbolicVarEF")]
    pub fn permutation_next(idx: u32) -> Self {
        Self::PermutationNext(idx)
    }

    // #[instrument(skip_all, level = "trace", name = "PermutationChallenge for SymbolicVarEF")]
    pub fn permutation_challenge(idx: u32) -> Self {
        Self::PermutationChallenge(idx)
    }

    // #[instrument(skip_all, level = "trace", name = "CumulativeSum for SymbolicVarEF")]
    pub fn cumulative_sum(idx: u32) -> Self {
        Self::CumulativeSum(idx)
    }

    pub fn variant(&self) -> u8 {
        match self {
            Self::Empty => 0x00,
            Self::PermutationLocal(_) => 0x01,
            Self::PermutationNext(_) => 0x02,
            Self::PermutationChallenge(_) => 0x03,
            Self::CumulativeSum(_) => 0x04,
        }
    }

    pub fn data(&self) -> u32 {
        match self {
            Self::Empty => 0,
            Self::PermutationLocal(idx) => *idx,
            Self::PermutationNext(idx) => *idx,
            Self::PermutationChallenge(idx) => *idx,
            Self::CumulativeSum(idx) => *idx,
        }
    }
}

impl From<SymbolicVarEF> for SymbolicExprEF {
    // #[instrument(skip_all, level = "trace", name = "From<SymbolicVarEF> for SymbolicExprEF")]
    fn from(value: SymbolicVarEF) -> Self {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_assign_v(output, value));
        drop(code);
        output
    }
}

impl Add<EF> for SymbolicVarEF {
    type Output = SymbolicExprEF;

    // #[instrument(skip_all, level = "trace", name = "Add<EF> for SymbolicVarEF")]
    fn add(self, rhs: EF) -> Self::Output {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_add_vc(output, self, rhs));
        drop(code);
        output
    }
}

impl Add<SymbolicVarEF> for SymbolicVarEF {
    type Output = SymbolicExprEF;

    // #[instrument(skip_all, level = "trace", name = "Add<SymbolicVarEF> for SymbolicVarEF")]
    fn add(self, rhs: SymbolicVarEF) -> Self::Output {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_add_vv(output, self, rhs));
        drop(code);
        output
    }
}

impl Add<SymbolicExprEF> for SymbolicVarEF {
    type Output = SymbolicExprEF;

    // #[instrument(skip_all, level = "trace", name = "Add<SymbolicExprEF> for SymbolicVarEF")]
    fn add(self, rhs: SymbolicExprEF) -> Self::Output {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_add_ve(output, self, rhs));
        drop(code);
        output
    }
}

impl Sub<EF> for SymbolicVarEF {
    type Output = SymbolicExprEF;

    // #[instrument(skip_all, level = "trace", name = "Sub<EF> for SymbolicVarEF")]
    fn sub(self, rhs: EF) -> Self::Output {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_sub_vc(output, self, rhs));
        drop(code);
        output
    }
}

impl Sub<SymbolicVarEF> for SymbolicVarEF {
    type Output = SymbolicExprEF;

    // #[instrument(skip_all, level = "trace", name = "Sub<SymbolicVarEF> for SymbolicVarEF")]
    fn sub(self, rhs: SymbolicVarEF) -> Self::Output {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_sub_vv(output, self, rhs));
        drop(code);
        output
    }
}

impl Sub<SymbolicExprEF> for SymbolicVarEF {
    type Output = SymbolicExprEF;

    // #[instrument(skip_all, level = "trace", name = "Sub<SymbolicExprEF> for SymbolicVarEF")]
    fn sub(self, rhs: SymbolicExprEF) -> Self::Output {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_sub_ve(output, self, rhs));
        drop(code);
        output
    }
}

impl Mul<EF> for SymbolicVarEF {
    type Output = SymbolicExprEF;

    // #[instrument(skip_all, level = "trace", name = "Mul<EF> for SymbolicVarEF")]
    fn mul(self, rhs: EF) -> Self::Output {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_mul_vc(output, self, rhs));
        drop(code);
        output
    }
}

impl Mul<SymbolicVarEF> for SymbolicVarEF {
    type Output = SymbolicExprEF;

    // #[instrument(skip_all, level = "trace", name = "Mul<SymbolicVarEF> for SymbolicVarEF")]
    fn mul(self, rhs: SymbolicVarEF) -> Self::Output {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_mul_vv(output, self, rhs));
        drop(code);
        output
    }
}

impl Mul<SymbolicExprEF> for SymbolicVarEF {
    type Output = SymbolicExprEF;

    // #[instrument(skip_all, level = "trace", name = "Mul<SymbolicExprEF> for SymbolicVarEF")]
    fn mul(self, rhs: SymbolicExprEF) -> Self::Output {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_mul_ve(output, self, rhs));
        drop(code);
        output
    }
}
