use std::{
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use crate::{
    instruction::Instruction32, symbolic_var_f::SymbolicVarF, CUDA_P3_EVAL_CODE,
    CUDA_P3_EVAL_EXPR_F_CTR, F,
};

use slop_algebra::AbstractField;

#[derive(Debug, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct SymbolicExprF(pub u32);

impl SymbolicExprF {
    // #[instrument(skip_all, level = "trace", name = "Empty for SymbolicExprF")]
    pub fn empty() -> Self {
        Self(u32::MAX)
    }

    // #[instrument(skip_all, level = "trace", name = "Alloc for SymbolicExprF")]
    pub fn alloc() -> Self {
        let mut tmp = CUDA_P3_EVAL_EXPR_F_CTR.lock().unwrap();
        let id = *tmp;
        *tmp += 1;
        drop(tmp);
        Self(id)
    }

    pub fn variant(&self) -> u8 {
        0
    }

    pub fn data(&self) -> u32 {
        self.0
    }
}

impl Default for SymbolicExprF {
    // #[instrument(skip_all, level = "trace", name = "Default for SymbolicExprF")]
    fn default() -> Self {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_assign_c(output, F::zero()));
        drop(code);
        output
    }
}

impl From<F> for SymbolicExprF {
    // #[instrument(skip_all, level = "trace", name = "From<F> for SymbolicExprF")]
    fn from(f: F) -> Self {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_assign_c(output, f));
        drop(code);
        output
    }
}

impl Add<F> for SymbolicExprF {
    type Output = Self;

    // #[instrument(skip_all, level = "trace", name = "Add<F> for SymbolicExprF")]
    fn add(self, rhs: F) -> Self::Output {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_add_ec(output, self, rhs));
        drop(code);
        output
    }
}

impl Add<SymbolicVarF> for SymbolicExprF {
    type Output = Self;

    // #[instrument(skip_all, level = "trace", name = "Add<SymbolicVarF> for SymbolicExprF")]
    fn add(self, rhs: SymbolicVarF) -> Self::Output {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_add_ev(output, self, rhs));
        drop(code);
        output
    }
}

impl Add<SymbolicExprF> for SymbolicExprF {
    type Output = SymbolicExprF;

    // #[instrument(skip_all, level = "trace", name = "Add<SymbolicExprF> for SymbolicExprF")]
    fn add(self, rhs: SymbolicExprF) -> Self::Output {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_add_ee(output, self, rhs));
        drop(code);
        output
    }
}

impl AddAssign<SymbolicExprF> for SymbolicExprF {
    // #[instrument(skip_all, level = "trace", name = "AddAssign<SymbolicExprF> for SymbolicExprF")]
    fn add_assign(&mut self, _: SymbolicExprF) {
        unreachable!()
    }
}

impl Sub<F> for SymbolicExprF {
    type Output = Self;

    // #[instrument(skip_all, level = "trace", name = "Sub<F> for SymbolicExprF")]
    fn sub(self, rhs: F) -> Self::Output {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_sub_ec(output, self, rhs));
        drop(code);
        output
    }
}

impl Sub<SymbolicVarF> for SymbolicExprF {
    type Output = Self;

    // #[instrument(skip_all, level = "trace", name = "Sub<SymbolicVarF> for SymbolicExprF")]
    fn sub(self, rhs: SymbolicVarF) -> Self::Output {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_sub_ev(output, self, rhs));
        drop(code);
        output
    }
}

impl Sub<SymbolicExprF> for SymbolicExprF {
    type Output = Self;

    // #[instrument(skip_all, level = "trace", name = "Sub<SymbolicExprF> for SymbolicExprF")]
    fn sub(self, rhs: SymbolicExprF) -> Self::Output {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_sub_ee(output, self, rhs));
        drop(code);
        output
    }
}

impl SubAssign<SymbolicExprF> for SymbolicExprF {
    // #[instrument(skip_all, level = "trace", name = "SubAssign<SymbolicExprF> for SymbolicExprF")]
    fn sub_assign(&mut self, _: SymbolicExprF) {
        unreachable!()
    }
}

impl Mul<F> for SymbolicExprF {
    type Output = Self;

    // #[instrument(skip_all, level = "trace", name = "Mul<F> for SymbolicExprF")]
    fn mul(self, rhs: F) -> Self::Output {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_mul_ec(output, self, rhs));
        drop(code);
        output
    }
}

impl Mul<SymbolicVarF> for SymbolicExprF {
    type Output = Self;

    // #[instrument(skip_all, level = "trace", name = "Mul<SymbolicVarF> for SymbolicExprF")]
    fn mul(self, rhs: SymbolicVarF) -> Self::Output {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_mul_ev(output, self, rhs));
        drop(code);
        output
    }
}

impl Mul<SymbolicExprF> for SymbolicExprF {
    type Output = Self;

    // #[instrument(skip_all, level = "trace", name = "Mul<SymbolicExprF> for SymbolicExprF")]
    fn mul(self, rhs: SymbolicExprF) -> Self::Output {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_mul_ee(output, self, rhs));
        drop(code);
        output
    }
}

impl MulAssign<SymbolicExprF> for SymbolicExprF {
    // #[instrument(skip_all, level = "trace", name = "MulAssign<SymbolicExprF> for SymbolicExprF")]
    fn mul_assign(&mut self, _: SymbolicExprF) {
        unreachable!()
    }
}

impl Neg for SymbolicExprF {
    type Output = Self;

    // #[instrument(skip_all, level = "trace", name = "Neg for SymbolicExprF")]
    fn neg(self) -> Self::Output {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_neg_e(output, self));
        drop(code);
        output
    }
}

impl Sum for SymbolicExprF {
    // #[instrument(skip_all, level = "trace", name = "Sum for SymbolicExprF")]
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut output = SymbolicExprF::zero();
        for item in iter {
            output = output + item;
        }
        output
    }
}

impl Product for SymbolicExprF {
    // #[instrument(skip_all, level = "trace", name = "Product for SymbolicExprF")]
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut output = SymbolicExprF::one();
        for item in iter {
            output = output * item;
        }
        output
    }
}

impl Clone for SymbolicExprF {
    #[allow(clippy::non_canonical_clone_impl)]
    // #[instrument(skip_all, level = "trace", name = "Clone for SymbolicExprF")]
    fn clone(&self) -> Self {
        // let output = SymbolicExprF::alloc();
        // let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        // code.push(Instruction32::f_assign_e(output, *self));
        // drop(code);
        // output
        *self
    }
}

impl AbstractField for SymbolicExprF {
    type F = F;

    // #[instrument(skip_all, level = "trace", name = "Zero for SymbolicExprF")]
    fn zero() -> Self {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_assign_c(output, F::zero()));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "One for SymbolicExprF")]
    fn one() -> Self {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_assign_c(output, F::one()));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "Two for SymbolicExprF")]
    fn two() -> Self {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_assign_c(output, F::two()));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "NegOne for SymbolicExprF")]
    fn neg_one() -> Self {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_assign_c(output, F::neg_one()));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "From<F> for SymbolicExprF")]
    fn from_f(f: Self::F) -> Self {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_assign_c(output, f));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "From<bool> for SymbolicExprF")]
    fn from_bool(b: bool) -> Self {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_assign_c(output, F::from_bool(b)));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "From<u8> for SymbolicExprF")]
    fn from_canonical_u8(n: u8) -> Self {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_assign_c(output, F::from_canonical_u8(n)));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "From<u16> for SymbolicExprF")]
    fn from_canonical_u16(n: u16) -> Self {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_assign_c(output, F::from_canonical_u16(n)));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "From<u32> for SymbolicExprF")]
    fn from_canonical_u32(n: u32) -> Self {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_assign_c(output, F::from_canonical_u32(n)));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "From<u64> for SymbolicExprF")]
    fn from_canonical_u64(n: u64) -> Self {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_assign_c(output, F::from_canonical_u64(n)));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "From<usize> for SymbolicExprF")]
    fn from_canonical_usize(n: usize) -> Self {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_assign_c(output, F::from_canonical_usize(n)));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "From<u32> for SymbolicExprF")]
    fn from_wrapped_u32(n: u32) -> Self {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_assign_c(output, F::from_wrapped_u32(n)));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "From<u64> for SymbolicExprF")]
    fn from_wrapped_u64(n: u64) -> Self {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_assign_c(output, F::from_wrapped_u64(n)));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "Generator for SymbolicExprF")]
    fn generator() -> Self {
        let output = SymbolicExprF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_assign_c(output, F::generator()));
        drop(code);
        output
    }
}
