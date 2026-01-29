use std::{
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use slop_algebra::{AbstractExtensionField, AbstractField};

use crate::{
    instruction::Instruction32, symbolic_expr_f::SymbolicExprF, symbolic_var_ef::SymbolicVarEF,
    CUDA_P3_EVAL_CODE, CUDA_P3_EVAL_EXPR_EF_CTR, EF,
};

#[derive(Debug, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct SymbolicExprEF(pub u32);

impl SymbolicExprEF {
    // #[instrument(skip_all, level = "trace", name = "Empty for SymbolicExprEF")]
    pub fn empty() -> Self {
        Self(u32::MAX)
    }

    // #[instrument(skip_all, level = "trace", name = "Alloc for SymbolicExprEF")]
    pub fn alloc() -> Self {
        let mut tmp = CUDA_P3_EVAL_EXPR_EF_CTR.lock().unwrap();
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

impl Default for SymbolicExprEF {
    // #[instrument(skip_all, level = "trace", name = "Default for SymbolicExprEF")]
    fn default() -> Self {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_assign_c(output, EF::zero()));
        drop(code);
        output
    }
}

impl From<EF> for SymbolicExprEF {
    // #[instrument(skip_all, level = "trace", name = "From<EF> for SymbolicExprEF")]
    fn from(f: EF) -> Self {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_assign_c(output, f));
        drop(code);
        output
    }
}

impl Add<EF> for SymbolicExprEF {
    type Output = Self;

    // #[instrument(skip_all, level = "trace", name = "Add<EF> for SymbolicExprEF")]
    fn add(self, rhs: EF) -> Self::Output {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_add_ec(output, self, rhs));
        drop(code);
        output
    }
}

impl Add<SymbolicVarEF> for SymbolicExprEF {
    type Output = Self;

    // #[instrument(skip_all, level = "trace", name = "Add<SymbolicVarEF> for SymbolicExprEF")]
    fn add(self, rhs: SymbolicVarEF) -> Self::Output {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_add_ev(output, self, rhs));
        drop(code);
        output
    }
}

impl Add<SymbolicExprEF> for SymbolicExprEF {
    type Output = Self;

    // #[instrument(skip_all, level = "trace", name = "Add<SymbolicExprEF> for SymbolicExprEF")]
    fn add(self, rhs: SymbolicExprEF) -> Self::Output {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_add_ee(output, self, rhs));
        drop(code);
        output
    }
}

impl AddAssign for SymbolicExprEF {
    // #[instrument(skip_all, level = "trace", name = "AddAssign for SymbolicExprEF")]
    fn add_assign(&mut self, rhs: Self) {
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_add_assign_e(*self, rhs));
        drop(code);
    }
}

impl Sub<EF> for SymbolicExprEF {
    type Output = Self;

    // #[instrument(skip_all, level = "trace", name = "Sub<EF> for SymbolicExprEF")]
    fn sub(self, rhs: EF) -> Self::Output {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_sub_ec(output, self, rhs));
        drop(code);
        output
    }
}

impl Sub<SymbolicVarEF> for SymbolicExprEF {
    type Output = Self;

    // #[instrument(skip_all, level = "trace", name = "Sub<SymbolicVarEF> for SymbolicExprEF")]
    fn sub(self, rhs: SymbolicVarEF) -> Self::Output {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_sub_ev(output, self, rhs));
        drop(code);
        output
    }
}

impl Sub<SymbolicExprEF> for SymbolicExprEF {
    type Output = Self;

    // #[instrument(skip_all, level = "trace", name = "Sub<SymbolicExprEF> for SymbolicExprEF")]
    fn sub(self, rhs: SymbolicExprEF) -> Self::Output {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_sub_ee(output, self, rhs));
        drop(code);
        output
    }
}

impl SubAssign for SymbolicExprEF {
    // #[instrument(skip_all, level = "trace", name = "SubAssign for SymbolicExprEF")]
    fn sub_assign(&mut self, rhs: Self) {
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_sub_assign_e(*self, rhs));
        drop(code);
    }
}

impl Mul<EF> for SymbolicExprEF {
    type Output = Self;

    // #[instrument(skip_all, level = "trace", name = "Mul<EF> for SymbolicExprEF")]
    fn mul(self, rhs: EF) -> Self::Output {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_mul_ec(output, self, rhs));
        drop(code);
        output
    }
}

impl Mul<SymbolicVarEF> for SymbolicExprEF {
    type Output = Self;

    // #[instrument(skip_all, level = "trace", name = "Mul<SymbolicVarEF> for SymbolicExprEF")]
    fn mul(self, rhs: SymbolicVarEF) -> Self::Output {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_mul_ev(output, self, rhs));
        drop(code);
        output
    }
}

impl Mul<SymbolicExprEF> for SymbolicExprEF {
    type Output = Self;

    // #[instrument(skip_all, level = "trace", name = "Mul<SymbolicExprEF> for SymbolicExprEF")]
    fn mul(self, rhs: SymbolicExprEF) -> Self::Output {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_mul_ee(output, self, rhs));
        drop(code);
        output
    }
}

impl MulAssign for SymbolicExprEF {
    // #[instrument(skip_all, level = "trace", name = "MulAssign for SymbolicExprEF")]
    fn mul_assign(&mut self, rhs: Self) {
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_mul_assign_e(*self, rhs));
        drop(code);
    }
}

impl Neg for SymbolicExprEF {
    type Output = Self;

    // #[instrument(skip_all, level = "trace", name = "Neg for SymbolicExprEF")]
    fn neg(self) -> Self::Output {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_neg_e(output, self));
        drop(code);
        output
    }
}

impl Sum for SymbolicExprEF {
    // #[instrument(skip_all, level = "trace", name = "Sum for SymbolicExprEF")]
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut output = SymbolicExprEF::zero();
        for item in iter {
            output = output + item;
        }
        output
    }
}

impl Product for SymbolicExprEF {
    // #[instrument(skip_all, level = "trace", name = "Product for SymbolicExprEF")]
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut output = SymbolicExprEF::one();
        for item in iter {
            output = output * item;
        }
        output
    }
}

impl Clone for SymbolicExprEF {
    #[allow(clippy::non_canonical_clone_impl)]
    // #[instrument(skip_all, level = "trace", name = "Clone for SymbolicExprEF")]
    fn clone(&self) -> Self {
        // let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        // let output = SymbolicExprEF::alloc();
        // code.push(Instruction32::e_assign_e(output, *self));
        // drop(code);
        // output
        *self
    }
}

impl AbstractField for SymbolicExprEF {
    type F = EF;

    // #[instrument(skip_all, level = "trace", name = "Zero for SymbolicExprEF")]
    fn zero() -> Self {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_assign_c(output, EF::zero()));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "One for SymbolicExprEF")]
    fn one() -> Self {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_assign_c(output, EF::one()));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "Two for SymbolicExprEF")]
    fn two() -> Self {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_assign_c(output, EF::two()));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "NegOne for SymbolicExprEF")]
    fn neg_one() -> Self {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_assign_c(output, EF::neg_one()));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "From<EF> for SymbolicExprEF")]
    fn from_f(f: Self::F) -> Self {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_assign_c(output, f));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "From<bool> for SymbolicExprEF")]
    fn from_bool(b: bool) -> Self {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_assign_c(output, EF::from_bool(b)));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "From<u8> for SymbolicExprEF")]
    fn from_canonical_u8(n: u8) -> Self {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_assign_c(output, EF::from_canonical_u8(n)));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "From<u16> for SymbolicExprEF")]
    fn from_canonical_u16(n: u16) -> Self {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_assign_c(output, EF::from_canonical_u16(n)));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "From<u32> for SymbolicExprEF")]
    fn from_canonical_u32(n: u32) -> Self {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_assign_c(output, EF::from_canonical_u32(n)));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "From<u64> for SymbolicExprEF")]
    fn from_canonical_u64(n: u64) -> Self {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_assign_c(output, EF::from_canonical_u64(n)));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "From<usize> for SymbolicExprEF")]
    fn from_canonical_usize(n: usize) -> Self {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_assign_c(output, EF::from_canonical_usize(n)));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "From<u32> for SymbolicExprEF")]
    fn from_wrapped_u32(n: u32) -> Self {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_assign_c(output, EF::from_wrapped_u32(n)));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "From<u64> for SymbolicExprEF")]
    fn from_wrapped_u64(n: u64) -> Self {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_assign_c(output, EF::from_wrapped_u64(n)));
        drop(code);
        output
    }

    // #[instrument(skip_all, level = "trace", name = "Generator for SymbolicExprEF")]
    fn generator() -> Self {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_assign_c(output, EF::generator()));
        drop(code);
        output
    }
}

impl From<SymbolicExprF> for SymbolicExprEF {
    // #[instrument(skip_all, level = "trace", name = "From<SymbolicExprF> for SymbolicExprEF")]
    fn from(value: SymbolicExprF) -> Self {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::ef_from_e(output, value));
        drop(code);
        output
    }
}

impl Add<SymbolicExprF> for SymbolicExprEF {
    type Output = Self;

    // #[instrument(skip_all, level = "trace", name = "Add<SymbolicExprF> for SymbolicExprEF")]
    fn add(self, rhs: SymbolicExprF) -> Self::Output {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::ef_add_ee(output, self, rhs));
        drop(code);
        output
    }
}

impl AddAssign<SymbolicExprF> for SymbolicExprEF {
    // #[instrument(skip_all, level = "trace", name = "AddAssign<SymbolicExprF> for SymbolicExprEF")]
    fn add_assign(&mut self, rhs: SymbolicExprF) {
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::ef_add_assign_e(*self, rhs));
        drop(code);
    }
}

impl Sub<SymbolicExprF> for SymbolicExprEF {
    type Output = Self;

    // #[instrument(skip_all, level = "trace", name = "Sub<SymbolicExprF> for SymbolicExprEF")]
    fn sub(self, rhs: SymbolicExprF) -> Self::Output {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::ef_sub_ee(output, self, rhs));
        drop(code);
        output
    }
}

impl SubAssign<SymbolicExprF> for SymbolicExprEF {
    // #[instrument(skip_all, level = "trace", name = "SubAssign<SymbolicExprF> for SymbolicExprEF")]
    fn sub_assign(&mut self, rhs: SymbolicExprF) {
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::ef_sub_assign_e(*self, rhs));
        drop(code);
    }
}

impl Mul<SymbolicExprF> for SymbolicExprEF {
    type Output = SymbolicExprEF;

    // #[instrument(skip_all, level = "trace", name = "Mul<SymbolicExprF> for SymbolicExprEF")]
    fn mul(self, rhs: SymbolicExprF) -> Self::Output {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::ef_mul_ee(output, self, rhs));
        drop(code);
        output
    }
}

impl MulAssign<SymbolicExprF> for SymbolicExprEF {
    // #[instrument(skip_all, level = "trace", name = "MulAssign<SymbolicExprF> for SymbolicExprEF")]
    fn mul_assign(&mut self, rhs: SymbolicExprF) {
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::ef_mul_assign_e(*self, rhs));
        drop(code);
    }
}

impl AbstractExtensionField<SymbolicExprF> for SymbolicExprEF {
    const D: usize = 4;

    fn from_base(value: SymbolicExprF) -> Self {
        let output = SymbolicExprEF::alloc();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::ef_from_e(output, value));
        drop(code);
        output
    }

    fn from_base_slice(_: &[SymbolicExprF]) -> Self {
        todo!()
    }

    fn from_base_fn<F: FnMut(usize) -> SymbolicExprF>(_: F) -> Self {
        todo!()
    }

    fn as_base_slice(&self) -> &[SymbolicExprF] {
        todo!()
    }
}
