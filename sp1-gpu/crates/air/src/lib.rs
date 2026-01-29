#![allow(clippy::assign_op_pattern)]

pub mod air_block;
pub mod instruction;
pub mod optimizer;
pub mod symbolic_expr_ef;
pub mod symbolic_expr_f;
pub mod symbolic_var_ef;
pub mod symbolic_var_f;
use std::sync::Mutex;

use air_block::BlockAir;
use instruction::{Instruction16, Instruction32};
use lazy_static::lazy_static;
use slop_air::{
    AirBuilder, AirBuilderWithPublicValues, ExtensionBuilder, PairBuilder, PermutationAirBuilder,
};
use slop_algebra::extension::BinomialExtensionField;
use slop_matrix::dense::RowMajorMatrixView;

use sp1_core_machine::air::TrivialOperationBuilder;
use sp1_hypercube::air::EmptyMessageBuilder;
use sp1_hypercube::{AirOpenedValues, PROOF_MAX_NUM_PVS};
use sp1_primitives::SP1Field;
use symbolic_expr_ef::SymbolicExprEF;
use symbolic_expr_f::SymbolicExprF;
use symbolic_var_ef::SymbolicVarEF;
use symbolic_var_f::SymbolicVarF;

pub type F = SP1Field;

pub type EF = BinomialExtensionField<F, 4>;

lazy_static! {
    pub static ref CUDA_P3_EVAL_LOCK: Mutex<()> = Mutex::new(());
    pub static ref CUDA_P3_EVAL_CODE: Mutex<Vec<Instruction32>> = Mutex::new(Vec::new());
    pub static ref CUDA_P3_EVAL_F_CONSTANTS: Mutex<Vec<F>> = Mutex::new(Vec::new());
    pub static ref CUDA_P3_EVAL_EF_CONSTANTS: Mutex<Vec<EF>> = Mutex::new(Vec::new());
    pub static ref CUDA_P3_EVAL_EXPR_F_CTR: Mutex<u32> = Mutex::new(0);
    pub static ref CUDA_P3_EVAL_EXPR_EF_CTR: Mutex<u32> = Mutex::new(0);
}

pub struct SymbolicProverFolder<'a> {
    pub preprocessed: RowMajorMatrixView<'a, SymbolicVarF>,
    pub main: RowMajorMatrixView<'a, SymbolicVarF>,
    pub public_values: &'a [SymbolicVarF],
    pub num_constraints: u32,
}

impl<'a> AirBuilder for SymbolicProverFolder<'a> {
    type F = F;
    type Var = SymbolicVarF;
    type Expr = SymbolicExprF;
    type M = RowMajorMatrixView<'a, SymbolicVarF>;

    fn main(&self) -> Self::M {
        self.main
    }

    fn is_first_row(&self) -> Self::Expr {
        unimplemented!();
    }

    fn is_last_row(&self) -> Self::Expr {
        unimplemented!();
    }

    fn is_transition_window(&self, _: usize) -> Self::Expr {
        unimplemented!();
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let x: Self::Expr = x.into();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::f_assert_zero(x));
        self.num_constraints += 1;
        drop(code);
    }
}

impl ExtensionBuilder for SymbolicProverFolder<'_> {
    type EF = EF;
    type ExprEF = SymbolicExprEF;
    type VarEF = SymbolicVarEF;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        let x: SymbolicExprEF = x.into();
        let mut code = CUDA_P3_EVAL_CODE.lock().unwrap();
        code.push(Instruction32::e_assert_zero(x));
        self.num_constraints += 1;
        drop(code);
    }
}

impl<'a> PermutationAirBuilder for SymbolicProverFolder<'a> {
    type MP = RowMajorMatrixView<'a, SymbolicVarEF>;
    type RandomVar = SymbolicVarEF;

    fn permutation(&self) -> Self::MP {
        unimplemented!();
    }
    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        unimplemented!();
    }
}

impl PairBuilder for SymbolicProverFolder<'_> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

impl AirBuilderWithPublicValues for SymbolicProverFolder<'_> {
    type PublicVar = SymbolicVarF;

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}

impl EmptyMessageBuilder for SymbolicProverFolder<'_> {}

impl TrivialOperationBuilder for SymbolicProverFolder<'_> {}

/// Generates code in CUDA for evaluating the constraint polynomial on the device.
#[allow(clippy::type_complexity)]
pub fn codegen_cuda_eval<A>(
    air: &A,
) -> (Vec<u32>, Vec<Instruction16>, Vec<u32>, Vec<F>, Vec<u32>, Vec<EF>, Vec<u32>, u32, u32)
where
    A: for<'a> BlockAir<SymbolicProverFolder<'a>>,
{
    let preprocessed_width = air.preprocessed_width() as u32;
    let width = air.width() as u32;
    let preprocessed = AirOpenedValues {
        local: (0..preprocessed_width).map(SymbolicVarF::preprocessed_local).collect(),
    };
    let main = AirOpenedValues { local: (0..width).map(SymbolicVarF::main_local).collect() };
    let public_values =
        (0..PROOF_MAX_NUM_PVS as u32).map(SymbolicVarF::public_value).collect::<Vec<_>>();

    let mut folder = SymbolicProverFolder {
        preprocessed: preprocessed.view(),
        main: main.view(),
        public_values: &public_values,
        num_constraints: 0,
    };

    let nb_block = air.num_blocks();
    let mut constraint_indices = Vec::new();
    let mut instructions = Vec::new();
    let mut block_indices = Vec::new();
    let mut f_constants = Vec::new();
    let mut f_constants_indices = Vec::new();
    let mut ef_constants = Vec::new();
    let mut ef_constants_indices = Vec::new();
    let mut f_ctr = 0;
    let mut ef_ctr = 0;
    for i in 0..nb_block {
        constraint_indices.push(folder.num_constraints);
        air.eval_block(&mut folder, i);
        let code = CUDA_P3_EVAL_CODE.lock().unwrap().to_vec();
        let block_f_constants = CUDA_P3_EVAL_F_CONSTANTS.lock().unwrap().to_vec();
        let block_ef_constants = CUDA_P3_EVAL_EF_CONSTANTS.lock().unwrap().to_vec();
        CUDA_P3_EVAL_RESET();
        let (block_code, block_f_ctr, block_ef_ctr) = optimizer::optimize(code);
        block_indices.push(instructions.len() as u32);
        f_constants_indices.push(f_constants.len() as u32);
        ef_constants_indices.push(ef_constants.len() as u32);
        f_ctr = f_ctr.max(block_f_ctr);
        ef_ctr = ef_ctr.max(block_ef_ctr);
        instructions.extend(block_code);
        f_constants.extend(block_f_constants);
        ef_constants.extend(block_ef_constants);
    }

    (
        constraint_indices,
        instructions,
        block_indices,
        f_constants,
        f_constants_indices,
        ef_constants,
        ef_constants_indices,
        f_ctr as u32,
        ef_ctr as u32,
    )
}

#[allow(non_snake_case)]
pub fn CUDA_P3_EVAL_RESET() {
    *CUDA_P3_EVAL_CODE.lock().unwrap() = Vec::new();
    *CUDA_P3_EVAL_EF_CONSTANTS.lock().unwrap() = Vec::new();
    *CUDA_P3_EVAL_EXPR_F_CTR.lock().unwrap() = 0;
    *CUDA_P3_EVAL_EXPR_EF_CTR.lock().unwrap() = 0;
}
