use std::{
    collections::BTreeMap,
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    sync::{Arc, LazyLock, Mutex},
};

use slop_air::{AirBuilder, AirBuilderWithPublicValues, GlobalBuilder, PairBuilder};
use slop_algebra::{extension::BinomialExtensionField, AbstractExtensionField, AbstractField};
use slop_matrix::dense::RowMajorMatrix;
use sp1_core_machine::{
    adapter::{
        register::{
            alu_type::{ALUTypeReader, ALUTypeReaderInput},
            r_type::{
                RTypeReader, RTypeReaderImmutable, RTypeReaderImmutableInput, RTypeReaderInput,
            },
        },
        state::{CPUState, CPUStateInput},
    },
    air::{SP1Operation, SP1OperationBuilder},
    operations::{
        AddOperation, AddOperationInput, BitwiseOperation, BitwiseOperationInput,
        BitwiseU16Operation, BitwiseU16OperationInput, IsEqualWordOperation, IsZeroOperation,
        IsZeroWordOperation, LtOperationSigned, LtOperationSignedInput, LtOperationUnsigned,
        LtOperationUnsignedInput, SubOperation, SubOperationInput, U16CompareOperation,
        U16CompareOperationInput, U16MSBOperation, U16MSBOperationInput, U16toU8Operation,
        U16toU8OperationSafe, U16toU8OperationSafeInput, U16toU8OperationUnsafe,
        U16toU8OperationUnsafeInput,
    },
};
use sp1_primitives::consts::WORD_BYTE_SIZE;
use sp1_hypercube::{
    air::{AirInteraction, InteractionScope, MachineAir, MessageBuilder},
    Word,
};

use crate::ir::{Func, FuncCtx, FuncDecl};

use super::{Ast, BinOp, ExprExtRef, ExprRef, IrVar};

use sp1_primitives::SP1Field;
type F = SP1Field;
type EF = BinomialExtensionField<SP1Field, 4>;

type AstType = Ast<ExprRef<F>, ExprExtRef<EF>>;
type Ty = crate::ir::Ty<ExprRef<F>, ExprExtRef<EF>>;

static GLOBAL_AST: LazyLock<Arc<Mutex<AstType>>> =
    LazyLock::new(|| Arc::new(Mutex::new(Ast::new())));

pub type Expr = ExprRef<F>;

impl AbstractField for Expr {
    type F = F;

    fn zero() -> Self {
        F::zero().into()
    }
    fn one() -> Self {
        F::one().into()
    }
    fn two() -> Self {
        F::two().into()
    }
    fn neg_one() -> Self {
        F::neg_one().into()
    }

    fn from_f(f: Self::F) -> Self {
        f.into()
    }
    fn from_bool(b: bool) -> Self {
        F::from_bool(b).into()
    }
    fn from_canonical_u8(n: u8) -> Self {
        F::from_canonical_u8(n).into()
    }
    fn from_canonical_u16(n: u16) -> Self {
        F::from_canonical_u16(n).into()
    }
    fn from_canonical_u32(n: u32) -> Self {
        F::from_canonical_u32(n).into()
    }
    fn from_canonical_u64(n: u64) -> Self {
        F::from_canonical_u64(n).into()
    }
    fn from_canonical_usize(n: usize) -> Self {
        F::from_canonical_usize(n).into()
    }
    fn from_wrapped_u32(n: u32) -> Self {
        F::from_wrapped_u32(n).into()
    }
    fn from_wrapped_u64(n: u64) -> Self {
        F::from_wrapped_u64(n).into()
    }

    fn generator() -> Self {
        F::generator().into()
    }
}

impl Add for Expr {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.bin_op(BinOp::Add, self, rhs)
    }
}

impl Sub for Expr {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.bin_op(BinOp::Sub, self, rhs)
    }
}

impl Mul for Expr {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.bin_op(BinOp::Mul, self, rhs)
    }
}

impl Neg for Expr {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.negate(self)
    }
}

impl Add<F> for Expr {
    type Output = Self;

    fn add(self, rhs: F) -> Self::Output {
        self + Expr::from(rhs)
    }
}

impl Sub<F> for Expr {
    type Output = Self;

    fn sub(self, rhs: F) -> Self::Output {
        self - Expr::from(rhs)
    }
}

impl Mul<F> for Expr {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        self * Expr::from(rhs)
    }
}

impl Sum for Expr {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(F::zero().into(), Add::add)
    }
}

impl Product for Expr {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(F::one().into(), Mul::mul)
    }
}

impl From<F> for Expr {
    fn from(f: F) -> Self {
        Expr::IrVar(IrVar::Constant(f))
    }
}

impl Default for Expr {
    fn default() -> Self {
        F::zero().into()
    }
}

impl AddAssign for Expr {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl SubAssign for Expr {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl MulAssign for Expr {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

pub type ExprExt = ExprExtRef<EF>;

impl AbstractField for ExprExt {
    type F = EF;

    fn zero() -> Self {
        EF::zero().into()
    }
    fn one() -> Self {
        EF::one().into()
    }
    fn two() -> Self {
        EF::two().into()
    }
    fn neg_one() -> Self {
        EF::neg_one().into()
    }

    fn from_f(f: Self::F) -> Self {
        f.into()
    }
    fn from_bool(b: bool) -> Self {
        EF::from_bool(b).into()
    }
    fn from_canonical_u8(n: u8) -> Self {
        EF::from_canonical_u8(n).into()
    }
    fn from_canonical_u16(n: u16) -> Self {
        EF::from_canonical_u16(n).into()
    }
    fn from_canonical_u32(n: u32) -> Self {
        EF::from_canonical_u32(n).into()
    }
    fn from_canonical_u64(n: u64) -> Self {
        EF::from_canonical_u64(n).into()
    }
    fn from_canonical_usize(n: usize) -> Self {
        EF::from_canonical_usize(n).into()
    }
    fn from_wrapped_u32(n: u32) -> Self {
        EF::from_wrapped_u32(n).into()
    }
    fn from_wrapped_u64(n: u64) -> Self {
        EF::from_wrapped_u64(n).into()
    }

    fn generator() -> Self {
        EF::generator().into()
    }
}

impl AbstractExtensionField<Expr> for ExprExt {
    const D: usize = <EF as AbstractExtensionField<F>>::D;

    fn from_base(b: Expr) -> Self {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.ext_from_base(b)
    }

    fn from_base_slice(_: &[Expr]) -> Self {
        todo!()
    }

    fn from_base_fn<F: FnMut(usize) -> Expr>(_: F) -> Self {
        todo!()
    }

    fn as_base_slice(&self) -> &[Expr] {
        todo!()
    }
}

impl From<Expr> for ExprExt {
    fn from(e: Expr) -> Self {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.ext_from_base(e)
    }
}

impl Add<Expr> for ExprExt {
    type Output = Self;

    fn add(self, rhs: Expr) -> Self::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.bin_op_base_ext(BinOp::Add, self, rhs)
    }
}

impl Sub<Expr> for ExprExt {
    type Output = Self;

    fn sub(self, rhs: Expr) -> Self::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.bin_op_base_ext(BinOp::Sub, self, rhs)
    }
}

impl Mul<Expr> for ExprExt {
    type Output = Self;

    fn mul(self, rhs: Expr) -> Self::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.bin_op_base_ext(BinOp::Mul, self, rhs)
    }
}

impl MulAssign<Expr> for ExprExt {
    fn mul_assign(&mut self, rhs: Expr) {
        *self = *self * rhs;
    }
}

impl AddAssign<Expr> for ExprExt {
    fn add_assign(&mut self, rhs: Expr) {
        *self = *self + rhs;
    }
}

impl SubAssign<Expr> for ExprExt {
    fn sub_assign(&mut self, rhs: Expr) {
        *self = *self - rhs;
    }
}

impl Add for ExprExt {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.bin_op_ext(BinOp::Add, self, rhs)
    }
}

impl Sub for ExprExt {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.bin_op_ext(BinOp::Sub, self, rhs)
    }
}

impl Mul for ExprExt {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.bin_op_ext(BinOp::Mul, self, rhs)
    }
}

impl Neg for ExprExt {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.neg_ext(self)
    }
}

impl From<EF> for ExprExt {
    fn from(f: EF) -> Self {
        ExprExtRef::ExtConstant(f)
    }
}

impl Default for ExprExt {
    fn default() -> Self {
        EF::zero().into()
    }
}

impl AddAssign for ExprExt {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl SubAssign for ExprExt {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl MulAssign for ExprExt {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Sum for ExprExt {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(EF::zero().into(), Add::add)
    }
}

impl Product for ExprExt {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(EF::one().into(), Mul::mul)
    }
}

pub struct ConstraintCompiler {
    public_values: Vec<Expr>,
    preprocessed: RowMajorMatrix<Expr>,
    global: RowMajorMatrix<Expr>,
    main: RowMajorMatrix<Expr>,
    modules: BTreeMap<String, Func<Expr, ExprExt>>,
    parent: Option<AstType>,
}

impl ConstraintCompiler {
    pub fn new<A: MachineAir<F>>(air: &A, num_public_values: usize) -> Self {
        let preprocessed_width = air.preprocessed_width();
        let global_width = air.global_width();
        let main_width = air.width();
        Self::with_sizes(num_public_values, preprocessed_width, global_width, main_width)
    }

    pub fn with_sizes(
        num_public_values: usize,
        preprocessed_width: usize,
        global_width: usize,
        main_width: usize,
    ) -> Self {
        // Initialize the global AST to empty.
        let mut ast = GLOBAL_AST.lock().unwrap();
        *ast = Ast::new();

        // Initialize the public values.
        let public_values = (0..num_public_values).map(Expr::public).collect();
        // Initialize the preprocessed, global, and main traces.
        let preprocessed = (0..preprocessed_width).map(Expr::preprocessed).collect();
        let preprocessed = RowMajorMatrix::new(preprocessed, preprocessed_width);
        let global = (0..global_width).map(Expr::global).collect();
        let global = RowMajorMatrix::new(global, global_width);
        let main = (0..main_width).map(Expr::main).collect();
        let main = RowMajorMatrix::new(main, main_width);

        Self { public_values, preprocessed, global, main, modules: BTreeMap::new(), parent: None }
    }

    pub fn ast(&self) -> Ast<ExprRef<F>, ExprExtRef<EF>> {
        let ast = GLOBAL_AST.lock().unwrap();
        ast.clone()
    }

    fn region(&self) -> Self {
        let parent = self.ast();
        let mut ast = GLOBAL_AST.lock().unwrap();
        *ast = Ast::new();
        Self {
            public_values: self.public_values.clone(),
            preprocessed: self.preprocessed.clone(),
            global: self.global.clone(),
            main: self.main.clone(),
            modules: BTreeMap::new(),
            parent: Some(parent),
        }
    }

    fn register_module(&mut self, decl: FuncDecl<Expr, ExprExt>, body: impl FnOnce(&mut Self)) {
        let mut body_builder = self.region();
        body(&mut body_builder);
        let body = body_builder.ast();

        let name = decl.name.clone();
        self.modules.append(&mut body_builder.modules);
        self.modules.insert(name, Func { decl, body });
    }

    pub fn modules(&self) -> &BTreeMap<String, Func<Expr, ExprExt>> {
        &self.modules
    }

    pub fn num_cols(&self) -> usize {
        self.main.width
    }
}

impl Drop for ConstraintCompiler {
    fn drop(&mut self) {
        if let Some(parent) = self.parent.take() {
            let mut ast = GLOBAL_AST.lock().unwrap();
            *ast = parent;
        }
    }
}

impl AirBuilder for ConstraintCompiler {
    type F = F;
    type Expr = Expr;
    type Var = Expr;
    type M = RowMajorMatrix<Expr>;

    fn main(&self) -> Self::M {
        self.main.clone()
    }

    fn is_first_row(&self) -> Self::Expr {
        unreachable!("first row is not supported")
    }

    fn is_last_row(&self) -> Self::Expr {
        unreachable!("last row is not supported")
    }

    fn is_transition_window(&self, _size: usize) -> Self::Expr {
        unreachable!("transition window is not supported")
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let x = x.into();
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.assert_zero(x);
    }
}

impl MessageBuilder<AirInteraction<Expr>> for ConstraintCompiler {
    fn send(&mut self, message: AirInteraction<Expr>, scope: InteractionScope) {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.send(message, scope);
    }

    fn receive(&mut self, message: AirInteraction<Expr>, scope: InteractionScope) {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.receive(message, scope);
    }
}

impl PairBuilder for ConstraintCompiler {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed.clone()
    }
}

impl GlobalBuilder for ConstraintCompiler {
    fn global(&self) -> Self::M {
        self.global.clone()
    }
}

impl AirBuilderWithPublicValues for ConstraintCompiler {
    type PublicVar = Expr;

    fn public_values(&self) -> &[Self::PublicVar] {
        &self.public_values
    }
}

impl SP1OperationBuilder<AddOperation<F>> for ConstraintCompiler {
    fn eval_operation(&mut self, input: AddOperationInput<Self>) {
        GLOBAL_AST.lock().unwrap().add_operation(input.a, input.b, input.cols, input.is_real);

        // Record the operation module
        if !self.modules.contains_key("AddOperation") {
            let mut ctx = FuncCtx::new();

            let input_a = Expr::input_from_struct::<Word<Expr>>(&mut ctx);
            let input_b = Expr::input_from_struct::<Word<Expr>>(&mut ctx);
            let cols = Expr::input_from_struct::<AddOperation<Expr>>(&mut ctx);
            let is_real = Expr::input_arg(&mut ctx);

            let func_input = AddOperationInput::new(input_a, input_b, cols, is_real);

            // Get parameter names from the derive macro
            let parameter_names = AddOperationInput::<Self>::PARAMETER_NAMES;

            self.register_module(
                FuncDecl::with_parameter_names(
                    "AddOperation",
                    vec![
                        Ty::Word(input_a),
                        Ty::Word(input_b),
                        Ty::AddOperation(cols),
                        Ty::Expr(is_real),
                    ],
                    vec![],
                    parameter_names,
                ),
                |body| {
                    AddOperation::<F>::lower(body, func_input);
                },
            );
        }
    }
}

impl SP1OperationBuilder<SubOperation<F>> for ConstraintCompiler {
    fn eval_operation(&mut self, input: SubOperationInput<Self>) {
        GLOBAL_AST.lock().unwrap().sub_operation(input.a, input.b, input.cols, input.is_real);

        // Record the operation module
        if !self.modules.contains_key("SubOperation") {
            let mut ctx = FuncCtx::new();

            let input_a = Expr::input_from_struct::<Word<Expr>>(&mut ctx);
            let input_b = Expr::input_from_struct::<Word<Expr>>(&mut ctx);
            let cols = Expr::input_from_struct::<SubOperation<Expr>>(&mut ctx);
            let is_real = Expr::input_arg(&mut ctx);

            let func_input = SubOperationInput::new(input_a, input_b, cols, is_real);

            // Get parameter names from the derive macro
            let parameter_names = SubOperationInput::<Self>::PARAMETER_NAMES;

            self.register_module(
                FuncDecl::with_parameter_names(
                    "SubOperation",
                    vec![
                        Ty::Word(input_a),
                        Ty::Word(input_b),
                        Ty::SubOperation(cols),
                        Ty::Expr(is_real),
                    ],
                    vec![],
                    parameter_names,
                ),
                |body| {
                    SubOperation::<F>::lower(body, func_input);
                },
            );
        }
    }
}

impl SP1OperationBuilder<U16toU8OperationSafe> for ConstraintCompiler {
    fn eval_operation(
        &mut self,
        input: U16toU8OperationSafeInput<Self>,
    ) -> [ExprRef<F>; WORD_BYTE_SIZE] {
        let result = GLOBAL_AST.lock().unwrap().u16_to_u8_operation_safe(
            input.u16_values,
            input.cols,
            input.is_real,
        );

        if !self.modules.contains_key("U16toU8OperationSafe") {
            let mut ctx = FuncCtx::new();

            let input_u16_values = core::array::from_fn(|_| Expr::input_arg(&mut ctx));
            let input_cols = Expr::input_from_struct::<U16toU8Operation<Expr>>(&mut ctx);
            let input_is_real = Expr::input_arg(&mut ctx);

            let func_input =
                U16toU8OperationSafeInput::new(input_u16_values, input_cols, input_is_real);
            let func_output = core::array::from_fn(|_| Expr::output_arg(&mut ctx));

            let func_decl = FuncDecl::new(
                "U16toU8OperationSafe",
                vec![
                    Ty::ArrWordSize(input_u16_values),
                    Ty::U16toU8Operation(input_cols),
                    Ty::Expr(input_is_real),
                ],
                vec![Ty::ArrWordByteSize(func_output)],
            );

            self.register_module(func_decl, |body| {
                let output = U16toU8OperationSafe::lower(body, func_input);
                for (i, o) in func_output.iter().zip(output.iter()) {
                    GLOBAL_AST.lock().unwrap().assign(*i, *o);
                }
            });
        }

        result
    }
}

impl SP1OperationBuilder<U16toU8OperationUnsafe> for ConstraintCompiler {
    fn eval_operation(
        &mut self,
        input: U16toU8OperationUnsafeInput<Self>,
    ) -> [ExprRef<F>; WORD_BYTE_SIZE] {
        let result =
            GLOBAL_AST.lock().unwrap().u16_to_u8_operation_unsafe(input.u16_values, input.cols);

        if !self.modules.contains_key("U16toU8OperationUnsafe") {
            let mut ctx = FuncCtx::new();

            let input_u16_values = core::array::from_fn(|_| Expr::input_arg(&mut ctx));
            let input_cols = Expr::input_from_struct::<U16toU8Operation<Expr>>(&mut ctx);
            let func_input = U16toU8OperationUnsafeInput::new(input_u16_values, input_cols);

            let func_output: [ExprRef<F>; WORD_BYTE_SIZE] =
                core::array::from_fn(|_| Expr::output_arg(&mut ctx));

            self.register_module(
                FuncDecl::with_parameter_names(
                    "U16toU8OperationUnsafe",
                    vec![Ty::ArrWordSize(input_u16_values), Ty::U16toU8Operation(input_cols)],
                    vec![Ty::ArrWordByteSize(func_output)],
                    U16toU8OperationUnsafeInput::<Self>::PARAMETER_NAMES,
                ),
                |body| {
                    let output = U16toU8OperationUnsafe::lower(body, func_input);
                    for (i, o) in func_output.iter().zip(output.iter()) {
                        GLOBAL_AST.lock().unwrap().assign(*i, *o);
                    }
                },
            );
        }
        result
    }
}

impl SP1OperationBuilder<IsZeroOperation<F>> for ConstraintCompiler {
    fn eval_operation(&mut self, input: <IsZeroOperation<F> as SP1Operation<Self>>::Input) {
        let mut ast = GLOBAL_AST.lock().unwrap();
        let (a, cols, is_real) = input;
        ast.is_zero_operation(a, cols, is_real);
        drop(ast);

        if !self.modules.contains_key("IsZeroOperation") {
            let mut ctx = FuncCtx::new();
            let input_a = Expr::input_arg(&mut ctx);
            let input_cols = Expr::input_from_struct::<IsZeroOperation<Expr>>(&mut ctx);
            let input_is_real = Expr::input_arg(&mut ctx);

            self.register_module(
                FuncDecl::new(
                    "IsZeroOperation",
                    vec![
                        Ty::Expr(input_a),
                        Ty::IsZeroOperation(input_cols),
                        Ty::Expr(input_is_real),
                    ],
                    vec![],
                ),
                |body| {
                    IsZeroOperation::<F>::lower(body, input);
                },
            );
        }
    }
}

impl SP1OperationBuilder<IsZeroWordOperation<F>> for ConstraintCompiler {
    fn eval_operation(
        &mut self,
        input: <IsZeroWordOperation<F> as SP1Operation<Self>>::Input,
    ) -> <IsZeroWordOperation<F> as SP1Operation<Self>>::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        let (a, cols, is_real) = input;
        ast.is_zero_word_operation(a, cols, is_real);
        drop(ast);

        if !self.modules.contains_key("IsZeroWordOperation") {
            let mut ctx = FuncCtx::new();
            let input_a = Expr::input_arg(&mut ctx);
            let input_cols = Expr::input_from_struct::<IsZeroWordOperation<Expr>>(&mut ctx);
            let input_is_real = Expr::input_arg(&mut ctx);

            self.register_module(
                FuncDecl::new(
                    "IsZeroWordOperation",
                    vec![
                        Ty::Expr(input_a),
                        Ty::IsZeroWordOperation(input_cols),
                        Ty::Expr(input_is_real),
                    ],
                    vec![],
                ),
                |body| {
                    IsZeroWordOperation::<F>::lower(body, input);
                },
            );
        }
    }
}

impl SP1OperationBuilder<IsEqualWordOperation<F>> for ConstraintCompiler {
    fn eval_operation(&mut self, input: <IsEqualWordOperation<F> as SP1Operation<Self>>::Input) {
        let mut ast = GLOBAL_AST.lock().unwrap();
        let (a, b, cols, is_real) = input;
        ast.is_equal_word_operation(a, b, cols, is_real);
        drop(ast);

        if !self.modules.contains_key("IsEqualWordOperation") {
            let mut ctx = FuncCtx::new();
            let input_a = Expr::input_arg(&mut ctx);
            let input_b = Expr::input_arg(&mut ctx);
            let input_cols = Expr::input_from_struct::<IsEqualWordOperation<Expr>>(&mut ctx);
            let input_is_real = Expr::input_arg(&mut ctx);

            self.register_module(
                FuncDecl::new(
                    "IsEqualWordOperation",
                    vec![
                        Ty::Expr(input_a),
                        Ty::Expr(input_b),
                        Ty::IsEqualWordOperation(input_cols),
                        Ty::Expr(input_is_real),
                    ],
                    vec![],
                ),
                |body| {
                    IsEqualWordOperation::<F>::lower(body, input);
                },
            );
        }
    }
}

impl SP1OperationBuilder<BitwiseOperation<F>> for ConstraintCompiler {
    fn eval_operation(&mut self, input: <BitwiseOperation<F> as SP1Operation<Self>>::Input) {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.bitwise_operation(input.a, input.b, input.cols, input.opcode, input.is_real);
        drop(ast);

        if !self.modules.contains_key("BitwiseOperation") {
            let mut ctx = FuncCtx::new();
            let input_a = core::array::from_fn(|_| Expr::input_arg(&mut ctx));
            let input_b = core::array::from_fn(|_| Expr::input_arg(&mut ctx));
            let input_cols = Expr::input_from_struct::<BitwiseOperation<Expr>>(&mut ctx);
            let input_opcode = Expr::input_arg(&mut ctx);
            let input_is_real = Expr::input_arg(&mut ctx);
            let func_input = BitwiseOperationInput::<Self>::new(
                input_a,
                input_b,
                input_cols,
                input_opcode,
                input_is_real,
            );

            self.register_module(
                FuncDecl::with_parameter_names(
                    "BitwiseOperation",
                    vec![
                        Ty::ArrWordByteSize(input_a),
                        Ty::ArrWordByteSize(input_b),
                        Ty::BitwiseOperation(input_cols),
                        Ty::Expr(input_opcode),
                        Ty::Expr(input_is_real),
                    ],
                    vec![],
                    BitwiseOperationInput::<Self>::PARAMETER_NAMES,
                ),
                |body| {
                    BitwiseOperation::<F>::lower(body, func_input);
                },
            );
        }
    }
}

impl SP1OperationBuilder<BitwiseU16Operation<F>> for ConstraintCompiler {
    fn eval_operation(
        &mut self,
        input: <BitwiseU16Operation<F> as SP1Operation<Self>>::Input,
    ) -> <BitwiseU16Operation<F> as SP1Operation<Self>>::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        let output =
            ast.bitwise_u16_operation(input.b, input.c, input.cols, input.opcode, input.is_real);
        drop(ast);

        if !self.modules.contains_key("BitwiseU16Operation") {
            let mut ctx = FuncCtx::new();
            let input_b = Word(core::array::from_fn(|_| Expr::input_arg(&mut ctx)));
            let input_c = Word(core::array::from_fn(|_| Expr::input_arg(&mut ctx)));
            let input_cols = Expr::input_from_struct::<BitwiseU16Operation<Expr>>(&mut ctx);
            let input_opcode = Expr::input_arg(&mut ctx);
            let input_is_real = Expr::input_arg(&mut ctx);

            let func_input = BitwiseU16OperationInput::<Self>::new(
                input_b,
                input_c,
                input_cols,
                input_opcode,
                input_is_real,
            );
            let output = Expr::output_from_struct::<Word<Expr>>(&mut ctx);

            self.register_module(
                FuncDecl::with_parameter_names(
                    "BitwiseU16Operation",
                    vec![
                        Ty::Word(input_b),
                        Ty::Word(input_c),
                        Ty::BitwiseU16Operation(input_cols),
                        Ty::Expr(input_opcode),
                        Ty::Expr(input_is_real),
                    ],
                    vec![Ty::Word(output)],
                    BitwiseU16OperationInput::<Self>::PARAMETER_NAMES,
                ),
                |body| {
                    let body_output = BitwiseU16Operation::<F>::lower(body, func_input);
                    for (i, o) in output.0.iter().zip(body_output.0.iter()) {
                        GLOBAL_AST.lock().unwrap().assign(*i, *o);
                    }
                },
            );
        }

        output
    }
}

impl SP1OperationBuilder<U16CompareOperation<F>> for ConstraintCompiler {
    fn eval_operation(
        &mut self,
        input: <U16CompareOperation<F> as SP1Operation<Self>>::Input,
    ) -> <U16CompareOperation<F> as SP1Operation<Self>>::Output {
        GLOBAL_AST.lock().unwrap().u16_compare_operation(
            input.a,
            input.b,
            input.cols,
            input.is_real,
        );

        if !self.modules.contains_key("U16CompareOperation") {
            let mut ctx = FuncCtx::new();
            let input_a = Expr::input_arg(&mut ctx);
            let input_b = Expr::input_arg(&mut ctx);
            let input_cols = Expr::input_from_struct::<U16CompareOperation<Expr>>(&mut ctx);
            let input_is_real = Expr::input_arg(&mut ctx);

            let func_input =
                U16CompareOperationInput::<Self>::new(input_a, input_b, input_cols, input_is_real);

            self.register_module(
                FuncDecl::with_parameter_names(
                    "U16CompareOperation",
                    vec![
                        Ty::Expr(input_a),
                        Ty::Expr(input_b),
                        Ty::U16CompareOperation(input_cols),
                        Ty::Expr(input_is_real),
                    ],
                    vec![],
                    U16CompareOperationInput::<Self>::PARAMETER_NAMES,
                ),
                |body| {
                    U16CompareOperation::<F>::lower(body, func_input);
                },
            );
        }
    }
}

impl SP1OperationBuilder<U16MSBOperation<F>> for ConstraintCompiler {
    fn eval_operation(
        &mut self,
        input: <U16MSBOperation<F> as SP1Operation<Self>>::Input,
    ) -> <U16MSBOperation<F> as SP1Operation<Self>>::Output {
        GLOBAL_AST.lock().unwrap().u16_msb_operation(input.a, input.cols, input.is_real);

        if !self.modules.contains_key("U16MSBOperation") {
            let mut ctx = FuncCtx::new();
            let input_a = Expr::input_arg(&mut ctx);
            let input_cols = Expr::input_from_struct::<U16MSBOperation<Expr>>(&mut ctx);
            let input_is_real = Expr::input_arg(&mut ctx);

            let func_input = U16MSBOperationInput::<Self>::new(input_a, input_cols, input_is_real);

            self.register_module(
                FuncDecl::with_parameter_names(
                    "U16MSBOperation",
                    vec![
                        Ty::Expr(input_a),
                        Ty::U16MSBOperation(input_cols),
                        Ty::Expr(input_is_real),
                    ],
                    vec![],
                    U16MSBOperationInput::<Self>::PARAMETER_NAMES,
                ),
                |body| {
                    U16MSBOperation::<F>::lower(body, func_input);
                },
            );
        }
    }
}

impl SP1OperationBuilder<LtOperationUnsigned<F>> for ConstraintCompiler {
    fn eval_operation(
        &mut self,
        input: <LtOperationUnsigned<F> as SP1Operation<Self>>::Input,
    ) -> <LtOperationUnsigned<F> as SP1Operation<Self>>::Output {
        GLOBAL_AST.lock().unwrap().lt_operation_unsigned(
            input.b,
            input.c,
            input.cols,
            input.is_real,
        );

        if !self.modules.contains_key("LtOperationUnsigned") {
            let mut ctx = FuncCtx::new();
            let input_b = Word([
                Expr::input_arg(&mut ctx),
                Expr::input_arg(&mut ctx),
                Expr::input_arg(&mut ctx),
                Expr::input_arg(&mut ctx),
            ]);
            let input_c = Word([
                Expr::input_arg(&mut ctx),
                Expr::input_arg(&mut ctx),
                Expr::input_arg(&mut ctx),
                Expr::input_arg(&mut ctx),
            ]);
            let input_cols = Expr::input_from_struct::<LtOperationUnsigned<Expr>>(&mut ctx);
            let input_is_real = Expr::input_arg(&mut ctx);

            let func_input =
                LtOperationUnsignedInput::<Self>::new(input_b, input_c, input_cols, input_is_real);

            self.register_module(
                FuncDecl::with_parameter_names(
                    "LtOperationUnsigned",
                    vec![
                        Ty::Word(input_b),
                        Ty::Word(input_c),
                        Ty::LtOperationUnsigned(input_cols),
                        Ty::Expr(input_is_real),
                    ],
                    vec![],
                    LtOperationUnsignedInput::<Self>::PARAMETER_NAMES,
                ),
                |body| {
                    LtOperationUnsigned::<F>::lower(body, func_input);
                },
            );
        }
    }
}

impl SP1OperationBuilder<LtOperationSigned<F>> for ConstraintCompiler {
    fn eval_operation(
        &mut self,
        input: <LtOperationSigned<F> as SP1Operation<Self>>::Input,
    ) -> <LtOperationSigned<F> as SP1Operation<Self>>::Output {
        GLOBAL_AST.lock().unwrap().lt_operation_signed(
            input.b,
            input.c,
            input.cols,
            input.is_signed,
            input.is_real,
        );

        if !self.modules.contains_key("LtOperationSigned") {
            let mut ctx = FuncCtx::new();
            let input_b = Word([
                Expr::input_arg(&mut ctx),
                Expr::input_arg(&mut ctx),
                Expr::input_arg(&mut ctx),
                Expr::input_arg(&mut ctx),
            ]);
            let input_c = Word([
                Expr::input_arg(&mut ctx),
                Expr::input_arg(&mut ctx),
                Expr::input_arg(&mut ctx),
                Expr::input_arg(&mut ctx),
            ]);
            let input_cols = Expr::input_from_struct::<LtOperationSigned<Expr>>(&mut ctx);
            let input_is_signed = Expr::input_arg(&mut ctx);
            let input_is_real = Expr::input_arg(&mut ctx);

            let func_input = LtOperationSignedInput::<Self>::new(
                input_b,
                input_c,
                input_cols,
                input_is_signed,
                input_is_real,
            );

            self.register_module(
                FuncDecl::with_parameter_names(
                    "LtOperationSigned",
                    vec![
                        Ty::Word(input_b),
                        Ty::Word(input_c),
                        Ty::LtOperationSigned(input_cols),
                        Ty::Expr(input_is_signed),
                        Ty::Expr(input_is_real),
                    ],
                    vec![],
                    LtOperationSignedInput::<Self>::PARAMETER_NAMES,
                ),
                |body| {
                    LtOperationSigned::<F>::lower(body, func_input);
                },
            );
        }
    }
}

impl SP1OperationBuilder<RTypeReader<F>> for ConstraintCompiler {
    fn eval_operation(&mut self, input: RTypeReaderInput<Self, Expr>) {
        GLOBAL_AST.lock().unwrap().r_type_reader(
            input.clk_high,
            input.clk_low,
            input.pc,
            input.opcode,
            input.op_a_write_value,
            input.cols,
            input.is_real,
        );

        if !self.modules.contains_key("RTypeReader") {
            let mut ctx = FuncCtx::new();

            let input_shard = Expr::input_arg(&mut ctx);
            let input_clk = Expr::input_arg(&mut ctx);
            let input_pc =
                [Expr::input_arg(&mut ctx), Expr::input_arg(&mut ctx), Expr::input_arg(&mut ctx)];
            let input_opcode = Expr::input_arg(&mut ctx);
            let input_op_a_write_value = Expr::input_from_struct::<Word<Expr>>(&mut ctx);
            let input_cols = Expr::input_from_struct::<RTypeReader<Expr>>(&mut ctx);
            let input_is_real = Expr::input_arg(&mut ctx);

            let func_input = RTypeReaderInput::<Self, Expr>::new(
                input_shard,
                input_clk,
                input_pc,
                input_opcode,
                input_op_a_write_value,
                input_cols,
                input_is_real,
            );

            self.register_module(
                FuncDecl::with_parameter_names(
                    "RTypeReader",
                    vec![
                        Ty::Expr(input_shard),
                        Ty::Expr(input_clk),
                        Ty::ArrAddressSize(input_pc),
                        Ty::Expr(input_opcode),
                        Ty::Word(input_op_a_write_value),
                        Ty::RTypeReader(input_cols),
                        Ty::Expr(input_is_real),
                    ],
                    vec![],
                    RTypeReaderInput::<Self, Expr>::PARAMETER_NAMES,
                ),
                |body| {
                    RTypeReader::<F>::lower(body, func_input);
                },
            );
        }
    }
}

impl SP1OperationBuilder<RTypeReaderImmutable> for ConstraintCompiler {
    fn eval_operation(&mut self, input: <RTypeReaderImmutable as SP1Operation<Self>>::Input) {
        GLOBAL_AST.lock().unwrap().r_type_reader_immutable(
            input.clk_high,
            input.clk_low,
            input.pc,
            input.opcode,
            input.cols,
            input.is_real,
        );

        if !self.modules.contains_key("RTypeReader") {
            let mut ctx = FuncCtx::new();

            let input_shard = Expr::input_arg(&mut ctx);
            let input_clk = Expr::input_arg(&mut ctx);
            let input_pc =
                [Expr::input_arg(&mut ctx), Expr::input_arg(&mut ctx), Expr::input_arg(&mut ctx)];
            let input_opcode = Expr::input_arg(&mut ctx);
            let input_cols = Expr::input_from_struct::<RTypeReader<Expr>>(&mut ctx);
            let input_is_real = Expr::input_arg(&mut ctx);

            let func_input = RTypeReaderImmutableInput::<Self>::new(
                input_shard,
                input_clk,
                input_pc,
                input_opcode,
                input_cols,
                input_is_real,
            );

            self.register_module(
                FuncDecl::with_parameter_names(
                    "RTypeReader",
                    vec![
                        Ty::Expr(input_shard),
                        Ty::Expr(input_clk),
                        Ty::ArrAddressSize(input_pc),
                        Ty::Expr(input_opcode),
                        Ty::RTypeReader(input_cols),
                        Ty::Expr(input_is_real),
                    ],
                    vec![],
                    RTypeReaderImmutableInput::<Self>::PARAMETER_NAMES,
                ),
                |body| {
                    RTypeReaderImmutable::lower(body, func_input);
                },
            );
        }
    }
}

impl SP1OperationBuilder<CPUState<F>> for ConstraintCompiler {
    fn eval_operation(&mut self, input: CPUStateInput<Self>) {
        GLOBAL_AST.lock().unwrap().cpu_state(
            input.cols,
            input.next_pc,
            input.clk_increment,
            input.is_real,
        );

        if !self.modules.contains_key("CPUState") {
            let mut ctx = FuncCtx::new();

            let input_cols = Expr::input_from_struct::<CPUState<Expr>>(&mut ctx);
            let input_next_pc =
                [Expr::input_arg(&mut ctx), Expr::input_arg(&mut ctx), Expr::input_arg(&mut ctx)];
            let input_clk_increment = Expr::input_arg(&mut ctx);
            let input_is_real = Expr::input_arg(&mut ctx);

            let func_input = CPUStateInput::<Self>::new(
                input_cols,
                input_next_pc,
                input_clk_increment,
                input_is_real,
            );

            self.register_module(
                FuncDecl::with_parameter_names(
                    "CPUState",
                    vec![
                        Ty::CPUState(input_cols),
                        Ty::ArrAddressSize(input_next_pc),
                        Ty::Expr(input_clk_increment),
                        Ty::Expr(input_is_real),
                    ],
                    vec![],
                    CPUStateInput::<Self>::PARAMETER_NAMES,
                ),
                |body| {
                    CPUState::<F>::lower(body, func_input);
                },
            );
        }
    }
}

impl SP1OperationBuilder<ALUTypeReader<F>> for ConstraintCompiler {
    fn eval_operation(&mut self, input: ALUTypeReaderInput<Self, Expr>) {
        GLOBAL_AST.lock().unwrap().alu_type_reader(
            input.clk_high,
            input.clk_low,
            input.pc,
            input.opcode,
            input.op_a_write_value,
            input.cols,
            input.is_real,
        );

        if !self.modules.contains_key("ALUTypeReader") {
            let mut ctx = FuncCtx::new();

            let input_clk_high = Expr::input_arg(&mut ctx);
            let input_clk_low = Expr::input_arg(&mut ctx);
            let input_pc =
                [Expr::input_arg(&mut ctx), Expr::input_arg(&mut ctx), Expr::input_arg(&mut ctx)];
            let input_opcode = Expr::input_arg(&mut ctx);
            let input_op_a_write_value = Expr::input_from_struct::<Word<Expr>>(&mut ctx);
            let input_cols = Expr::input_from_struct::<ALUTypeReader<Expr>>(&mut ctx);
            let input_is_real = Expr::input_arg(&mut ctx);

            let func_input = ALUTypeReaderInput::<Self, Expr>::new(
                input_clk_high,
                input_clk_low,
                input_pc,
                input_opcode,
                input_op_a_write_value,
                input_cols,
                input_is_real,
            );

            self.register_module(
                FuncDecl::with_parameter_names(
                    "ALUTypeReader",
                    vec![
                        Ty::Expr(input_clk_high),
                        Ty::Expr(input_clk_low),
                        Ty::ArrAddressSize(input_pc),
                        Ty::Expr(input_opcode),
                        Ty::Word(input_op_a_write_value),
                        Ty::ALUTypeReader(input_cols),
                        Ty::Expr(input_is_real),
                    ],
                    vec![],
                    ALUTypeReaderInput::<Self, Expr>::PARAMETER_NAMES,
                ),
                |body| {
                    ALUTypeReader::<F>::lower(body, func_input);
                },
            );
        }
    }
}
