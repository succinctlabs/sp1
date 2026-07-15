use std::collections::BTreeMap;

use crate::{
    air::{AirInteraction, InteractionScope, MachineAir, MessageBuilder},
    ir::{Ast, Attribute, ExprExtRef, ExprRef, Func, Shape, GLOBAL_AST},
};
use slop_air::{
    AirBuilder, AirBuilderWithPublicValues, ExtensionBuilder, GlobalBuilder, PairBuilder,
};
use slop_matrix::dense::RowMajorMatrix;

use crate::ir::expr_impl::{Expr, ExprExt, EF, F};

/// The constraint compiler that records the constraints of a chip.
#[derive(Clone, Debug)]
pub struct ConstraintCompiler {
    public_values: Vec<Expr>,
    preprocessed: RowMajorMatrix<Expr>,
    global: RowMajorMatrix<Expr>,
    main: RowMajorMatrix<Expr>,
    modules: BTreeMap<String, Func<Expr, ExprExt>>,
    parent: Option<Ast<ExprRef<F>, ExprExtRef<EF>>>,
}

impl ConstraintCompiler {
    /// Creates a new [`ConstraintCompiler`]
    pub fn new<A: MachineAir<F>>(air: &A, num_public_values: usize) -> Self {
        let preprocessed_width = air.preprocessed_width();
        let global_width = air.global_width();
        let main_width = air.width();
        Self::with_sizes(num_public_values, preprocessed_width, global_width, main_width)
    }

    /// Creates a new [`ConstraintCompiler`] with specific dimensions.
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

    /// Returns the currently recorded AST.
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

    /// Records a module (that is usually just a function call that represents an operation).
    pub fn register_module(
        &mut self,
        name: String,
        params: Vec<(String, Attribute, Shape<ExprRef<F>, ExprExtRef<EF>>)>,
        body: impl FnOnce(&mut Self) -> Shape<ExprRef<F>, ExprExtRef<EF>>,
    ) {
        let mut body_builder = self.region();
        let result = body(&mut body_builder);
        let body = body_builder.ast();

        let decl = crate::ir::FuncDecl::new(name.clone(), params, result);
        self.modules.append(&mut body_builder.modules);
        self.modules.insert(name, Func { decl, body });
    }

    /// The modules that has been recorded.
    #[must_use]
    pub fn modules(&self) -> &BTreeMap<String, Func<Expr, ExprExt>> {
        &self.modules
    }

    /// The total number of cols of the chip.
    #[must_use]
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

impl ExtensionBuilder for ConstraintCompiler {
    type EF = EF;
    type ExprEF = ExprExt;
    type VarEF = ExprExt;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        let x = x.into();
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.assert_ext_zero(x);
    }
}
