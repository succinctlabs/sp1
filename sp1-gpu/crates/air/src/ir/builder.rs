//! `DagBuilder` and the trait implementations needed to drive a chip's `eval`.
//!
//! `DagBuilder` holds matrix views and a constraint counter, and defers actual
//! node allocation to the global DAG state. The trait impls (`AirBuilder`,
//! `ExtensionBuilder`, etc.) carry `unimplemented!()` stubs for the builder
//! methods SP1 chips don't use (transition windows, permutation columns).

use slop_air::{
    Air, AirBuilder, AirBuilderWithPublicValues, ExtensionBuilder, PairBuilder,
    PermutationAirBuilder,
};
use slop_matrix::dense::{DenseMatrix, RowMajorMatrixView};

use sp1_core_machine::air::TrivialOperationBuilder;
use sp1_hypercube::air::{EmptyMessageBuilder, MachineAir};
use sp1_hypercube::{AirOpenedValues, PROOF_MAX_NUM_PVS};

use crate::ir::dag::{ConstraintDag, ConstraintField, ConstraintRef};
use crate::ir::expr::{DagExprEF, DagExprF};
use crate::ir::state::{with_state, DAG_BUILDER_LOCK, DAG_STATE};
use crate::ir::var::{DagVarEF, DagVarF};
use crate::{EF, F};

/// Drives a chip's `eval` for the DAG-native path.
///
/// Holds the matrix views the chip's `eval` will read (constructed before the
/// folder is built) and a per-folder constraint counter. All node allocation
/// flows through the global `DAG_STATE`.
pub struct DagBuilder<'a> {
    pub preprocessed: RowMajorMatrixView<'a, DagVarF>,
    pub main: RowMajorMatrixView<'a, DagVarF>,
    pub public_values: &'a [DagVarF],
    pub num_constraints: u32,
}

impl<'a> AirBuilder for DagBuilder<'a> {
    type F = F;
    type Expr = DagExprF;
    type Var = DagVarF;
    type M = RowMajorMatrixView<'a, DagVarF>;

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
        let alpha_index = self.num_constraints;
        with_state(|s| {
            s.constraints.push(ConstraintRef {
                root: x.0,
                alpha_index,
                field: ConstraintField::Base,
            });
        });
        self.num_constraints += 1;
    }
}

impl ExtensionBuilder for DagBuilder<'_> {
    type EF = EF;
    type ExprEF = DagExprEF;
    type VarEF = DagVarEF;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        let x: Self::ExprEF = x.into();
        let alpha_index = self.num_constraints;
        with_state(|s| {
            s.constraints.push(ConstraintRef {
                root: x.0,
                alpha_index,
                field: ConstraintField::Extension,
            });
        });
        self.num_constraints += 1;
    }
}

impl<'a> PermutationAirBuilder for DagBuilder<'a> {
    type MP = RowMajorMatrixView<'a, DagVarEF>;
    type RandomVar = DagVarEF;

    fn permutation(&self) -> Self::MP {
        unimplemented!();
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        unimplemented!();
    }
}

impl PairBuilder for DagBuilder<'_> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

impl AirBuilderWithPublicValues for DagBuilder<'_> {
    type PublicVar = DagVarF;

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}

impl EmptyMessageBuilder for DagBuilder<'_> {}

impl TrivialOperationBuilder for DagBuilder<'_> {}

// ============================================================================
// Entry point
// ============================================================================

/// Run a chip's `eval` against the DAG-native builder and return the resulting
/// `ConstraintDag`.
///
/// Acquires the global guard, resets state, runs `eval` once (auto-chunking
/// partitions the DAG downstream), snapshots the state, and releases.
pub fn build_dag<A>(air: &A) -> ConstraintDag
where
    A: MachineAir<F> + for<'a> Air<DagBuilder<'a>>,
{
    let _guard = DAG_BUILDER_LOCK.lock().unwrap();

    // Reset before we begin.
    {
        let mut state = DAG_STATE.lock().unwrap();
        state.reset();
    }

    let preprocessed_width = air.preprocessed_width() as u32;
    let main_width = air.width() as u32;

    // Eagerly intern all preprocessed and main column refs. Chip `eval`
    // reads them through the matrix view.
    let prep_vars: Vec<DagVarF> =
        (0..preprocessed_width).map(DagVarF::preprocessed_local).collect();
    let main_vars: Vec<DagVarF> = (0..main_width).map(DagVarF::main_local).collect();
    let public_values: Vec<DagVarF> =
        (0..PROOF_MAX_NUM_PVS as u32).map(DagVarF::public_value).collect();

    let prep_matrix = DenseMatrix::new(prep_vars, preprocessed_width.max(1) as usize);
    let main_matrix = DenseMatrix::new(main_vars, main_width.max(1) as usize);
    let preprocessed_view = AirOpenedValues { local: prep_matrix.values.clone() };
    let main_view = AirOpenedValues { local: main_matrix.values.clone() };

    let mut folder = DagBuilder {
        preprocessed: preprocessed_view.view(),
        main: main_view.view(),
        public_values: &public_values,
        num_constraints: 0,
    };

    air.eval(&mut folder);

    // Snapshot.
    let (nodes, constraints) = {
        let mut state = DAG_STATE.lock().unwrap();
        let nodes = std::mem::take(&mut state.nodes);
        let constraints = std::mem::take(&mut state.constraints);
        state.reset();
        (nodes, constraints)
    };

    ConstraintDag { nodes, constraints, preprocessed_width, main_width }
}
