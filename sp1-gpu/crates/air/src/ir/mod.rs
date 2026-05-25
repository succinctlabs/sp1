//! DAG-native AIR constraint IR.
//!
//! Each chip's `eval` produces a single `ConstraintDag` with explicit
//! cross-constraint sharing, which is then chunked, lowered, and compiled to
//! flat bytecode that the fused zerocheck kernels interpret.
//!
//! Entry point: [`builder::build_dag`].

pub mod analysis;
pub mod builder;
pub mod bytecode;
pub mod chunker;
pub mod column_tile_bytecode;
pub mod dag;
pub mod expr;
pub mod lowering;
mod state;
pub mod var;

pub use analysis::{analyze_constraints, ColumnLeaf, ConstraintInfo, ConstraintShape};
pub use builder::{build_dag, DagBuilder};
pub use bytecode::{lower_sequential, BcOp, ChunkBytecode, DagInstr, LeafRef};
pub use chunker::{chunk_dag, Chunk, ChunkBudget};
pub use column_tile_bytecode::{
    lower_column_tile, ColumnTermEntry, ColumnTileBytecode, COEFF_KIND_CONST, COEFF_KIND_MASK,
    COEFF_KIND_PUBLIC, COEFF_NEGATE_BIT,
};
pub use dag::{ConstraintDag, ConstraintRef, DagNode, NodeId, TraceSource};
pub use expr::{DagExprEF, DagExprF};
pub use lowering::{
    enumerate_lowerings, ColumnTilePlan, ColumnTilePlanTerm, Lowering, SequentialPlan,
};
pub use var::{DagVarEF, DagVarF};
