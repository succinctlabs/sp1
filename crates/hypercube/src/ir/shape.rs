use serde::{Deserialize, Serialize};
use sp1_primitives::consts::WORD_SIZE;

/// Shapes of input type to `SP1Operation`
///
/// More like poor man's `facet::Facet`...
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Shape<Expr, ExprExt> {
    /// A unit type. This should only be used for representing Output shapes.
    Unit,
    /// An arithmetic expression.
    Expr(Expr),
    /// An arithmetic expression over the extension field.
    ExprExt(ExprExt),
    /// A word in the base field.
    Word([Expr; WORD_SIZE]),
    /// An array of shapes of arbitrary size.
    Array(Vec<Box<Shape<Expr, ExprExt>>>),
    /// A flexible struct type that can represent nested structures.
    /// Contains the struct name and a vector of (`field_name`, `field_shape`) pairs.
    Struct(String, Vec<(String, Box<Shape<Expr, ExprExt>>)>),
}

impl<Expr, ExprExt> Shape<Expr, ExprExt> {
    /// Converts the shape to its corresponding Lean type.
    ///
    /// SAFETY: all elements of [`Shape::Array`] must have the same shape. We use the first item as
    /// the shape.
    ///
    /// SAFETY: [`Shape::Array`] must be non-empty.
    pub fn to_lean_type(&self) -> String {
        match self {
            Shape::Unit => "Unit".to_string(),
            Shape::Expr(_) => "F".to_string(),
            Shape::ExprExt(_) => todo!("extension field not implemented yet"),
            Shape::Word(_) => "(Word F)".to_string(),
            Shape::Array(elems) => {
                format!("(Vector {} {})", elems.first().unwrap().to_lean_type(), elems.len())
            }
            Shape::Struct(name, _) => format!("{name} F"),
        }
    }
}
