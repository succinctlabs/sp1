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
            // Structs are field-generic in the clean-native output (`structure Foo (F : Type)`).
            Shape::Struct(name, _) => format!("({name} F)"),
        }
    }

    /// Collect the Lean `structure` definitions for this shape and any nested struct shapes,
    /// emitting nested structs *before* the structs that contain them and de-duplicating by
    /// name. Each pushed entry is `(name, full_structure_block)`. Used so the generated
    /// operation module is self-contained (struct definition(s) + constraints).
    pub fn collect_lean_struct_defs(&self, out: &mut Vec<(String, String)>) {
        match self {
            Shape::Struct(name, fields) => {
                for (_, field) in fields {
                    field.collect_lean_struct_defs(out);
                }
                if out.iter().any(|(n, _)| n == name) {
                    return;
                }
                let mut def = format!("structure {name} (F : Type) where\n");
                for (field_name, field) in fields {
                    def.push_str(&format!("  {field_name} : {}\n", field.to_lean_type()));
                }
                // Derive `ProvableStruct` so the column struct can serve as a Clean circuit
                // output/column type (the witnessed gadget returns `⟨…⟩ : Var (Foo F)`).
                def.push_str("deriving ProvableStruct\n");
                out.push((name.clone(), def));
            }
            Shape::Array(elems) => {
                for e in elems {
                    e.collect_lean_struct_defs(out);
                }
            }
            _ => {}
        }
    }
}
