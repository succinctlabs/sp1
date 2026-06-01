use std::{collections::HashMap, fmt::Display};

use serde::{Deserialize, Serialize};
use slop_algebra::{ExtensionField, Field};

use crate::ir::{Ast, ExprExtRef, ExprRef, Shape};

/// Whether a parameter to a function is an input to a deterministic output, or if that parameter
/// itself should be considered a deterministic output.
///
/// This is used only for the Picus determinisim checker, hence its name.
#[derive(Default, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PicusArg {
    /// Input to deterministic outputs.
    Input,
    /// A determinstic output.
    Output,
    /// Doesn't influence the result. `builder` falls into this category.
    #[default]
    Unknown,
}

/// Attributes of function input parameters
#[derive(Default, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Attribute {
    /// Whether the parameter is a deterministic output or an input to deterministic outputs. Used
    /// only for the Picus determinism checker, hence its name.
    pub picus: PicusArg,
}

impl Display for Attribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.picus {
            PicusArg::Input => write!(f, "#[picus(input)]"),
            PicusArg::Output => write!(f, "#[picus(output)]"),
            PicusArg::Unknown => Ok(()),
        }
    }
}

/// Represents the "shape" of a function. It only contains the name, input shape, and output shape
/// of the function, disregarding what the function actually constraints/computes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuncDecl<Expr, ExprExt> {
    /// The name of the function call, which is usually the operation name.
    pub name: String,
    /// The names and the shapes of the input arguments.
    pub input: Vec<(String, Attribute, Shape<Expr, ExprExt>)>,
    /// The shape of the output.
    pub output: Shape<Expr, ExprExt>,
}

impl<Expr, ExprExt> FuncDecl<Expr, ExprExt> {
    /// Crates a new [`FuncDecl`].
    pub fn new(
        name: String,
        input: Vec<(String, Attribute, Shape<Expr, ExprExt>)>,
        output: Shape<Expr, ExprExt>,
    ) -> Self {
        Self { name, input, output }
    }
}

impl<F: Field, EF: ExtensionField<F>> FuncDecl<ExprRef<F>, ExprExtRef<EF>> {
    /// A flattened list of the struct representing the position of Input(x) index.
    pub fn input_mapping(&self) -> HashMap<usize, String> {
        let mut mapping = HashMap::new();
        for (name, _, arg) in &self.input {
            arg.map_input(name.clone(), &mut mapping);
        }
        mapping
    }

    /// The function output's corresponding Lean type in sp1-lean.
    pub fn to_output_lean_type(&self) -> String {
        match self.output {
            Shape::Unit => "SP1Constraints F".to_string(),
            _ => format!("{} × SP1Constraints F", self.output.to_lean_type()),
        }
    }
}

/// Represents a function, containing its name, input/output shapes, and its body [Ast].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Func<Expr, ExprExt> {
    /// The shape of the function. See [`FuncDecl`] for more details.
    pub decl: FuncDecl<Expr, ExprExt>,
    /// The body of the [Func], representing the computations performed and the constraints
    /// asserted by this function.
    pub body: Ast<Expr, ExprExt>,
}

impl<F: Field, EF: ExtensionField<F>> Display for Func<ExprRef<F>, ExprExtRef<EF>> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "fn {}(", self.decl.name)?;
        for (i, (name, attr, inp)) in self.decl.input.iter().enumerate() {
            // Print attribute if it's not Unknown
            match attr.picus {
                PicusArg::Unknown => write!(f, "    {name}: {inp:?}")?,
                _ => write!(f, "    {attr} {name}: {inp:?}")?,
            }
            if i < self.decl.input.len() - 1 {
                writeln!(f, ",")?;
            }
        }
        write!(f, ")")?;
        match self.decl.output {
            Shape::Unit => {}
            _ => write!(f, " -> {:?}", self.decl.output)?,
        }
        writeln!(f, " {{")?;
        write!(f, "{}", self.body.to_string_pretty("   "))?;
        writeln!(f, "}}")
    }
}
