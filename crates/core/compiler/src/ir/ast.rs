use std::{
    borrow::Borrow,
    collections::HashMap,
    fmt::{Debug, Display},
};

use serde::{Deserialize, Serialize};
use sp1_hypercube::{
    air::{AirInteraction, InteractionScope},
    InteractionKind, Word,
};
use sp1_primitives::consts::{WORD_BYTE_SIZE, WORD_SIZE};

use slop_algebra::{ExtensionField, Field};

use sp1_core_machine::{
    adapter::{
        register::{alu_type::ALUTypeReader, r_type::RTypeReader},
        state::CPUState,
    },
    memory::{RegisterAccessCols, RegisterAccessTimestamp},
    operations::{
        AddOperation, AddressOperation, BitwiseOperation, BitwiseU16Operation,
        IsEqualWordOperation, IsZeroOperation, IsZeroWordOperation, LtOperationSigned,
        LtOperationUnsigned, SubOperation, U16CompareOperation, U16MSBOperation, U16toU8Operation,
    },
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum IrVar<F> {
    Public(usize),
    Preprocessed(usize),
    Main(usize),
    Constant(F),
    /// Symbolic inverse of a small canonical-u32 base. Mirrors the variant in
    /// `crates/hypercube/src/ir/var.rs` so this parallel AST tree stays in
    /// sync; Lean emission for both renders `((base : Fin KB)⁻¹)`.
    InverseConstant {
        /// The pre-image — Lean emission writes `(base : Fin KB)⁻¹`.
        base: u32,
        /// The eagerly-computed inverse field element.
        value: F,
    },
    InputArg(usize),
    OutputArg(usize),
}

impl<F: Field> Display for IrVar<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IrVar::Public(i) => write!(f, "Public({i})"),
            IrVar::Preprocessed(i) => write!(f, "Preprocessed({i})"),
            IrVar::Main(i) => write!(f, "Main({i})"),
            IrVar::Constant(c) => write!(f, "{c}"),
            IrVar::InverseConstant { base, .. } => write!(f, "({base} : Fin KB)⁻¹"),
            IrVar::InputArg(i) => write!(f, "Input({i})"),
            IrVar::OutputArg(i) => write!(f, "Output({i})"),
        }
    }
}

impl<F: Field> IrVar<F> {
    /// Convert to Lean syntax based on context (chip vs operation)
    pub fn to_lean(&self, is_operation: bool, input_mapping: &HashMap<usize, String>) -> String {
        match self {
            IrVar::Main(i) => format!("Main[{i}]"),
            IrVar::InputArg(i) => {
                if is_operation {
                    input_mapping.get(i).map_or(format!("I[{i}]"), |s| s.clone())
                } else {
                    // In chip context, InputArg shouldn't appear
                    format!("InputArg({i})")
                }
            }
            IrVar::Constant(c) => format!("{c}"),
            IrVar::InverseConstant { base, .. } => format!("(({base} : Fin KB)⁻¹)"),
            IrVar::Public(i) => format!("Public[{i}]"),
            IrVar::Preprocessed(i) => format!("Preprocessed[{i}]"),
            IrVar::OutputArg(i) => format!("Output[{i}]"),
        }
    }
}

pub struct FuncCtx {
    input_idx: usize,
    output_idx: usize,
}

impl FuncCtx {
    pub fn new() -> Self {
        Self { input_idx: 0, output_idx: 0 }
    }
}

impl Default for FuncCtx {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ExprRef<F> {
    IrVar(IrVar<F>),
    Expr(usize),
}

impl<F: Field> ExprRef<F> {
    /// An expression representing a variable from public inputs.
    pub fn public(index: usize) -> Self {
        ExprRef::IrVar(IrVar::Public(index))
    }

    /// An expression representing a variable from preprocessed trace.
    pub fn preprocessed(index: usize) -> Self {
        ExprRef::IrVar(IrVar::Preprocessed(index))
    }

    /// An expression representing a variable from main trace.
    pub fn main(index: usize) -> Self {
        ExprRef::IrVar(IrVar::Main(index))
    }

    /// An expression representing a constant value.
    pub fn constant(value: F) -> Self {
        ExprRef::IrVar(IrVar::Constant(value))
    }

    /// An expression representing a variable from input arguments.
    pub fn input_arg(ctx: &mut FuncCtx) -> Self {
        let index = ctx.input_idx;
        ctx.input_idx += 1;
        ExprRef::IrVar(IrVar::InputArg(index))
    }

    /// Get a struct with input arguments.
    ///
    /// Given a sized struct that can be flattened to a slice of `Self`, produce a new struct of
    /// this type where all the fields are replaced with input arguments.
    pub fn input_from_struct<T>(ctx: &mut FuncCtx) -> T
    where
        T: Copy,
        [Self]: Borrow<T>,
    {
        let size = std::mem::size_of::<T>() / std::mem::size_of::<Self>();
        let values = (0..size).map(|_| Self::input_arg(ctx)).collect::<Vec<_>>();
        let value_ref: &T = values.as_slice().borrow();
        *value_ref
    }

    /// An expression representing a variable from output arguments.
    pub fn output_arg(ctx: &mut FuncCtx) -> Self {
        let index = ctx.output_idx;
        ctx.output_idx += 1;
        ExprRef::IrVar(IrVar::OutputArg(index))
    }

    /// Get a struct with output arguments.
    ///
    /// Given a sized struct that can be flattened to a slice of `Self`, produce a new struct of
    /// this type where all the fields are replaced with output arguments.
    pub fn output_from_struct<T>(ctx: &mut FuncCtx) -> T
    where
        T: Copy,
        [Self]: Borrow<T>,
    {
        let size = std::mem::size_of::<T>() / std::mem::size_of::<Self>();
        let values = (0..size).map(|_| Self::output_arg(ctx)).collect::<Vec<_>>();
        let value_ref: &T = values.as_slice().borrow();
        *value_ref
    }
}

impl<F: Field> Display for ExprRef<F> {
    #[allow(clippy::uninlined_format_args)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExprRef::IrVar(ir_var) => write!(f, "{}", ir_var),
            ExprRef::Expr(expr) => write!(f, "Expr({})", expr),
        }
    }
}

impl<F: Field> ExprRef<F> {
    /// Convert to Lean syntax
    pub fn to_lean(&self, is_operation: bool, input_mapping: &HashMap<usize, String>) -> String {
        match self {
            ExprRef::IrVar(var) => var.to_lean(is_operation, input_mapping),
            ExprRef::Expr(i) => format!("E{i}"),
        }
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ExprExtRef<EF> {
    ExtConstant(EF),
    Expr(usize),
}

impl<EF: Field> ExprExtRef<EF> {
    /// An expression representing a variable from input arguments.
    pub fn input_arg(ctx: &mut FuncCtx) -> Self {
        let index = ctx.input_idx;
        ctx.input_idx += 1;
        ExprExtRef::Expr(index)
    }

    /// An expression representing a variable from output arguments.
    pub fn output_arg(ctx: &mut FuncCtx) -> Self {
        let index = ctx.output_idx;
        ctx.output_idx += 1;
        ExprExtRef::Expr(index)
    }
}

impl<EF: Field> Display for ExprExtRef<EF> {
    #[allow(clippy::uninlined_format_args)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExprExtRef::ExtConstant(ext_constant) => write!(f, "{ext_constant}"),
            ExprExtRef::Expr(expr) => write!(f, "ExprExt({})", expr),
        }
    }
}

impl<EF: Field> ExprExtRef<EF> {
    /// Convert to Lean syntax
    pub fn to_lean(&self, _is_operation: bool, _input_mapping: &HashMap<usize, String>) -> String {
        match self {
            ExprExtRef::ExtConstant(c) => format!("{c}"),
            ExprExtRef::Expr(i) => format!("EExt{i}"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuncDecl<Expr, ExprExt> {
    pub name: String,
    pub input: Vec<Ty<Expr, ExprExt>>,
    pub output: Vec<Ty<Expr, ExprExt>>,
    // This is an `Option` because I don't want to spend time fixing the
    // remaining 15 operations. Once we macro-generate this, this should be
    // required.
    pub parameter_names: Option<Vec<String>>,
}

impl<Expr, ExprExt> FuncDecl<Expr, ExprExt> {
    pub fn new(name: &str, input: Vec<Ty<Expr, ExprExt>>, output: Vec<Ty<Expr, ExprExt>>) -> Self {
        Self { name: name.to_string(), input, output, parameter_names: None }
    }

    pub fn with_parameter_names(
        name: &str,
        input: Vec<Ty<Expr, ExprExt>>,
        output: Vec<Ty<Expr, ExprExt>>,
        parameter_names: &[&str],
    ) -> Self {
        Self {
            name: name.to_string(),
            input,
            output,
            parameter_names: Some(parameter_names.iter().map(|s| s.to_string()).collect()),
        }
    }
}

fn extract_expr(val: &serde_json::Value) -> Option<String> {
    match val {
        serde_json::Value::Object(obj) if obj.len() == 1 => {
            if let Some(val) = obj.get("Expr") {
                match val {
                    serde_json::Value::Number(idx) => {
                        let i: usize = idx.as_u64().unwrap() as usize;
                        Some(format!("E{i}"))
                    }
                    _ => None,
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

fn extract_output(val: &serde_json::Value) -> Option<String> {
    match val {
        serde_json::Value::Object(obj) if obj.len() == 1 => {
            if let Some(var) = obj.get("IrVar") {
                match var {
                    serde_json::Value::Object(obj) if obj.len() == 1 => {
                        if let Some(val) = obj.get("OutputArg") {
                            match val {
                                serde_json::Value::Number(idx) => {
                                    let i: usize = idx.as_u64().unwrap() as usize;
                                    Some(format!("E{i}"))
                                }
                                _ => None,
                            }
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

impl<Expr, ExprExt> FuncDecl<Expr, ExprExt>
where
    Expr: Debug + Serialize,
    ExprExt: Debug + Serialize,
{
    #[allow(clippy::uninlined_format_args)]
    fn traverse(val: &serde_json::Value, m: &HashMap<usize, String>) -> String {
        match val {
            serde_json::Value::Object(map) => {
                if let Some(irval) = map.get("IrVar") {
                    assert_eq!(map.len(), 1);
                    if let Some(serde_json::Value::Number(idx)) = irval.get("InputArg") {
                        let i: usize = idx.as_u64().unwrap() as usize;
                        m.get(&i).map_or(format!("I[{i}]"), |s| s.clone())
                    } else if let Some(serde_json::Value::Number(idx)) = irval.get("Main") {
                        let i: usize = idx.as_u64().unwrap() as usize;
                        format!("Main[{i}]")
                    } else if let Some(serde_json::Value::Number(idx)) = irval.get("Constant") {
                        let i: usize = idx.as_u64().unwrap() as usize;
                        format!("{i}")
                    } else {
                        eprintln!("{:?}", val);
                        unimplemented!()
                    }
                } else if let Some(expr) = map.get("Expr") {
                    match expr {
                        serde_json::Value::Number(idx) => {
                            let i: usize = idx.as_u64().unwrap() as usize;
                            format!("E{i}")
                        }
                        _ => unimplemented!(),
                    }
                } else {
                    let mut res = "{ ".to_string();

                    for (i, (field_name, field_val)) in map.iter().enumerate() {
                        res.push_str(&format!(
                            "{} := {}",
                            field_name,
                            &Self::traverse(field_val, m)
                        ));
                        if i + 1 < map.len() {
                            res.push_str(", ");
                        }
                    }

                    res.push_str(" }");
                    res
                }
            }
            serde_json::Value::Array(lst) => {
                let mut res = "#v[".to_string();

                for (i, val) in lst.iter().enumerate() {
                    res.push_str(&Self::traverse(val, m));
                    if i + 1 < lst.len() {
                        res.push_str(", ");
                    }
                }

                res.push(']');
                res
            }
            _ => {
                eprintln!("Unhandled value: {}", val);
                unimplemented!()
            }
        }
    }

    // this is more like fun calls
    pub fn to_lean_call(&self, m: &HashMap<usize, String>) -> String {
        let mut res = format!("{}.constraints", self.name);

        match serde_json::to_value(&self.input).unwrap() {
            serde_json::Value::Array(args) => {
                for arg in args {
                    match arg {
                        serde_json::Value::Object(obj) if obj.len() == 1 => {
                            let obj_val = obj.into_values().next().unwrap();
                            res.push_str(&format!(" {}", Self::traverse(&obj_val, m)));
                        }
                        _ => unimplemented!(),
                    }
                }
            }
            _ => unimplemented!(),
        }

        res
    }

    pub fn to_lean_output(&self, is_construct: bool) -> String {
        let mut res = String::new();

        assert_eq!(self.output.len(), 1);

        let out = self.output.first().unwrap();
        match serde_json::to_value(out).unwrap() {
            serde_json::Value::Object(obj) if obj.len() == 1 => {
                if let Some(expr) = obj.get("Expr") {
                    match expr {
                        serde_json::Value::Number(idx) => {
                            let i: usize = idx.as_u64().unwrap() as usize;
                            res.push_str(&format!("E{i}"));
                        }
                        _ => unimplemented!(),
                    }
                }
                if let Some(lst) =
                    obj.get("Word").or(obj.get("ArrWordByteSize")).or(obj.get("ArrWordSize"))
                {
                    match lst {
                        serde_json::Value::Array(elems) => {
                            if is_construct {
                                res.push_str("#v[");
                                for (i, expr) in elems.iter().enumerate() {
                                    res.push_str(&extract_output(expr).unwrap());
                                    if i + 1 < elems.len() {
                                        res.push_str(", ");
                                    }
                                }
                                res.push(']');
                            } else {
                                res.push_str("⟨⟨[");
                                for (i, expr) in elems.iter().enumerate() {
                                    res.push_str(&extract_expr(expr).unwrap());
                                    if i + 1 < elems.len() {
                                        res.push_str(", ");
                                    }
                                }
                                res.push_str("]⟩, _⟩");
                            }
                        }
                        _ => unimplemented!(),
                    }
                } else {
                    unimplemented!()
                }
            }
            _ => unimplemented!(),
        }

        res
    }

    pub fn to_output_lean_type(&self) -> String {
        if self.output.is_empty() {
            "SP1ConstraintList (Fin KB)".to_string()
        } else {
            assert_eq!(self.output.len(), 1);
            match self.output.first().unwrap() {
                Ty::Word(_) => "Word (Fin KB) × SP1ConstraintList (Fin KB)".to_string(),
                Ty::Expr(_) => "(Fin KB) × SP1ConstraintList (Fin KB)".to_string(),
                Ty::ArrWordSize(_) => {
                    "Vector (Fin KB) WORD_SIZE × SP1ConstraintList (Fin KB)".to_string()
                }
                Ty::ArrWordByteSize(_) => {
                    "Vector (Fin KB) WORD_BYTE_SIZE × SP1ConstraintList (Fin KB)".to_string()
                }
                _ => unimplemented!(),
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Func<Expr, ExprExt> {
    pub decl: FuncDecl<Expr, ExprExt>,
    pub body: Ast<Expr, ExprExt>,
}

impl<F: Field, EF: ExtensionField<F>> Display for Func<ExprRef<F>, ExprExtRef<EF>> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "fn {}(", self.decl.name)?;
        for (i, inp) in self.decl.input.iter().enumerate() {
            write!(f, "    {inp}")?;
            if i < self.decl.input.len() - 1 {
                writeln!(f, ",")?;
            }
        }
        write!(f, ")")?;
        if !self.decl.output.is_empty() {
            write!(f, "->")?;
            for (i, out) in self.decl.output.iter().enumerate() {
                write!(f, "{out}")?;
                if i < self.decl.output.len() - 1 {
                    write!(f, ", ")?;
                }
            }
        }
        writeln!(f, " {{")?;
        write!(f, "{}", self.body.to_string_pretty("   "))?;
        writeln!(f, "}}")
    }
}

impl<F: Field, EF: ExtensionField<F>> Func<ExprRef<F>, ExprExtRef<EF>> {
    #[allow(clippy::uninlined_format_args)]
    fn traverse(val: &serde_json::Value, name: String, m: &mut HashMap<usize, String>) {
        match val {
            serde_json::Value::Object(map) => {
                if let Some(irval) = map.get("IrVar") {
                    assert_eq!(map.len(), 1);
                    if let serde_json::Value::Number(idx) = irval.get("InputArg").unwrap() {
                        m.insert(idx.as_i64().unwrap() as usize, name);
                    } else {
                        unimplemented!()
                    }
                } else {
                    for (field_name, field_val) in map {
                        Self::traverse(field_val, format!("{}.{}", name, field_name), m);
                    }
                }
            }
            serde_json::Value::Array(lst) => {
                for (i, elem) in lst.iter().enumerate() {
                    Self::traverse(elem, format!("{}[{}]", name, i), m);
                }
            }
            _ => unimplemented!(),
        }
    }

    pub fn calc_input_mapping(&self) -> HashMap<usize, String> {
        let mut mapping: HashMap<usize, String> = HashMap::default();

        for (field_val, field_name) in self.decl.input.iter().zip(
            self.decl
                .parameter_names
                .clone()
                .expect("must provide field_names to calculate input mapping")
                .iter(),
        ) {
            let json_val = serde_json::to_value(field_val).unwrap();
            match json_val {
                serde_json::Value::Object(obj) => {
                    assert_eq!(obj.len(), 1);
                    let obj_val = obj.into_values().next().unwrap();
                    Self::traverse(&obj_val, field_name.clone(), &mut mapping);
                }
                _ => unimplemented!(),
            }
        }

        mapping
    }
}

/// A type in the IR.
///
/// Types can appear in function arguments as inputs and outputs, and in function declarations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Ty<Expr, ExprExt> {
    /// An arithmetic expression.
    Expr(Expr),
    /// An arithmetic expression over the extension field.
    ExprExt(ExprExt),
    /// A word in the base field.
    Word(Word<Expr>),
    /// An addition operation.
    AddOperation(AddOperation<Expr>),
    /// A subtraction operation.
    SubOperation(SubOperation<Expr>),
    /// An address operation.
    AddressOperation(AddressOperation<Expr>),
    /// A conversion from a word to an array of words of size `WORD_SIZE`.
    U16toU8Operation(U16toU8Operation<Expr>),
    /// An array of limbs of size `3`.
    ArrAddressSize([Expr; 3]),
    /// An array of words of size `WORD_SIZE`.
    ArrWordSize([Expr; WORD_SIZE]),
    /// An array of words of size `WORD_BYTE_SIZE`.
    ArrWordByteSize([Expr; WORD_BYTE_SIZE]),
    /// An is zero operation.
    IsZeroOperation(IsZeroOperation<Expr>),
    /// An is zero word operation.
    IsZeroWordOperation(IsZeroWordOperation<Expr>),
    /// An is equal word operation.
    IsEqualWordOperation(IsEqualWordOperation<Expr>),
    /// A bitwise operation.
    BitwiseOperation(BitwiseOperation<Expr>),
    /// A bitwise u16 operation.
    BitwiseU16Operation(BitwiseU16Operation<Expr>),
    /// A u16 compare operation.
    U16CompareOperation(U16CompareOperation<Expr>),
    /// A u16 MSB operation.
    U16MSBOperation(U16MSBOperation<Expr>),
    /// An LT unsigned operation.
    LtOperationUnsigned(LtOperationUnsigned<Expr>),
    /// An LT signed operation.
    LtOperationSigned(LtOperationSigned<Expr>),
    /// An R-type reader operation.
    RTypeReader(RTypeReader<Expr>),
    /// An ALU-type reader operation.
    ALUTypeReader(ALUTypeReader<Expr>),
    /// A CPU state operation.
    CPUState(CPUState<Expr>),
    RegisterAccessTimestamp(RegisterAccessTimestamp<Expr>),
    RegisterAccessCols(RegisterAccessCols<Expr>),
}

impl<Expr, ExprExt> Display for Ty<Expr, ExprExt>
where
    Expr: Debug + Display,
    ExprExt: Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ty::Expr(expr) => write!(f, "{expr}"),
            Ty::ExprExt(expr_ext) => write!(f, "{expr_ext}"),
            Ty::Word(word) => write!(f, "{word}"),
            Ty::AddOperation(add_operation) => write!(f, "{add_operation:?}"),
            Ty::SubOperation(sub_operation) => write!(f, "{sub_operation:?}"),
            Ty::AddressOperation(address_operation) => write!(f, "{address_operation:?}"),
            Ty::U16toU8Operation(u16to_u8_operation) => write!(f, "{u16to_u8_operation:?}"),
            Ty::ArrAddressSize(arr) => write!(f, "{arr:?}"),
            Ty::ArrWordSize(arr) => write!(f, "{arr:?}"),
            Ty::ArrWordByteSize(arr) => write!(f, "{arr:?}"),
            Ty::IsZeroOperation(is_zero_operation) => write!(f, "{is_zero_operation:?}"),
            Ty::IsZeroWordOperation(is_zero_word_operation) => {
                write!(f, "{is_zero_word_operation:?}")
            }
            Ty::IsEqualWordOperation(is_equal_word_operation) => {
                write!(f, "{is_equal_word_operation:?}")
            }
            Ty::BitwiseOperation(bitwise_operation) => write!(f, "{bitwise_operation:?}"),
            Ty::BitwiseU16Operation(bitwise_u16_operation) => {
                write!(f, "{bitwise_u16_operation:?}")
            }
            Ty::U16CompareOperation(u16_compare_operation) => {
                write!(f, "{u16_compare_operation:?}")
            }
            Ty::U16MSBOperation(u16_msb_operation) => {
                write!(f, "{u16_msb_operation:?}")
            }
            Ty::LtOperationUnsigned(lt_operation_unsigned) => {
                write!(f, "{lt_operation_unsigned:?}")
            }
            Ty::LtOperationSigned(lt_operation_signed) => {
                write!(f, "{lt_operation_signed:?}")
            }
            Ty::RTypeReader(r_type_reader) => write!(f, "{r_type_reader:?}"),
            Ty::ALUTypeReader(alu_type_reader) => write!(f, "{alu_type_reader:?}"),
            Ty::CPUState(cpu_state) => write!(f, "{cpu_state:?}"),
            Ty::RegisterAccessTimestamp(timestamp) => write!(f, "{timestamp:?}"),
            Ty::RegisterAccessCols(cols) => write!(f, "{cols:?}"),
        }
    }
}

impl<Expr, ExprExt> Ty<Expr, ExprExt> {
    pub fn to_lean_type(&self) -> String {
        match self {
            Ty::Expr(_) => "(Fin KB)".to_string(),
            Ty::Word(_) => "Word (Fin KB)".to_string(),
            Ty::AddOperation(_) => "AddOperation".to_string(),
            Ty::SubOperation(_) => "SubOperation".to_string(),
            Ty::BitwiseU16Operation(_) => "BitwiseU16Operation".to_string(),
            Ty::BitwiseOperation(_) => "BitwiseOperation".to_string(),
            Ty::U16toU8Operation(_) => "U16toU8Operation".to_string(),
            Ty::U16CompareOperation(_) => "U16CompareOperation".to_string(),
            Ty::U16MSBOperation(_) => "U16MSBOperation".to_string(),
            Ty::LtOperationUnsigned(_) => "LtOperationUnsigned".to_string(),
            Ty::LtOperationSigned(_) => "LtOperationSigned".to_string(),
            Ty::ArrWordSize(_) => "Vector (Fin KB) 4".to_string(),
            Ty::ArrWordByteSize(_) => "Vector (Fin KB) 2".to_string(),
            Ty::RTypeReader(_) => "RTypeReader".to_string(),
            Ty::ALUTypeReader(_) => "ALUTypeReader".to_string(),
            Ty::CPUState(_) => "CPUState".to_string(),
            _ => unimplemented!(),
        }
    }
}

/// An operation in the IR.
///
/// Operations can appear in the AST, and are used to represent the program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OpExpr<Expr, ExprExt> {
    /// An assertion that an expression is zero.
    AssertZero(Expr),
    /// A send operation.
    Send(AirInteraction<Expr>, InteractionScope),
    /// A receive operation.
    Receive(AirInteraction<Expr>, InteractionScope),
    /// A function call.
    Call(FuncDecl<Expr, ExprExt>),
    /// A binary operation.
    BinOp(BinOp, Expr, Expr, Expr),
    /// A binary operation over the extension field.
    BinOpExt(BinOp, ExprExt, ExprExt, ExprExt),
    /// A binary operation over the base field and the extension field.
    BinOpBaseExt(BinOp, ExprExt, ExprExt, Expr),
    /// A negation operation.
    Neg(Expr, Expr),
    /// A negation operation over the extension field.
    NegExt(ExprExt, ExprExt),
    /// A conversion from the base field to the extension field.
    ExtFromBase(ExprExt, Expr),
    /// An assertion that an expression over the extension field is zero.
    AssertExtZero(ExprExt),
    /// An assignment operation.
    Assign(Expr, Expr),
}

pub fn write_interaction<Expr>(
    f: &mut std::fmt::Formatter<'_>,
    interaction: &AirInteraction<Expr>,
    scope: &InteractionScope,
) -> std::fmt::Result
where
    Expr: Display,
{
    write!(
        f,
        "kind: {}, scope: {scope}, multiplicity: {}, values: [",
        interaction.kind, interaction.multiplicity
    )?;
    for (i, value) in interaction.values.iter().enumerate() {
        write!(f, "{value}")?;
        if i < interaction.values.len() - 1 {
            write!(f, ", ")?;
        }
    }
    write!(f, "]")?;
    Ok(())
}

impl<F, EF> Display for OpExpr<ExprRef<F>, ExprExtRef<EF>>
where
    F: Field,
    EF: ExtensionField<F>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpExpr::AssertZero(x) => write!(f, "Assert({x} == 0)"),
            OpExpr::Send(interaction, scope) => {
                write!(f, "Send(")?;
                write_interaction(f, interaction, scope)?;
                write!(f, ")")?;
                Ok(())
            }
            OpExpr::Receive(interaction, scope) => {
                write!(f, "Receive(")?;
                write_interaction(f, interaction, scope)?;
                write!(f, ")")?;
                Ok(())
            }
            OpExpr::Assign(a, b) => write!(f, "{a} = {b}"),
            OpExpr::Call(func) => {
                if !func.output.is_empty() {
                    if func.output.len() > 1 {
                        write!(f, "(")?;
                    }
                    for out in func.output.iter() {
                        write!(f, "{out}")?;
                    }
                    if func.output.len() > 1 {
                        write!(f, ")")?;
                    }
                    write!(f, " = ")?;
                }
                write!(f, "{}(", func.name)?;
                for (i, inp) in func.input.iter().enumerate() {
                    write!(f, "{inp}")?;
                    if i < func.input.len() - 1 {
                        write!(f, ", ")?;
                    }
                }
                write!(f, ")")?;
                Ok(())
            }
            OpExpr::BinOp(op, a, b, c) => match op {
                BinOp::Add => write!(f, "{a} = {b} + {c}"),
                BinOp::Sub => write!(f, "{a} = {b} - {c}"),
                BinOp::Mul => write!(f, "{a} = {b} * {c}"),
            },
            OpExpr::BinOpExt(op, a, b, c) => match op {
                BinOp::Add => write!(f, "{a} = {b} + {c}"),
                BinOp::Sub => write!(f, "{a} = {b} - {c}"),
                BinOp::Mul => write!(f, "{a} = {b} * {c}"),
            },
            OpExpr::BinOpBaseExt(op, a, b, c) => match op {
                BinOp::Add => write!(f, "{a} = {b} + {c}"),
                BinOp::Sub => write!(f, "{a} = {b} - {c}"),
                BinOp::Mul => write!(f, "{a} = {b} * {c}"),
            },
            OpExpr::Neg(a, b) => write!(f, "{a} = -{b}"),
            OpExpr::NegExt(a, b) => write!(f, "{a} = -{b}"),
            OpExpr::ExtFromBase(a, b) => write!(f, "{a} = {b}"),
            OpExpr::AssertExtZero(a) => write!(f, "Assert({a} == 0)"),
        }
    }
}

impl<F: Field, EF: ExtensionField<F>> OpExpr<ExprRef<F>, ExprExtRef<EF>> {
    #[allow(clippy::uninlined_format_args)]
    /// Convert operation to Lean syntax
    pub fn to_lean(
        &self,
        is_operation: bool,
        input_mapping: &HashMap<usize, String>,
    ) -> Option<String> {
        match self {
            OpExpr::AssertZero(expr) => {
                Some(format!(".assertZero {}", expr.to_lean(is_operation, input_mapping)))
            }
            OpExpr::Send(interaction, _scope) => {
                let mult = interaction.multiplicity.to_lean(is_operation, input_mapping);
                match interaction.kind {
                    InteractionKind::Byte => {
                        // Values: [opcode, a, b, c]
                        if interaction.values.len() == 4 {
                            let opcode = match &interaction.values[0] {
                                ExprRef::IrVar(IrVar::Constant(c)) => {
                                    format!("ByteOpcode.ofNat {c}")
                                }
                                _ => format!(
                                    "ByteOpcode.ofNat {}",
                                    interaction.values[0].to_lean(is_operation, input_mapping)
                                ),
                            };
                            let a = interaction.values[1].to_lean(is_operation, input_mapping);
                            let b = interaction.values[2].to_lean(is_operation, input_mapping);
                            let c = interaction.values[3].to_lean(is_operation, input_mapping);
                            Some(format!(".send (.byte ({}) {} {} {}) {}", opcode, a, b, c, mult))
                        } else {
                            unimplemented!()
                        }
                    }
                    InteractionKind::Memory => {
                        // Values: [shard, clk, addr, low, high]
                        if interaction.values.len() == 5 {
                            let shard = interaction.values[0].to_lean(is_operation, input_mapping);
                            let clk = interaction.values[1].to_lean(is_operation, input_mapping);
                            let addr = interaction.values[2].to_lean(is_operation, input_mapping);
                            let low = interaction.values[3].to_lean(is_operation, input_mapping);
                            let high = interaction.values[4].to_lean(is_operation, input_mapping);
                            Some(format!(
                                ".send (.memory {} {} {} {} {}) {}",
                                shard, clk, addr, low, high, mult
                            ))
                        } else {
                            unimplemented!()
                        }
                    }
                    InteractionKind::State => {
                        // Values: [shard, clk, pc]
                        if interaction.values.len() == 3 {
                            let shard = interaction.values[0].to_lean(is_operation, input_mapping);
                            let clk = interaction.values[1].to_lean(is_operation, input_mapping);
                            let pc = interaction.values[2].to_lean(is_operation, input_mapping);
                            Some(format!(".send (.state {} {} {}) {}", shard, clk, pc, mult))
                        } else {
                            unimplemented!()
                        }
                    }
                    _ => None,
                }
            }
            OpExpr::Receive(interaction, _scope) => {
                let mult = interaction.multiplicity.to_lean(is_operation, input_mapping);
                match interaction.kind {
                    InteractionKind::Memory => {
                        if interaction.values.len() == 5 {
                            let shard = interaction.values[0].to_lean(is_operation, input_mapping);
                            let clk = interaction.values[1].to_lean(is_operation, input_mapping);
                            let addr = interaction.values[2].to_lean(is_operation, input_mapping);
                            let low = interaction.values[3].to_lean(is_operation, input_mapping);
                            let high = interaction.values[4].to_lean(is_operation, input_mapping);
                            Some(format!(
                                ".receive (.memory {} {} {} {} {}) {}",
                                shard, clk, addr, low, high, mult
                            ))
                        } else {
                            unimplemented!()
                        }
                    }
                    InteractionKind::State => {
                        // Values: [shard, clk, pc]
                        if interaction.values.len() == 3 {
                            let shard = interaction.values[0].to_lean(is_operation, input_mapping);
                            let clk = interaction.values[1].to_lean(is_operation, input_mapping);
                            let pc = interaction.values[2].to_lean(is_operation, input_mapping);
                            Some(format!(".receive (.state {} {} {}) {}", shard, clk, pc, mult))
                        } else {
                            unimplemented!()
                        }
                    }
                    _ => None,
                }
            }
            OpExpr::BinOp(op, result, a, b) => {
                let result_str = result.to_lean(is_operation, input_mapping);
                let a_str = a.to_lean(is_operation, input_mapping);
                let b_str = b.to_lean(is_operation, input_mapping);
                let op_str = match op {
                    BinOp::Add => "+",
                    BinOp::Sub => "-",
                    BinOp::Mul => "*",
                };
                Some(format!("let {} : Fin KB := {} {} {}", result_str, a_str, op_str, b_str))
            }
            OpExpr::BinOpExt(op, result, a, b) => {
                // Extension field operations - similar to BinOp
                let result_str = result.to_lean(is_operation, input_mapping);
                let a_str = a.to_lean(is_operation, input_mapping);
                let b_str = b.to_lean(is_operation, input_mapping);
                let op_str = match op {
                    BinOp::Add => "+",
                    BinOp::Sub => "-",
                    BinOp::Mul => "*",
                };
                Some(format!("let {} := {} {} {}", result_str, a_str, op_str, b_str))
            }
            OpExpr::BinOpBaseExt(op, result, a, b) => {
                // Mixed base/extension field operations
                let result_str = result.to_lean(is_operation, input_mapping);
                let a_str = a.to_lean(is_operation, input_mapping);
                let b_str = b.to_lean(is_operation, input_mapping);
                let op_str = match op {
                    BinOp::Add => "+",
                    BinOp::Sub => "-",
                    BinOp::Mul => "*",
                };
                Some(format!("let {} := {} {} {}", result_str, a_str, op_str, b_str))
            }
            OpExpr::Neg(result, a) => {
                let result_str = result.to_lean(is_operation, input_mapping);
                let a_str = a.to_lean(is_operation, input_mapping);
                Some(format!("let {} : Fin KB := -{}", result_str, a_str))
            }
            OpExpr::NegExt(result, a) => {
                let result_str = result.to_lean(is_operation, input_mapping);
                let a_str = a.to_lean(is_operation, input_mapping);
                Some(format!("let {} := -{}", result_str, a_str))
            }
            OpExpr::ExtFromBase(result, a) => {
                let result_str = result.to_lean(is_operation, input_mapping);
                let a_str = a.to_lean(is_operation, input_mapping);
                Some(format!("let {} := {}", result_str, a_str))
            }
            OpExpr::AssertExtZero(a) => {
                Some(format!(".assertZero {}", a.to_lean(is_operation, input_mapping)))
            }
            OpExpr::Assign(a, b) => {
                let a_str = a.to_lean(is_operation, input_mapping);
                let b_str = b.to_lean(is_operation, input_mapping);
                Some(format!("let {} : Fin KB := {}", a_str, b_str))
            }
            OpExpr::Call(_func) => {
                // Function calls will be handled separately in the AST level
                // as they need special treatment for operation composition
                // String::new()
                unimplemented!()
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ast<Expr, ExprExt> {
    assignments: Vec<usize>,
    ext_assignments: Vec<usize>,
    operations: Vec<OpExpr<Expr, ExprExt>>,
}

impl<F: Field, EF: ExtensionField<F>> Ast<ExprRef<F>, ExprExtRef<EF>> {
    pub fn new() -> Self {
        Self { assignments: vec![], ext_assignments: vec![], operations: vec![] }
    }

    pub fn alloc(&mut self) -> ExprRef<F> {
        let id = self.assignments.len();
        self.assignments.push(self.operations.len());
        ExprRef::Expr(id)
    }

    pub fn alloc_array<const N: usize>(&mut self) -> [ExprRef<F>; N] {
        core::array::from_fn(|_| self.alloc())
    }

    pub fn assign(&mut self, a: ExprRef<F>, b: ExprRef<F>) {
        let op = OpExpr::Assign(a, b);
        self.operations.push(op);
    }

    pub fn alloc_ext(&mut self) -> ExprExtRef<EF> {
        let id = self.ext_assignments.len();
        self.ext_assignments.push(self.operations.len());
        ExprExtRef::Expr(id)
    }

    pub fn assert_zero(&mut self, x: ExprRef<F>) {
        let op = OpExpr::AssertZero(x);
        self.operations.push(op);
    }

    pub fn assert_ext_zero(&mut self, x: ExprExtRef<EF>) {
        let op = OpExpr::AssertExtZero(x);
        self.operations.push(op);
    }

    pub fn bin_op(&mut self, op: BinOp, a: ExprRef<F>, b: ExprRef<F>) -> ExprRef<F> {
        let result = self.alloc();
        // self.assignments.push(self.operations.len());
        let op = OpExpr::BinOp(op, result, a, b);
        self.operations.push(op);
        result
    }

    pub fn negate(&mut self, a: ExprRef<F>) -> ExprRef<F> {
        let result = self.alloc();
        let op = OpExpr::Neg(result, a);
        self.operations.push(op);
        result
    }

    pub fn bin_op_ext(
        &mut self,
        op: BinOp,
        a: ExprExtRef<EF>,
        b: ExprExtRef<EF>,
    ) -> ExprExtRef<EF> {
        let result = self.alloc_ext();
        // self.ext_assignments.push(self.operations.len());
        let op = OpExpr::BinOpExt(op, result, a, b);
        self.operations.push(op);
        result
    }

    pub fn bin_op_base_ext(
        &mut self,
        op: BinOp,
        a: ExprExtRef<EF>,
        b: ExprRef<F>,
    ) -> ExprExtRef<EF> {
        let result = self.alloc_ext();
        // self.ext_assignments.push(self.operations.len());
        let op = OpExpr::BinOpBaseExt(op, result, a, b);
        self.operations.push(op);
        result
    }

    pub fn neg_ext(&mut self, a: ExprExtRef<EF>) -> ExprExtRef<EF> {
        let result = self.alloc_ext();
        let op = OpExpr::NegExt(result, a);
        self.operations.push(op);
        result
    }

    pub fn ext_from_base(&mut self, a: ExprRef<F>) -> ExprExtRef<EF> {
        let result = self.alloc_ext();
        let op = OpExpr::ExtFromBase(result, a);
        self.operations.push(op);
        result
    }

    pub fn send(&mut self, message: AirInteraction<ExprRef<F>>, scope: InteractionScope) {
        let op = OpExpr::Send(message, scope);
        self.operations.push(op);
    }

    pub fn receive(&mut self, message: AirInteraction<ExprRef<F>>, scope: InteractionScope) {
        let op = OpExpr::Receive(message, scope);
        self.operations.push(op);
    }

    #[allow(clippy::uninlined_format_args)]
    pub fn to_string_pretty(&self, prefix: &str) -> String {
        let mut s = String::new();
        for op in &self.operations {
            s.push_str(&format!("{prefix}{}\n", op));
        }
        s
    }

    #[allow(clippy::uninlined_format_args)]
    /// Convert AST to Lean constraint list
    pub fn to_lean(
        &self,
        is_operation: bool,
        output: &Option<String>,
        input_mapping: &HashMap<usize, String>,
    ) -> String {
        let mut result = String::new();
        let mut constraint_list: Vec<String> = Vec::new();
        let mut extra_constraints: Vec<String> = Vec::new();

        // Generate let bindings and collect constraints
        for op in &self.operations {
            match op {
                OpExpr::BinOp(_, _, _, _)
                | OpExpr::BinOpExt(_, _, _, _)
                | OpExpr::BinOpBaseExt(_, _, _, _)
                | OpExpr::Neg(_, _)
                | OpExpr::NegExt(_, _)
                | OpExpr::ExtFromBase(_, _)
                | OpExpr::Assign(ExprRef::Expr(_), _) => {
                    // These generate let bindings
                    result.push_str("  ");
                    result.push_str(&op.to_lean(is_operation, input_mapping).unwrap());
                    result.push('\n');
                }
                OpExpr::AssertZero(_) | OpExpr::AssertExtZero(_) => {
                    // These go into the constraint list
                    constraint_list.push(op.to_lean(is_operation, input_mapping).unwrap());
                }
                OpExpr::Send(_, _) | OpExpr::Receive(_, _) => {
                    // These also go into the constraint list
                    if let Some(cstr) = op.to_lean(is_operation, input_mapping) {
                        constraint_list.push(cstr);
                    }
                }
                OpExpr::Call(func) => {
                    // Function calls need special handling
                    // We'll handle this in the next step

                    result.push_str("  ");
                    let cs: String = format!("CS{}", extra_constraints.len());

                    if func.output.is_empty() {
                        result.push_str(&format!("let {cs} : SP1ConstraintList (Fin KB) := "));
                    } else {
                        result.push_str("let ⟨");
                        result.push_str(&func.to_lean_output(false));
                        result.push_str(&format!(", {cs}⟩ := "));
                    }

                    result.push_str(&func.to_lean_call(input_mapping));
                    result.push('\n');

                    extra_constraints.push(cs);
                }
                OpExpr::Assign(ExprRef::IrVar(IrVar::OutputArg(_)), _) => {}
                _ => unimplemented!(),
            }
        }

        // Generate the constraint list
        if let Some(out) = output {
            result.push_str(&format!("  ⟨{},", out));
        }
        result.push_str("  [\n");
        for (i, constraint) in constraint_list.iter().enumerate() {
            result.push_str("    ");
            result.push_str(constraint);
            if i < constraint_list.len() - 1 {
                result.push(',');
            }
            result.push('\n');
        }
        result.push_str("  ]");

        for extra_cstr in extra_constraints {
            result.push_str(&format!(" ++ {extra_cstr}"));
        }
        if output.is_some() {
            result.push('⟩')
        }

        result
    }

    pub fn add_operation(
        &mut self,
        a: Word<ExprRef<F>>,
        b: Word<ExprRef<F>>,
        cols: AddOperation<ExprRef<F>>,
        is_real: ExprRef<F>,
    ) {
        let func = FuncDecl::new(
            "AddOperation",
            vec![Ty::Word(a), Ty::Word(b), Ty::AddOperation(cols), Ty::Expr(is_real)],
            vec![],
        );
        let op = OpExpr::Call(func);
        self.operations.push(op);
    }

    pub fn sub_operation(
        &mut self,
        a: Word<ExprRef<F>>,
        b: Word<ExprRef<F>>,
        cols: SubOperation<ExprRef<F>>,
        is_real: ExprRef<F>,
    ) {
        let func = FuncDecl::new(
            "SubOperation",
            vec![Ty::Word(a), Ty::Word(b), Ty::SubOperation(cols), Ty::Expr(is_real)],
            vec![],
        );
        let op = OpExpr::Call(func);
        self.operations.push(op);
    }

    pub fn address_operation(
        &mut self,
        b: Word<ExprRef<F>>,
        c: Word<ExprRef<F>>,
        offset_bit0: ExprRef<F>,
        offset_bit1: ExprRef<F>,
        is_real: ExprRef<F>,
        cols: AddressOperation<ExprRef<F>>,
    ) -> ExprRef<F> {
        let output = self.alloc();
        let func = FuncDecl::new(
            "AddressOperation",
            vec![
                Ty::Word(b),
                Ty::Word(c),
                Ty::Expr(offset_bit0),
                Ty::Expr(offset_bit1),
                Ty::Expr(is_real),
                Ty::AddressOperation(cols),
            ],
            vec![Ty::Expr(output)],
        );
        let op = OpExpr::Call(func);
        self.operations.push(op);
        output
    }

    pub fn u16_to_u8_operation_safe(
        &mut self,
        u16_values: [ExprRef<F>; WORD_SIZE],
        cols: U16toU8Operation<ExprRef<F>>,
        is_real: ExprRef<F>,
    ) -> [ExprRef<F>; WORD_BYTE_SIZE] {
        let result = self.alloc_array();
        let func = FuncDecl::new(
            "U16toU8OperationSafe",
            vec![Ty::ArrWordSize(u16_values), Ty::Expr(is_real), Ty::U16toU8Operation(cols)],
            vec![Ty::ArrWordByteSize(result)],
        );
        let op = OpExpr::Call(func);
        self.operations.push(op);
        result
    }

    pub fn u16_to_u8_operation_unsafe(
        &mut self,
        u16_values: [ExprRef<F>; WORD_SIZE],
        cols: U16toU8Operation<ExprRef<F>>,
    ) -> [ExprRef<F>; WORD_BYTE_SIZE] {
        let result = self.alloc_array();
        let func = FuncDecl::new(
            "U16toU8OperationUnsafe",
            vec![Ty::ArrWordSize(u16_values), Ty::U16toU8Operation(cols)],
            vec![Ty::ArrWordByteSize(result)],
        );
        let op = OpExpr::Call(func);
        self.operations.push(op);
        result
    }

    pub fn is_zero_operation(
        &mut self,
        a: ExprRef<F>,
        cols: IsZeroOperation<ExprRef<F>>,
        is_real: ExprRef<F>,
    ) {
        let func = FuncDecl::new(
            "IsZeroOperation",
            vec![Ty::Expr(a), Ty::Expr(is_real), Ty::IsZeroOperation(cols)],
            vec![],
        );
        let op = OpExpr::Call(func);
        self.operations.push(op);
    }

    pub fn is_zero_word_operation(
        &mut self,
        a: Word<ExprRef<F>>,
        cols: IsZeroWordOperation<ExprRef<F>>,
        is_real: ExprRef<F>,
    ) {
        let func = FuncDecl::new(
            "IsZeroWordOperation",
            vec![Ty::Word(a), Ty::IsZeroWordOperation(cols), Ty::Expr(is_real)],
            vec![],
        );
        let op = OpExpr::Call(func);
        self.operations.push(op);
    }

    pub fn is_equal_word_operation(
        &mut self,
        a: Word<ExprRef<F>>,
        b: Word<ExprRef<F>>,
        cols: IsEqualWordOperation<ExprRef<F>>,
        is_real: ExprRef<F>,
    ) {
        let func = FuncDecl::new(
            "IsEqualWordOperation",
            vec![Ty::Word(a), Ty::Word(b), Ty::IsEqualWordOperation(cols), Ty::Expr(is_real)],
            vec![],
        );
        let op = OpExpr::Call(func);
        self.operations.push(op);
    }

    pub fn bitwise_operation(
        &mut self,
        a: [ExprRef<F>; WORD_BYTE_SIZE],
        b: [ExprRef<F>; WORD_BYTE_SIZE],
        cols: BitwiseOperation<ExprRef<F>>,
        opcode: ExprRef<F>,
        is_real: ExprRef<F>,
    ) {
        let func = FuncDecl::new(
            "BitwiseOperation",
            vec![
                Ty::ArrWordByteSize(a),
                Ty::ArrWordByteSize(b),
                Ty::BitwiseOperation(cols),
                Ty::Expr(opcode),
                Ty::Expr(is_real),
            ],
            vec![],
        );
        let op = OpExpr::Call(func);
        self.operations.push(op);
    }

    pub fn bitwise_u16_operation(
        &mut self,
        b: Word<ExprRef<F>>,
        c: Word<ExprRef<F>>,
        cols: BitwiseU16Operation<ExprRef<F>>,
        opcode: ExprRef<F>,
        is_real: ExprRef<F>,
    ) -> Word<ExprRef<F>> {
        let output = Word(core::array::from_fn(|_| self.alloc()));
        let func = FuncDecl::new(
            "BitwiseU16Operation",
            vec![
                Ty::Word(b),
                Ty::Word(c),
                Ty::BitwiseU16Operation(cols),
                Ty::Expr(opcode),
                Ty::Expr(is_real),
            ],
            vec![Ty::Word(output)],
        );
        let op = OpExpr::Call(func);
        self.operations.push(op);
        output
    }

    pub fn u16_compare_operation(
        &mut self,
        a: ExprRef<F>,
        b: ExprRef<F>,
        cols: U16CompareOperation<ExprRef<F>>,
        is_real: ExprRef<F>,
    ) {
        let func = FuncDecl::new(
            "U16CompareOperation",
            vec![Ty::Expr(a), Ty::Expr(b), Ty::U16CompareOperation(cols), Ty::Expr(is_real)],
            vec![],
        );
        let op = OpExpr::Call(func);
        self.operations.push(op);
    }

    pub fn u16_msb_operation(
        &mut self,
        a: ExprRef<F>,
        cols: U16MSBOperation<ExprRef<F>>,
        is_real: ExprRef<F>,
    ) {
        let func = FuncDecl::new(
            "U16MSBOperation",
            vec![Ty::Expr(a), Ty::U16MSBOperation(cols), Ty::Expr(is_real)],
            vec![],
        );
        let op = OpExpr::Call(func);
        self.operations.push(op);
    }

    pub fn lt_operation_unsigned(
        &mut self,
        b: Word<ExprRef<F>>,
        c: Word<ExprRef<F>>,
        cols: LtOperationUnsigned<ExprRef<F>>,
        is_real: ExprRef<F>,
    ) {
        let func = FuncDecl::new(
            "LtOperationUnsigned",
            vec![Ty::Word(b), Ty::Word(c), Ty::LtOperationUnsigned(cols), Ty::Expr(is_real)],
            vec![],
        );
        let op = OpExpr::Call(func);
        self.operations.push(op);
    }

    pub fn lt_operation_signed(
        &mut self,
        b: Word<ExprRef<F>>,
        c: Word<ExprRef<F>>,
        cols: LtOperationSigned<ExprRef<F>>,
        is_signed: ExprRef<F>,
        is_real: ExprRef<F>,
    ) {
        let func = FuncDecl::new(
            "LtOperationSigned",
            vec![
                Ty::Word(b),
                Ty::Word(c),
                Ty::LtOperationSigned(cols),
                Ty::Expr(is_signed),
                Ty::Expr(is_real),
            ],
            vec![],
        );
        let op = OpExpr::Call(func);
        self.operations.push(op);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn r_type_reader(
        &mut self,
        clk_high: ExprRef<F>,
        clk_low: ExprRef<F>,
        pc: [ExprRef<F>; 3],
        opcode: ExprRef<F>,
        op_a_write_value: Word<ExprRef<F>>,
        cols: RTypeReader<ExprRef<F>>,
        is_real: ExprRef<F>,
    ) {
        let func = FuncDecl::new(
            "RTypeReader",
            vec![
                Ty::Expr(clk_high),
                Ty::Expr(clk_low),
                Ty::ArrAddressSize(pc),
                Ty::Expr(opcode),
                Ty::Word(op_a_write_value),
                Ty::RTypeReader(cols),
                Ty::Expr(is_real),
            ],
            vec![],
        );
        let op = OpExpr::Call(func);
        self.operations.push(op);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn r_type_reader_immutable(
        &mut self,
        clk_high: ExprRef<F>,
        clk_low: ExprRef<F>,
        pc: [ExprRef<F>; 3],
        opcode: ExprRef<F>,
        cols: RTypeReader<ExprRef<F>>,
        is_real: ExprRef<F>,
    ) {
        let func = FuncDecl::new(
            "RTypeReaderImmutable",
            vec![
                Ty::Expr(clk_high),
                Ty::Expr(clk_low),
                Ty::ArrAddressSize(pc),
                Ty::Expr(opcode),
                Ty::RTypeReader(cols),
                Ty::Expr(is_real),
            ],
            vec![],
        );
        let op = OpExpr::Call(func);
        self.operations.push(op);
    }

    pub fn cpu_state(
        &mut self,
        cols: CPUState<ExprRef<F>>,
        next_pc: [ExprRef<F>; 3],
        clk_increment: ExprRef<F>,
        is_real: ExprRef<F>,
    ) {
        let func = FuncDecl::new(
            "CPUState",
            vec![
                Ty::CPUState(cols),
                Ty::ArrAddressSize(next_pc),
                Ty::Expr(clk_increment),
                Ty::Expr(is_real),
            ],
            vec![],
        );
        let op = OpExpr::Call(func);
        self.operations.push(op);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn alu_type_reader(
        &mut self,
        clk_high: ExprRef<F>,
        clk_low: ExprRef<F>,
        pc: [ExprRef<F>; 3],
        opcode: ExprRef<F>,
        op_a_write_value: Word<ExprRef<F>>,
        cols: ALUTypeReader<ExprRef<F>>,
        is_real: ExprRef<F>,
    ) {
        let func = FuncDecl::new(
            "ALUTypeReader",
            vec![
                Ty::Expr(clk_high),
                Ty::Expr(clk_low),
                Ty::ArrAddressSize(pc),
                Ty::Expr(opcode),
                Ty::Word(op_a_write_value),
                Ty::ALUTypeReader(cols),
                Ty::Expr(is_real),
            ],
            vec![],
        );
        let op = OpExpr::Call(func);
        self.operations.push(op);
    }
}

impl<F: Field, EF: ExtensionField<F>> Default for Ast<ExprRef<F>, ExprExtRef<EF>> {
    fn default() -> Self {
        Self::new()
    }
}
