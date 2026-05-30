use std::collections::HashMap;

use itertools::Itertools;
use slop_algebra::{ExtensionField, Field};

use crate::{
    air::AirInteraction,
    ir::{ExprExtRef, ExprRef, IrVar, Shape},
    InteractionKind,
};

// TODO(gzgz): implement constructor and destructor
impl<F: Field, EF: ExtensionField<F>> Shape<ExprRef<F>, ExprExtRef<EF>> {
    /// Output the string that would construct a value of this [Shape]
    pub fn to_lean_constructor(&self, mapping: &HashMap<usize, String>) -> String {
        match self {
            Shape::Unit => unimplemented!("Unit shouldn't appear in constructors"),
            Shape::Expr(expr) => expr.to_lean_string(mapping),
            Shape::ExprExt(_) => todo!(),
            Shape::Word(word) => {
                format!("#v[{}]", word.iter().map(|x| x.to_lean_string(mapping)).join(", "))
            }
            Shape::Array(vals) => {
                format!("#v[{}]", vals.iter().map(|x| x.to_lean_constructor(mapping)).join(", "))
            }
            Shape::Struct(_, fields) => {
                format!(
                    "{{ {} }}",
                    fields
                        .iter()
                        .flat_map(|(field_name, field_val)| {
                            // An array-of-struct field is flattened to `name_0 := …, name_1 := …`
                            // (matching the flattened struct definition in
                            // `Shape::collect_lean_struct_defs` and body paths in `map_input`);
                            // array-of-scalar stays a single `name := #v[…]`.
                            match field_val.as_ref() {
                                Shape::Array(elems)
                                    if matches!(
                                        elems.first().map(|e| e.as_ref()),
                                        Some(Shape::Struct(..))
                                    ) =>
                                {
                                    elems
                                        .iter()
                                        .enumerate()
                                        .map(|(i, e)| {
                                            format!("{field_name}_{i} := {}", e.to_lean_constructor(mapping))
                                        })
                                        .collect::<Vec<_>>()
                                }
                                _ => vec![format!(
                                    "{field_name} := {}",
                                    field_val.to_lean_constructor(mapping)
                                )],
                            }
                        })
                        .join(", ")
                )
            }
        }
    }

    /// Output the string that would destruct a value of this [Shape]
    pub fn to_lean_destructor(&self) -> String {
        match self {
            Shape::Unit => unimplemented!("Unit shouldn't appear in destructors"),
            Shape::Expr(expr) => expr.to_lean_string(&HashMap::default()),
            Shape::ExprExt(_) => todo!(),
            Shape::Word(word) => format!(
                "⟨⟨[{}]⟩, _⟩",
                word.iter().map(|x| x.to_lean_string(&HashMap::default())).join(", ")
            ),
            Shape::Array(vals) => {
                format!("⟨⟨[{}]⟩, _⟩", vals.iter().map(|x| x.to_lean_destructor()).join(", "))
            }
            Shape::Struct(_, _) => todo!("why would you need to destruct a struct"),
        }
    }

    /// The output value's leaf variable names, in flattened column order. Used to bind a call's
    /// returned value by index (`tmp.1[k]`) rather than by a structural `⟨⟨[..]⟩, _⟩` destructure
    /// of the `Vector`, which does not elaborate. Mirrors [`Self::to_lean_destructor`]'s flat
    /// treatment of `Word`/`Array` leaves.
    pub fn output_leaves(&self) -> Vec<String> {
        match self {
            Shape::Expr(expr) => vec![expr.to_lean_string(&HashMap::default())],
            Shape::Word(word) => {
                word.iter().map(|x| x.to_lean_string(&HashMap::default())).collect()
            }
            Shape::Array(vals) => vals.iter().flat_map(|x| x.output_leaves()).collect(),
            _ => unimplemented!("output_leaves only supports Expr/Word/Array outputs"),
        }
    }

    /// Calculates the full variable name that corresponds to `InputArg(x)`.
    ///
    /// For example,
    /// ```lean
    /// structure AddOperation where
    ///   value : Word SP1Field
    ///
    /// def AddOperation.constraints
    ///   (b : SP1Field)
    ///   (c : SP1Field)
    ///   (cols : AddOperation)
    ///   (is_real : SP1Field) := sorry
    /// ```
    ///
    /// `Expr(InputArg(3))` then maps to "cols.value[1]" because if you recursively flatten the
    /// input arguments to `AddOperation.constraints` in argument/field declaration order, then the
    /// element at index 3 corresponds to `cols.value[1]`.
    pub fn map_input(&self, prefix: String, input_mapping: &mut HashMap<usize, String>) {
        match self {
            Shape::Unit => unimplemented!("Unit shouldn't appear as input"),
            Shape::Expr(ExprRef::IrVar(IrVar::InputArg(idx))) => {
                input_mapping.insert(*idx, prefix);
            }
            Shape::Word(vals) => {
                for (i, val) in vals.iter().enumerate() {
                    match val {
                        ExprRef::IrVar(IrVar::InputArg(idx)) => {
                            input_mapping.insert(*idx, format!("{prefix}[{i}]"));
                        }
                        _ => unimplemented!("map_input must be backed by Input(x)"),
                    }
                }
            }
            Shape::Array(vals) => {
                // Array-of-struct fields are flattened to `prefix_i` separate struct fields (see
                // `Shape::collect_lean_struct_defs`); array-of-scalar keeps `prefix[i]` indexing.
                let flatten = matches!(vals.first().map(|v| v.as_ref()), Some(Shape::Struct(..)));
                for (i, val) in vals.iter().enumerate() {
                    let path =
                        if flatten { format!("{prefix}_{i}") } else { format!("{prefix}[{i}]") };
                    val.map_input(path, input_mapping);
                }
            }
            Shape::Struct(_, fields) => {
                for (name, field) in fields {
                    field.map_input(format!("{prefix}.{name}"), input_mapping);
                }
            }
            _ => unimplemented!(),
        }
    }
}

impl<F: Field> AirInteraction<ExprRef<F>> {
    /// Converts an Air interaction to an `AirInteraction` in sp1-lean.
    pub fn to_lean_string(&self, input_mapping: &HashMap<usize, String>) -> String {
        let mut res = "(".to_string();

        let kind_str = match self.kind {
            InteractionKind::Memory => ".memory",
            InteractionKind::Program => ".program",
            InteractionKind::Byte => ".byte",
            InteractionKind::State => ".state",
            _ => todo!(),
        };
        res.push_str(kind_str);

        match self.kind {
            InteractionKind::Byte => {
                assert_eq!(self.values.len(), 4);
                for (idx, val) in self.values.iter().enumerate() {
                    if idx == 0 {
                        // ByteOpcode
                        res.push_str(&format!(
                            " (ByteOpcode.ofNat {})",
                            val.to_lean_string(input_mapping)
                        ));
                    } else {
                        res.push_str(&format!(" {}", val.to_lean_string(input_mapping)));
                    }
                }
            }
            InteractionKind::Memory => {
                assert_eq!(self.values.len(), 9);
                for val in &self.values {
                    res.push_str(&format!(" {}", val.to_lean_string(input_mapping)));
                }
            }
            InteractionKind::State => {
                assert_eq!(self.values.len(), 5);
                for val in &self.values {
                    res.push_str(&format!(" {}", val.to_lean_string(input_mapping)));
                }
            }
            InteractionKind::Program => {
                assert_eq!(self.values.len(), 16);

                for (idx, val) in self.values.iter().enumerate() {
                    if idx == 3 {
                        // Opcode
                        res.push_str(&format!(
                            " (Opcode.ofNat {})",
                            val.to_lean_string(input_mapping)
                        ));
                    } else {
                        res.push_str(&format!(" {}", val.to_lean_string(input_mapping)));
                    }
                }
            }
            _ => {
                todo!();
            }
        }

        res.push(')');
        res
    }
}
