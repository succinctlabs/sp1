use core::marker::PhantomData;
use itertools::Itertools;
use p3_field::{AbstractExtensionField, PrimeField};
use std::collections::HashMap;

use crate::ir::{Config, DslIR};

const GNARK_TEMPLATE: &str = include_str!("template.txt");

/// Indents a block of lines by one tab.
pub fn indent(lines: Vec<String>) -> Vec<String> {
    lines.into_iter().map(|x| format!("\t{}", x)).collect()
}

/// Masks the evaluation of lines based on a condition.
pub fn mask(cond: String, lines: Vec<String>) -> Vec<String> {
    lines
        .iter()
        .map(|line| {
            let parts = line.split('=').collect::<Vec<_>>();
            let dst = parts[0].trim_end();
            let expr = parts[1].trim_end();
            if dst.contains("var") {
                format!("{dst} = api.Select({cond}, {expr}, {dst}")
            } else if dst.contains("felt") {
                format!("{dst} = babybearChip.Select({cond}, {expr}, {dst})")
            } else if dst.contains("ext") {
                format!("{dst} = babybearChip.SelectExtension({cond}, {expr}, {dst}")
            } else {
                panic!("unexpected dst for DslIR::IfEq")
            }
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct GnarkBackend<C: Config> {
    pub nb_backend_vars: usize,
    pub used: HashMap<String, bool>,
    pub phantom: PhantomData<C>,
}

impl<C: Config> GnarkBackend<C> {
    pub fn alloc(&mut self) -> String {
        let id = format!("backend{}", self.nb_backend_vars);
        self.nb_backend_vars += 1;
        id
    }

    pub fn assign(&mut self, id: String) -> &str {
        self.used.insert(id.clone(), true);
        "="
    }

    pub fn emit(&mut self, operations: Vec<DslIR<C>>) -> Vec<String> {
        let mut lines: Vec<String> = Vec::new();
        for instruction in operations {
            match instruction {
                DslIR::Imm(a, b) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} frontend.Variable(\"{}\")",
                        a.id(),
                        operator,
                        b.as_canonical_biguint()
                    ));
                }
                DslIR::ImmFelt(a, b) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybear.NewVariable({})",
                        a.id(),
                        operator,
                        b
                    ));
                }
                DslIR::ImmExt(a, b) => {
                    let operator = self.assign(a.id());
                    let b = b.as_base_slice();
                    let b_start = "[4]int{";
                    let b = b.iter().map(|x| x.to_string()).join(",");
                    let b_end = "}";
                    let b = format!("{}{}{}", b_start, b, b_end);
                    lines.push(format!(
                        "{} {} babybear.NewExtensionVariable({})",
                        a.id(),
                        operator,
                        b
                    ));
                }
                DslIR::AddV(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} api.Add({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ))
                }
                DslIR::AddVI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} api.Add({}, frontend.Variable(\"{}\"))",
                        a.id(),
                        operator,
                        b.id(),
                        c.as_canonical_biguint()
                    ));
                }
                DslIR::AddF(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.Add({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::AddFI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.Add({}, babybear.NewVariable({}))",
                        a.id(),
                        operator,
                        b.id(),
                        c
                    ));
                }
                DslIR::AddE(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.AddExtension({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::AddEI(a, b, c) => {
                    let operator = self.assign(a.id());
                    let c = c.as_base_slice();
                    let c_start = "[4]int{";
                    let c = c.iter().map(|x| x.to_string()).join(",");
                    let c_end = "}";
                    let c = format!("{}{}{}", c_start, c, c_end);
                    lines.push(format!(
                        "{} {} babybearChip.AddExtension({}, babybear.NewExtensionVariable({}))",
                        a.id(),
                        operator,
                        b.id(),
                        c
                    ));
                }
                DslIR::AddEFI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.AddFelt({}, babybear.NewVariable({}))",
                        a.id(),
                        operator,
                        b.id(),
                        c
                    ));
                }
                DslIR::AddEFFI(a, b, c) => {
                    let operator = self.assign(a.id());
                    let c = c.as_base_slice();
                    let c_start = "[4]int{";
                    let c = c.iter().map(|x| x.to_string()).join(",");
                    let c_end = "}";
                    let c = format!("{}{}{}", c_start, c, c_end);
                    lines.push(format!(
                        "{} {} babybearChip.AddFelt(babybear.NewExtensionVariable({}), {})",
                        a.id(),
                        operator,
                        c,
                        b.id()
                    ));
                }
                DslIR::AddEF(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.AddFelt({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::MulV(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} api.Mul({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::MulVI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} api.Mul(frontend.Variable({}), \"{}\")",
                        a.id(),
                        operator,
                        b.id(),
                        c.as_canonical_biguint()
                    ));
                }
                DslIR::MulF(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.Mul({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::MulFI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.Mul({}, babybear.NewVariable({}))",
                        a.id(),
                        operator,
                        b.id(),
                        c
                    ));
                }
                DslIR::MulE(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.MulExtension({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::MulEI(a, b, c) => {
                    let operator = self.assign(a.id());
                    let c = c.as_base_slice();
                    let c_start = "[4]int{";
                    let c = c.iter().map(|x| x.to_string()).join(",");
                    let c_end = "}";
                    let c = format!("{}{}{}", c_start, c, c_end);
                    lines.push(format!(
                        "{} {} babybearChip.MulExtension({}, babybear.NewExtensionVariable({}))",
                        a.id(),
                        operator,
                        b.id(),
                        c
                    ));
                }
                DslIR::MulEFI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.MulFelt({}, babybear.NewVariable({}))",
                        a.id(),
                        operator,
                        c,
                        b.id()
                    ));
                }
                DslIR::MulEF(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.Mul({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::SubV(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} api.Sub({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::SubVI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} api.Sub(frontend.Variable({}), {})",
                        a.id(),
                        operator,
                        b.id(),
                        c
                    ));
                }
                DslIR::SubVIN(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} api.Sub(frontend.Variable({}), {})",
                        a.id(),
                        operator,
                        b,
                        c.id()
                    ));
                }
                DslIR::SubF(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.Sub({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::SubFI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.Sub({}, babybear.NewVariable({}))",
                        a.id(),
                        operator,
                        b.id(),
                        c
                    ));
                }
                DslIR::SubFIN(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.Sub(babybear.NewVariable({}), {})",
                        a.id(),
                        operator,
                        b,
                        c.id()
                    ));
                }
                DslIR::SubE(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.SubExtension({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::SubEI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.SubExtension({}, babybear.NewExtensionVariable({}))",
                        a.id(),
                        operator,
                        b.id(),
                        c
                    ));
                }
                DslIR::SubEIN(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.SubExtension(babybear.NewExtensionVariable({}), {})",
                        a.id(),
                        operator,
                        b,
                        c.id()
                    ));
                }
                DslIR::SubEFI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.SubFelt({}, babybear.NewVariable({}))",
                        a.id(),
                        operator,
                        c,
                        b.id()
                    ));
                }
                DslIR::SubEFIN(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.SubFelt(babybear.NewExtensionVariable({}), {})",
                        a.id(),
                        operator,
                        b,
                        c.id()
                    ));
                }
                DslIR::SubEF(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.SubFelt({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::DivF(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.Div({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::DivFI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.Div({}, babybear.NewVariable({}))",
                        a.id(),
                        operator,
                        b.id(),
                        c
                    ));
                }
                DslIR::DivFIN(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.Div(babybear.NewVariable({}), {})",
                        a.id(),
                        operator,
                        b,
                        c.id()
                    ));
                }
                DslIR::DivE(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.DivExtension({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::DivEI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.DivExtension({}, babybear.NewExtensionVariable({}))",
                        a.id(),
                        operator,
                        b.id(),
                        c
                    ));
                }
                DslIR::DivEIN(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.DivExtension(babybear.NewExtensionVariable({}), {})",
                        a.id(),
                        operator,
                        b,
                        c.id()
                    ));
                }
                DslIR::DivEFI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.DivFelt({}, babybear.NewVariable({}))",
                        a.id(),
                        operator,
                        c,
                        b.id()
                    ));
                }
                DslIR::DivEFIN(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.DivFelt(babybear.NewExtensionVariable({}), {})",
                        a.id(),
                        operator,
                        b,
                        c.id()
                    ));
                }
                DslIR::DivEF(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.DivFelt({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::NegV(a, b) => {
                    let operator = self.assign(a.id());
                    lines.push(format!("{} {} api.Neg({})", a.id(), operator, b.id()));
                }
                DslIR::NegF(a, b) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.Neg({})",
                        a.id(),
                        operator,
                        b.id()
                    ));
                }
                DslIR::NegE(a, b) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.NegExtension({})",
                        a.id(),
                        operator,
                        b.id()
                    ));
                }
                DslIR::InvV(a, b) => {
                    let operator = self.assign(a.id());
                    lines.push(format!("{} {} api.Inv({})", a.id(), operator, b.id()));
                }
                DslIR::InvF(a, b) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.Inv({})",
                        a.id(),
                        operator,
                        b.id()
                    ));
                }
                DslIR::InvE(a, b) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} babybearChip.InvExtension({})",
                        a.id(),
                        operator,
                        b.id()
                    ))
                }
                DslIR::For(a, b, _, d) => {
                    lines.push(format!("for i := {}; i < {}; i++ {{", a.value(), b.value()));
                    lines.extend(indent(self.emit(d)));
                    lines.push("}".to_string());
                }
                DslIR::IfEq(a, b, c, d) => {
                    let cond = self.alloc();
                    let operator = self.assign(cond.clone());
                    lines.push(format!(
                        "{} {} api.IsZero(api.Sub({}, {}))",
                        cond,
                        operator,
                        a.id(),
                        b.id()
                    ));
                    lines.extend(mask(cond.clone(), self.emit(c)));
                    lines.extend(mask(cond.clone(), self.emit(d)));
                }
                DslIR::IfNe(a, b, c, d) => {
                    let cond = self.alloc();
                    let operator = self.assign(cond.clone());
                    lines.push(format!(
                        "{} {} api.Sub(frontend.Variable(1), api.IsZero(api.Sub({}, {})))",
                        cond,
                        operator,
                        a.id(),
                        b.id()
                    ));
                    lines.extend(mask(cond.clone(), self.emit(c)));
                    lines.extend(mask(cond.clone(), self.emit(d)));
                }
                DslIR::IfEqI(a, b, c, d) => {
                    let cond = self.alloc();
                    let operator = self.assign(cond.clone());
                    lines.push(format!(
                        "{} {} api.IsZero(api.Sub({}, frontend.Variable(\"{}\")))",
                        cond,
                        operator,
                        a.id(),
                        b.as_canonical_biguint()
                    ));
                    lines.extend(mask(cond.clone(), self.emit(c)));
                    lines.extend(mask(cond.clone(), self.emit(d)));
                }
                DslIR::IfNeI(a, b, c, d) => {
                    let cond = self.alloc();
                    let operator = self.assign(cond.clone());
                    lines.push(format!(
                        "{} {} api.Sub(frontend.Variable(1), api.IsZero(api.Sub({}, frontend.Variable({}))))",
                        cond,
                        operator,
                        a.id(),
                        b
                    ));
                    lines.extend(mask(cond.clone(), self.emit(c)));
                    lines.extend(mask(cond.clone(), self.emit(d)));
                }
                DslIR::AssertEqV(a, b) => {
                    lines.push(format!("api.AssertIsEqual({}, {})", a.id(), b.id()));
                }
                DslIR::AssertNeV(a, b) => {
                    lines.push(format!("api.AssertNe({}, {})", a.id(), b.id()));
                }
                DslIR::AssertEqF(a, b) => {
                    lines.push(format!("babybearChip.AssertEq({}, {})", a.id(), b.id()));
                }
                DslIR::AssertNeF(a, b) => {
                    lines.push(format!("babybearChip.AssertNe({}, {})", a.id(), b.id()));
                }
                DslIR::AssertEqE(a, b) => {
                    lines.push(format!(
                        "babybearChip.AssertEqExtension({}, {})",
                        a.id(),
                        b.id()
                    ));
                }
                DslIR::AssertNeE(a, b) => {
                    lines.push(format!(
                        "babybearChip.AssertNeExtension({}, {})",
                        a.id(),
                        b.id()
                    ));
                }
                DslIR::AssertEqVI(a, b) => {
                    lines.push(format!(
                        "api.AssertIsEqual({}, frontend.Variable(\"{}\"))",
                        a.id(),
                        b.as_canonical_biguint(),
                    ));
                }
                DslIR::AssertNeVI(a, b) => {
                    lines.push(format!(
                        "api.AssertNe({}, frontend.Variable({}))",
                        a.id(),
                        b
                    ));
                }
                DslIR::AssertEqFI(a, b) => {
                    lines.push(format!(
                        "babybearChip.AssertEq({}, babybear.NewVariable({}))",
                        a.id(),
                        b
                    ));
                }
                DslIR::AssertNeFI(a, b) => {
                    lines.push(format!(
                        "babybearChip.AssertNe({}, babybear.NewVariable({}))",
                        a.id(),
                        b
                    ));
                }
                DslIR::AssertEqEI(a, b) => {
                    let b = b.as_base_slice();
                    let b_start = "[4]int{";
                    let b = b.iter().map(|x| x.to_string()).join(",");
                    let b_end = "}";
                    let b = format!("{}{}{}", b_start, b, b_end);
                    lines.push(format!(
                        "babybearChip.AssertEqExtension({}, babybear.NewExtensionVariable({}))",
                        a.id(),
                        b
                    ));
                }
                DslIR::AssertNeEI(a, b) => {
                    lines.push(format!(
                        "babybearChip.AssertNeExtension({}, babybear.NewExtensionVariable({}))",
                        a.id(),
                        b
                    ));
                }
                DslIR::CircuitPoseidon2Permute(state) => {
                    let state_def = "state = [3]frontend.Variable{";
                    let state_args = state.iter().map(|x| x.id()).collect::<Vec<_>>().join(",");
                    state.iter().for_each(|x| {
                        self.assign(x.id());
                    });
                    let state_closure = "}";
                    lines.push(format!("{}{}{}", state_def, state_args, state_closure));
                    lines.push("p2.PermuteMut(&state)".to_string());
                    state
                        .iter()
                        .enumerate()
                        .for_each(|(i, s)| lines.push(format!("{} = state[{}]", s.id(), i)))
                }
                DslIR::CircuitNum2BitsV(var, num_bits, output) => {
                    lines.push(format!("state2 = api.ToBinary({}, {})", var.id(), num_bits));
                    for i in 0..num_bits {
                        let operator = self.assign(output[i].id());
                        lines.push(format!("{} {} state2[{}]", output[i].id(), operator, i));
                    }
                }
                DslIR::CircuitNum2BitsF(var, output) => {
                    lines.push(format!("state2 = babybearChip.ToBinary({})", var.id(),));
                    for i in 0..32 {
                        let operator = self.assign(output[i].id());
                        lines.push(format!("{} {} state2[{}]", output[i].id(), operator, i));
                    }
                }
                DslIR::PrintV(var) => {
                    lines.push(format!("api.Println({})", var.id()));
                }
                DslIR::PrintF(var) => {
                    lines.push(format!("babybearChip.PrintF({})", var.id()));
                }
                DslIR::PrintE(var) => {
                    lines.push(format!("babybearChip.PrintE({})", var.id()));
                }
                DslIR::CircuitSelectF(cond, a, b, c) => {
                    let assign = self.assign(c.id());
                    lines.push(format!(
                        "{} {} babybearChip.Select({}, {}, {})",
                        c.id(),
                        assign,
                        cond.id(),
                        a.id(),
                        b.id(),
                    ));
                }
                _ => todo!(),
            };
        }
        lines
    }

    pub fn compile(&mut self, program: Vec<DslIR<C>>) -> String {
        let operations = self.emit(program);
        let initializes = self
            .used
            .keys()
            .sorted()
            .map(|id| {
                if id.contains("var") {
                    format!("{} := frontend.Variable(0)", id)
                } else if id.contains("felt") {
                    format!("var {} *babybear.Variable", id)
                } else if id.contains("ext") {
                    format!("var {} *babybear.ExtensionVariable", id)
                } else if id.contains("backend") {
                    format!("var {} frontend.Variable", id)
                } else {
                    panic!("Unknown variable type")
                }
            })
            .collect::<Vec<_>>();
        let finalizes = self
            .used
            .keys()
            .sorted()
            .map(|id| format!("_ = {}", id))
            .collect::<Vec<_>>();

        let mut lines = Vec::new();
        lines.extend(vec!["".to_string(), "// Initializations.".to_string()]);
        lines.extend(initializes);
        lines.extend(vec!["".to_string(), "// Operations.".to_string()]);
        lines.extend(operations);
        lines.extend(vec!["".to_string(), "// Finalizes.".to_string()]);
        lines.extend(finalizes);
        GNARK_TEMPLATE.replace("{{LINES}}", &indent(lines).join("\n"))
    }
}

#[cfg(test)]
mod tests {

    use p3_baby_bear::BabyBear;
    use p3_field::{extension::BinomialExtensionField, AbstractField};

    use super::*;
    use crate::ir::{Felt, Usize, Var};
    use crate::prelude::Builder;

    #[derive(Clone)]
    struct BabyBearConfig;

    impl Config for BabyBearConfig {
        type N = BabyBear;
        type F = BabyBear;
        type EF = BinomialExtensionField<BabyBear, 4>;
    }

    #[test]
    fn test() {
        let program = vec![
            DslIR::Imm(Var::new(0), BabyBear::zero()),
            DslIR::AddV(Var::new(3), Var::new(0), Var::new(1)),
            DslIR::AddVI(Var::new(4), Var::new(3), BabyBear::one()),
            DslIR::Imm(Var::new(1), BabyBear::one()),
            DslIR::AddV(Var::new(2), Var::new(0), Var::new(1)),
            DslIR::AddVI(Var::new(3), Var::new(2), BabyBear::one()),
            DslIR::SubV(Var::new(4), Var::new(2), Var::new(3)),
            DslIR::SubVI(Var::new(5), Var::new(4), BabyBear::one()),
            DslIR::MulV(Var::new(6), Var::new(2), Var::new(5)),
            DslIR::MulVI(Var::new(7), Var::new(6), BabyBear::one()),
            DslIR::NegV(Var::new(9), Var::new(8)),
            DslIR::InvV(Var::new(10), Var::new(9)),
        ];
        let mut backend = GnarkBackend::<BabyBearConfig> {
            nb_backend_vars: 0,
            used: HashMap::new(),
            phantom: PhantomData,
        };
        let result = backend.compile(program);
        println!("{:?}", result);
    }

    #[test]
    fn test2() {
        let mut builder = Builder::<BabyBearConfig>::default();
        let t: Var<_> = builder.eval(BabyBear::zero());
        let a: Felt<_> = builder.eval(BabyBear::zero());
        let b: Felt<_> = builder.eval(BabyBear::one());

        let start = Usize::Const(0);
        let end = Usize::Const(12);

        builder.range(start, end).for_each(|_, builder| {
            let temp: Felt<_> = builder.uninit();
            builder.assign(temp, b);
            builder.assign(b, a + b);
            builder.assign(a, temp);
        });

        let expected_value = BabyBear::from_canonical_u32(144);
        builder.assert_felt_eq(a, expected_value);

        builder.if_eq(t, t).then_or_else(
            |builder| {
                builder.assign(a, b);
            },
            |builder| {
                builder.assign(a, a + b);
            },
        );
        builder.if_ne(t, t).then_or_else(
            |builder| {
                builder.assign(a, b);
            },
            |builder| {
                builder.assign(a, a + b);
            },
        );

        let mut backend = GnarkBackend::<BabyBearConfig> {
            nb_backend_vars: 0,
            used: HashMap::new(),
            phantom: PhantomData,
        };
        let result = backend.compile(builder.operations);
        println!("{}", result);
    }
}
