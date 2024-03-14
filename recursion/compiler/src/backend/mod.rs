use core::marker::PhantomData;
use std::collections::HashMap;

use crate::ir::{Config, DslIR};

const GNARK_TEMPLATE: &str = include_str!("gnark.txt");

pub fn indent(lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .map(|x| format!("        {}", x))
        .collect()
}

#[derive(Debug, Clone)]
pub struct GnarkBackend<C: Config> {
    pub used: HashMap<String, bool>,
    pub phantom: PhantomData<C>,
}

impl<C: Config> GnarkBackend<C> {
    pub fn assign(&mut self, id: String) -> &str {
        if *self.used.get(&id).unwrap_or(&false) {
            "="
        } else {
            self.used.insert(id.clone(), true);
            ":="
        }
    }

    pub fn emit(&mut self, operations: Vec<DslIR<C>>) -> Vec<String> {
        let mut lines: Vec<String> = Vec::new();
        for instruction in operations {
            match instruction {
                DslIR::Imm(a, b) => {
                    let operator = self.assign(a.id());
                    lines.push(format!("{} {} frontend.Variable({})", a.id(), operator, b));
                }
                DslIR::ImmFelt(a, b) => {
                    let operator = self.assign(a.id());
                    lines.push(format!("{} {} types.Felt({})", a.id(), operator, b));
                }
                DslIR::ImmExt(a, b) => {
                    let operator = self.assign(a.id());
                    lines.push(format!("{} {} types.Ext({})", a.id(), operator, b));
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
                        "{} {} api.Add({}, frontend.Variable({}))",
                        a.id(),
                        operator,
                        b.id(),
                        c
                    ));
                }
                DslIR::AddF(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} fieldChip.Add({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::AddFI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} fieldChip.Add({}, types.NewFelt({}))",
                        a.id(),
                        operator,
                        b.id(),
                        c
                    ));
                }
                DslIR::AddE(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} extensionChip.Add({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::AddEI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} extensionChip.Add({}, types.NewExt({}))",
                        a.id(),
                        operator,
                        b.id(),
                        c
                    ));
                }
                DslIR::AddEFI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} extensionChip.AddFelt({}, types.NewFelt({}))",
                        a.id(),
                        operator,
                        b.id(),
                        c
                    ));
                }
                DslIR::AddEFFI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} extensionChip.AddFelt(types.NewExt({}), {})",
                        a.id(),
                        operator,
                        c,
                        b.id()
                    ));
                }
                DslIR::AddEF(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} extensionChip.AddFelt({}, {})",
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
                        "{} {} api.Mul(frontend.Variable({}), {})",
                        a.id(),
                        operator,
                        b.id(),
                        c
                    ));
                }
                DslIR::MulF(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} fieldChip.Mul({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::MulFI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} fieldChip.Mul({}, types.NewFelt({}))",
                        a.id(),
                        operator,
                        b.id(),
                        c
                    ));
                }
                DslIR::MulE(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} extensionChip.Mul({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::MulEI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} extensionChip.Mul({}, types.NewExt({}))",
                        a.id(),
                        operator,
                        b.id(),
                        c
                    ));
                }
                DslIR::MulEFI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} extensionChip.MulFelt({}, types.NewFelt({}))",
                        a.id(),
                        operator,
                        c,
                        b.id()
                    ));
                }
                DslIR::MulEF(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} fieldChip.Mul({}, {})",
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
                        "{} {} fieldChip.Sub({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::SubFI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} fieldChip.Sub({}, types.NewFelt({}))",
                        a.id(),
                        operator,
                        b.id(),
                        c
                    ));
                }
                DslIR::SubFIN(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} fieldChip.Sub(types.NewFelt({}), {})",
                        a.id(),
                        operator,
                        b,
                        c.id()
                    ));
                }
                DslIR::SubE(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} extensionChip.Sub({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::SubEI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} extensionChip.Sub({}, types.NewExt({}))",
                        a.id(),
                        operator,
                        b.id(),
                        c
                    ));
                }
                DslIR::SubEIN(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} extensionChip.Sub(types.NewExt({}), {})",
                        a.id(),
                        operator,
                        b,
                        c.id()
                    ));
                }
                DslIR::SubEFI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} extensionChip.SubFelt({}, types.NewFelt({}))",
                        a.id(),
                        operator,
                        c,
                        b.id()
                    ));
                }
                DslIR::SubEFIN(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} extensionChip.SubFelt(types.NewExt({}), {})",
                        a.id(),
                        operator,
                        b,
                        c.id()
                    ));
                }
                DslIR::SubEF(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} extensionChip.SubFelt({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::DivF(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} fieldChip.Div({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::DivFI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} fieldChip.Div({}, types.NewFelt({}))",
                        a.id(),
                        operator,
                        b.id(),
                        c
                    ));
                }
                DslIR::DivFIN(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} fieldChip.Div(types.NewFelt({}), {})",
                        a.id(),
                        operator,
                        b,
                        c.id()
                    ));
                }
                DslIR::DivE(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} extensionChip.Div({}, {})",
                        a.id(),
                        operator,
                        b.id(),
                        c.id()
                    ));
                }
                DslIR::DivEI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} extensionChip.Div({}, types.NewExt({}))",
                        a.id(),
                        operator,
                        b.id(),
                        c
                    ));
                }
                DslIR::DivEIN(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} extensionChip.Div(types.NewExt({}), {})",
                        a.id(),
                        operator,
                        b,
                        c.id()
                    ));
                }
                DslIR::DivEFI(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} extensionChip.DivFelt({}, types.NewFelt({}))",
                        a.id(),
                        operator,
                        c,
                        b.id()
                    ));
                }
                DslIR::DivEFIN(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} extensionChip.DivFelt(types.NewExt({}), {})",
                        a.id(),
                        operator,
                        b,
                        c.id()
                    ));
                }
                DslIR::DivEF(a, b, c) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} extensionChip.DivFelt({}, {})",
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
                    lines.push(format!("{} {} fieldChip.Neg({})", a.id(), operator, b.id()));
                }
                DslIR::NegE(a, b) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} extensionChip.Neg({})",
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
                    lines.push(format!("{} {} fieldChip.Inv({})", a.id(), operator, b.id()));
                }
                DslIR::InvE(a, b) => {
                    let operator = self.assign(a.id());
                    lines.push(format!(
                        "{} {} extensionChip.Inv({})",
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
                DslIR::IfEq(_, _, _, _) => {
                    todo!()
                }
                DslIR::IfNe(_, _, _, _) => {
                    todo!()
                }
                DslIR::IfEqI(_, _, _, _) => {
                    todo!()
                }
                DslIR::IfNeI(_, _, _, _) => {
                    todo!()
                }
                DslIR::AssertEqV(a, b) => {
                    lines.push(format!("api.AssertEq({}, {})", a.id(), b.id()));
                }
                DslIR::AssertNeV(a, b) => {
                    lines.push(format!("api.AssertNe({}, {})", a.id(), b.id()));
                }
                DslIR::AssertEqF(a, b) => {
                    lines.push(format!("fieldChip.AssertEq({}, {})", a.id(), b.id()));
                }
                DslIR::AssertNeF(a, b) => {
                    lines.push(format!("fieldChip.AssertNe({}, {})", a.id(), b.id()));
                }
                DslIR::AssertEqE(a, b) => {
                    lines.push(format!("extensionChip.AssertEq({}, {})", a.id(), b.id()));
                }
                DslIR::AssertNeE(a, b) => {
                    lines.push(format!("extensionChip.AssertNe({}, {})", a.id(), b.id()));
                }
                DslIR::AssertEqVI(a, b) => {
                    lines.push(format!(
                        "api.AssertEq({}, frontend.Variable({}))",
                        a.id(),
                        b
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
                        "fieldChip.AssertEq({}, types.NewFelt({}))",
                        a.id(),
                        b
                    ));
                }
                DslIR::AssertNeFI(a, b) => {
                    lines.push(format!(
                        "fieldChip.AssertNe({}, types.NewFelt({}))",
                        a.id(),
                        b
                    ));
                }
                DslIR::AssertEqEI(a, b) => {
                    lines.push(format!(
                        "extensionChip.AssertEq({}, types.NewExt({}))",
                        a.id(),
                        b
                    ));
                }
                DslIR::AssertNeEI(a, b) => {
                    lines.push(format!(
                        "extensionChip.AssertNe({}, types.NewExt({}))",
                        a.id(),
                        b
                    ));
                }
            };
        }
        lines
    }

    pub fn compile(&mut self, program: Vec<DslIR<C>>) -> String {
        let lines = self.emit(program);
        GNARK_TEMPLATE.replace("{{LINES}}", &indent(lines).join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::{extension::BinomialExtensionField, AbstractField};

    use crate::ir::{Felt, Usize, Var};
    use crate::prelude::Builder;

    use super::*;

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
            used: HashMap::new(),
            phantom: PhantomData,
        };
        let result = backend.compile(program);
        println!("{:?}", result);
    }

    #[test]
    fn test2() {
        let mut builder = Builder::<BabyBearConfig>::default();
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

        let mut backend = GnarkBackend::<BabyBearConfig> {
            used: HashMap::new(),
            phantom: PhantomData,
        };
        let result = backend.compile(builder.operations);
        println!("{}", result);
    }
}
