use core::marker::PhantomData;

use crate::ir::{Config, DslIR};

const GNARK_TEMPLATE: &str = include_str!("gnark.txt");

#[derive(Debug, Clone)]
pub struct GnarkBackend<C: Config> {
    pub phantom: PhantomData<C>,
}

impl<C: Config> GnarkBackend<C> {
    pub fn emit(program: Vec<DslIR<C>>) -> String {
        let mut lines: Vec<String> = Vec::new();
        for instruction in program {
            let line = match instruction {
                DslIR::Imm(a, b) => {
                    format!("{} := frontend.Variable({})", a.id(), b)
                }
                DslIR::ImmFelt(a, b) => {
                    format!("{} := types.Felt({})", a.id(), b)
                }
                DslIR::ImmExt(a, b) => {
                    format!("{} := types.Ext({})", a.id(), b)
                }
                DslIR::AddV(a, b, c) => {
                    format!("{} := api.Add({}, {})", a.id(), b.id(), c.id())
                }
                DslIR::AddVI(a, b, c) => {
                    format!(
                        "{} := api.Add({}, frontend.Variable({}))",
                        a.id(),
                        b.id(),
                        c
                    )
                }
                DslIR::AddF(a, b, c) => {
                    format!("{} := fieldChip.Add({}, {})", a.id(), b.id(), c.id())
                }
                DslIR::AddFI(a, b, c) => {
                    format!(
                        "{} := fieldChip.Add({}, types.NewFelt({}))",
                        a.id(),
                        b.id(),
                        c
                    )
                }
                DslIR::AddE(a, b, c) => {
                    format!("{} := extensionChip.Add({}, {})", a.id(), b.id(), c.id())
                }
                DslIR::AddEI(a, b, c) => {
                    format!(
                        "{} := extensionChip.Add({}, types.NewExt({}))",
                        a.id(),
                        b.id(),
                        c
                    )
                }
                DslIR::AddEFI(a, b, c) => {
                    format!(
                        "{} := extensionChip.AddFelt({}, types.NewFelt({}))",
                        a.id(),
                        b.id(),
                        c
                    )
                }
                DslIR::AddEFFI(a, b, c) => {
                    format!(
                        "{} := extensionChip.AddFelt(types.NewExt({}), {})",
                        a.id(),
                        c,
                        b.id()
                    )
                }
                DslIR::AddEF(a, b, c) => {
                    format!(
                        "{} := extensionChip.AddFelt({}, {})",
                        a.id(),
                        b.id(),
                        c.id()
                    )
                }
                DslIR::MulV(a, b, c) => {
                    format!("{} := api.Mul({}, {})", a.id(), b.id(), c.id())
                }
                DslIR::MulVI(a, b, c) => {
                    format!(
                        "{} := api.Mul(frontend.Variable({}), {})",
                        a.id(),
                        b.id(),
                        c
                    )
                }
                DslIR::MulF(a, b, c) => {
                    format!("{} := fieldChip.Mul({}, {})", a.id(), b.id(), c.id())
                }
                DslIR::MulFI(a, b, c) => {
                    format!(
                        "{} := fieldChip.Mul({}, types.NewFelt({}))",
                        a.id(),
                        b.id(),
                        c
                    )
                }
                DslIR::MulE(a, b, c) => {
                    format!("{} := extensionChip.Mul({}, {})", a.id(), b.id(), c.id())
                }
                DslIR::MulEI(a, b, c) => {
                    format!(
                        "{} := extensionChip.Mul({}, types.NewExt({}))",
                        a.id(),
                        b.id(),
                        c
                    )
                }
                DslIR::MulEFI(a, b, c) => {
                    format!(
                        "{} := extensionChip.MulFelt({}, types.NewFelt({}))",
                        a.id(),
                        c,
                        b.id()
                    )
                }
                DslIR::MulEF(a, b, c) => {
                    format!("{} := fieldChip.Mul({}, {})", a.id(), b.id(), c.id())
                }
                DslIR::SubV(a, b, c) => {
                    format!("{} := api.Sub({}, {})", a.id(), b.id(), c.id())
                }
                DslIR::SubVI(a, b, c) => {
                    format!(
                        "{} := api.Sub(frontend.Variable({}), {})",
                        a.id(),
                        b.id(),
                        c
                    )
                }
                DslIR::SubVIN(a, b, c) => {
                    format!(
                        "{} := api.Sub(frontend.Variable({}), {})",
                        a.id(),
                        b,
                        c.id()
                    )
                }
                DslIR::SubF(a, b, c) => {
                    format!("{} := fieldChip.Sub({}, {})", a.id(), b.id(), c.id())
                }
                DslIR::SubFI(a, b, c) => {
                    format!(
                        "{} := fieldChip.Sub({}, types.NewFelt({}))",
                        a.id(),
                        b.id(),
                        c
                    )
                }
                DslIR::SubFIN(a, b, c) => {
                    format!(
                        "{} := fieldChip.Sub(types.NewFelt({}), {})",
                        a.id(),
                        b,
                        c.id()
                    )
                }
                DslIR::SubE(a, b, c) => {
                    format!("{} := extensionChip.Sub({}, {})", a.id(), b.id(), c.id())
                }
                DslIR::SubEI(a, b, c) => {
                    format!(
                        "{} := extensionChip.Sub({}, types.NewExt({}))",
                        a.id(),
                        b.id(),
                        c
                    )
                }
                DslIR::SubEIN(a, b, c) => {
                    format!(
                        "{} := extensionChip.Sub(types.NewExt({}), {})",
                        a.id(),
                        b,
                        c.id()
                    )
                }
                DslIR::SubEFI(a, b, c) => {
                    format!(
                        "{} := extensionChip.SubFelt({}, types.NewFelt({}))",
                        a.id(),
                        c,
                        b.id()
                    )
                }
                DslIR::SubEFIN(a, b, c) => {
                    format!(
                        "{} := extensionChip.SubFelt(types.NewExt({}), {})",
                        a.id(),
                        b,
                        c.id()
                    )
                }
                DslIR::SubEF(a, b, c) => {
                    format!(
                        "{} := extensionChip.SubFelt({}, {})",
                        a.id(),
                        b.id(),
                        c.id()
                    )
                }
                DslIR::DivF(a, b, c) => {
                    format!("{} := fieldChip.Div({}, {})", a.id(), b.id(), c.id())
                }
                DslIR::DivFI(a, b, c) => {
                    format!(
                        "{} := fieldChip.Div({}, types.NewFelt({}))",
                        a.id(),
                        b.id(),
                        c
                    )
                }
                DslIR::DivFIN(a, b, c) => {
                    format!(
                        "{} := fieldChip.Div(types.NewFelt({}), {})",
                        a.id(),
                        b,
                        c.id()
                    )
                }
                DslIR::DivE(a, b, c) => {
                    format!("{} := extensionChip.Div({}, {})", a.id(), b.id(), c.id())
                }
                DslIR::DivEI(a, b, c) => {
                    format!(
                        "{} := extensionChip.Div({}, types.NewExt({}))",
                        a.id(),
                        b.id(),
                        c
                    )
                }
                DslIR::DivEIN(a, b, c) => {
                    format!(
                        "{} := extensionChip.Div(types.NewExt({}), {})",
                        a.id(),
                        b,
                        c.id()
                    )
                }
                DslIR::DivEFI(a, b, c) => {
                    format!(
                        "{} := extensionChip.DivFelt({}, types.NewFelt({}))",
                        a.id(),
                        c,
                        b.id()
                    )
                }
                DslIR::DivEFIN(a, b, c) => {
                    format!(
                        "{} := extensionChip.DivFelt(types.NewExt({}), {})",
                        a.id(),
                        b,
                        c.id()
                    )
                }
                DslIR::DivEF(a, b, c) => {
                    format!(
                        "{} := extensionChip.DivFelt({}, {})",
                        a.id(),
                        b.id(),
                        c.id()
                    )
                }
                DslIR::NegV(a, b) => {
                    format!("{} := api.Neg({})", a.id(), b.id())
                }
                DslIR::NegF(a, b) => {
                    format!("{} := fieldChip.Neg({})", a.id(), b.id())
                }
                DslIR::NegE(a, b) => {
                    format!("{} := extensionChip.Neg({})", a.id(), b.id())
                }
                DslIR::InvV(a, b) => {
                    format!("{} := api.Inv({})", a.id(), b.id())
                }
                DslIR::InvF(a, b) => {
                    format!("{} := fieldChip.Inv({})", a.id(), b.id())
                }
                DslIR::InvE(a, b) => {
                    format!("{} := extensionChip.Inv({})", a.id(), b.id())
                }
                DslIR::For(a, b, _, d) => [
                    format!("for i := {}; i < {}; i++ {{", a.value(), b.value()),
                    Self::emit(d),
                    "}".to_string(),
                ]
                .join("\n"),
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
                    format!("api.AssertEq({}, {})", a.id(), b.id())
                }
                DslIR::AssertNeV(a, b) => {
                    format!("api.AssertNe({}, {})", a.id(), b.id())
                }
                DslIR::AssertEqF(a, b) => {
                    format!("fieldChip.AssertEq({}, {})", a.id(), b.id())
                }
                DslIR::AssertNeF(a, b) => {
                    format!("fieldChip.AssertNe({}, {})", a.id(), b.id())
                }
                DslIR::AssertEqE(a, b) => {
                    format!("extensionChip.AssertEq({}, {})", a.id(), b.id())
                }
                DslIR::AssertNeE(a, b) => {
                    format!("extensionChip.AssertNe({}, {})", a.id(), b.id())
                }
                DslIR::AssertEqVI(a, b) => {
                    format!("api.AssertEq({}, frontend.Variable({}))", a.id(), b)
                }
                DslIR::AssertNeVI(a, b) => {
                    format!("api.AssertNe({}, frontend.Variable({}))", a.id(), b)
                }
                DslIR::AssertEqFI(a, b) => {
                    format!("fieldChip.AssertEq({}, types.NewFelt({}))", a.id(), b)
                }
                DslIR::AssertNeFI(a, b) => {
                    format!("fieldChip.AssertNe({}, types.NewFelt({}))", a.id(), b)
                }
                DslIR::AssertEqEI(a, b) => {
                    format!("extensionChip.AssertEq({}, types.NewExt({}))", a.id(), b)
                }
                DslIR::AssertNeEI(a, b) => {
                    format!("extensionChip.AssertNe({}, types.NewExt({}))", a.id(), b)
                }
            };
            lines.push(line);
        }
        let lines = lines.join("\n        ");
        GNARK_TEMPLATE.replace("{{LINES}}", &lines)
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::{extension::BinomialExtensionField, AbstractField};

    use crate::ir::Var;

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
        let result = GnarkBackend::<BabyBearConfig>::emit(program);
        println!("{}", result);
    }
}
