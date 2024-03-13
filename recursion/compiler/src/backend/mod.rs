use core::marker::PhantomData;

use crate::ir::{Config, DslIR};

#[derive(Debug, Clone)]
pub struct GnarkBackend<C: Config> {
    pub phantom: PhantomData<C>,
}

impl<C: Config> GnarkBackend<C> {
    pub fn emit(&mut self, program: Vec<DslIR<C>>) -> String {
        let mut lines: Vec<String> = Vec::new();
        for instruction in program {
            match instruction {
                // Variables.
                DslIR::Imm(a, b) => {
                    lines.push(format!("{} := frontend.Variable({})", a.id(), b));
                }
                DslIR::AddV(a, b, c) => {
                    lines.push(format!("{} := api.Add({}, {})", a.id(), b.id(), c.id()));
                }
                DslIR::AddVI(a, b, c) => {
                    lines.push(format!(
                        "{} := api.Add({}, frontend.Variable({}))",
                        a.id(),
                        b.id(),
                        c
                    ));
                }
                DslIR::SubV(a, b, c) => {
                    lines.push(format!("{} := api.Sub({}, {})", a.id(), b.id(), c.id()));
                }
                DslIR::SubVI(a, b, c) => {
                    lines.push(format!(
                        "{} := api.Sub(frontend.Variable({}), {})",
                        a.id(),
                        b.id(),
                        c
                    ));
                }
                DslIR::MulV(a, b, c) => {
                    lines.push(format!("{} := api.Mul({}, {})", a.id(), b.id(), c.id()));
                }
                DslIR::MulVI(a, b, c) => {
                    lines.push(format!(
                        "{} := api.Mul(frontend.Variable({}), {})",
                        a.id(),
                        b.id(),
                        c
                    ));
                }
                DslIR::DivV(a, b, c) => {
                    lines.push(format!("{} := api.Div({}, {})", a.id(), b.id(), c.id()));
                }
                DslIR::DivVI(a, b, c) => {
                    lines.push(format!(
                        "{} := api.Div(frontend.Variable({}), {})",
                        a.id(),
                        b.id(),
                        c
                    ));
                }
                DslIR::NegV(a, b) => {
                    lines.push(format!("{} := api.Neg({})", a.id(), b.id()));
                }
                DslIR::InvV(a, b) => {
                    lines.push(format!("{} := api.Inv({})", a.id(), b.id()));
                }
                // Felts.
                DslIR::ImmFelt(a, b) => {
                    lines.push(format!("{} := types.Felt({})", a.id(), b));
                }
                DslIR::ImmExt(a, b) => {
                    lines.push(format!("{} := types.Ext({})", a.id(), b));
                }
                _ => todo!(),
            }
        }
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::{extension::BinomialExtensionField, AbstractField};

    use crate::ir::Var;

    use super::*;

    struct BabyBearConfig;

    impl Config for BabyBearConfig {
        type N = BabyBear;
        type F = BabyBear;
        type EF = BinomialExtensionField<BabyBear, 4>;
    }

    #[test]
    fn test() {
        let mut backend = GnarkBackend::<BabyBearConfig> {
            phantom: PhantomData,
        };
        let program = vec![
            DslIR::Imm(Var::new(0), BabyBear::zero()),
            DslIR::Imm(Var::new(1), BabyBear::one()),
            DslIR::AddV(Var::new(2), Var::new(0), Var::new(1)),
            DslIR::AddVI(Var::new(3), Var::new(2), BabyBear::one()),
            DslIR::SubV(Var::new(4), Var::new(2), Var::new(3)),
            DslIR::SubVI(Var::new(5), Var::new(4), BabyBear::one()),
            DslIR::MulV(Var::new(6), Var::new(2), Var::new(5)),
            DslIR::MulVI(Var::new(7), Var::new(6), BabyBear::one()),
            DslIR::DivV(Var::new(7), Var::new(6), Var::new(5)),
            DslIR::DivVI(Var::new(8), Var::new(7), BabyBear::one()),
            DslIR::NegV(Var::new(9), Var::new(8)),
            DslIR::InvV(Var::new(10), Var::new(9)),
        ];
        let result = backend.emit(program);
        println!("{}", result);
    }
}
