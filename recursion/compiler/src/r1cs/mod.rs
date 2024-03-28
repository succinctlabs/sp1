use std::marker::PhantomData;

use p3_field::AbstractExtensionField;
use serde::{Deserialize, Serialize};

use crate::prelude::{Config, DslIR};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConstraintOpcode {
    ImmV = 0,
    ImmF = 1,
    ImmE = 2,
    AddV = 3,
    AddF = 4,
    AddE = 5,
    AddEF = 6,
    MulV = 7,
    MulF = 8,
    MulE = 9,
    MulEF = 10,
    SubV = 11,
    SubF = 12,
    SubE = 13,
    SubEF = 14,
    DivF = 15,
    DivE = 16,
    DivEF = 17,
    NegV = 18,
    NegF = 19,
    NegE = 20,
    InvV = 21,
    InvF = 22,
    InvE = 23,
    AssertEqV = 24,
    AssertEqF = 25,
    AssertEqE = 26,
    Permute = 27,
    Num2BitsV = 28,
    Num2BitsF = 29,
    PrintV = 30,
    PrintF = 31,
    PrintE = 32,
    SelectF = 33,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    pub opcode: ConstraintOpcode,
    pub args: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Default)]
pub struct R1CSBackend<C: Config> {
    pub phantom: PhantomData<C>,
}

impl<C: Config> R1CSBackend<C> {
    pub fn emit(&mut self, operations: Vec<DslIR<C>>) -> Vec<Constraint> {
        let mut constraints: Vec<Constraint> = Vec::new();
        for instruction in operations {
            match instruction {
                DslIR::Imm(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::ImmV,
                    args: vec![vec![a.loc()], vec![b.to_string()]],
                }),
                DslIR::ImmFelt(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::ImmF,
                    args: vec![vec![a.loc()], vec![b.to_string()]],
                }),
                DslIR::ImmExt(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::ImmE,
                    args: vec![
                        vec![a.loc()],
                        b.as_base_slice().iter().map(|x| x.to_string()).collect(),
                    ],
                }),
                DslIR::AddV(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AddV,
                    args: vec![vec![a.loc()], vec![b.loc()], vec![c.loc()]],
                }),
                DslIR::AddF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AddF,
                    args: vec![vec![a.loc()], vec![b.loc()], vec![c.loc()]],
                }),
                DslIR::AddE(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AddE,
                    args: vec![vec![a.loc()], vec![b.loc()], vec![c.loc()]],
                }),
                DslIR::AddEF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AddEF,
                    args: vec![vec![a.loc()], vec![b.loc()], vec![c.loc()]],
                }),
                DslIR::MulV(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::MulV,
                    args: vec![vec![a.loc()], vec![b.loc()], vec![c.loc()]],
                }),
                DslIR::MulF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::MulF,
                    args: vec![vec![a.loc()], vec![b.loc()], vec![c.loc()]],
                }),
                DslIR::MulE(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::MulE,
                    args: vec![vec![a.loc()], vec![b.loc()], vec![c.loc()]],
                }),
                DslIR::MulEF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::MulEF,
                    args: vec![vec![a.loc()], vec![b.loc()], vec![c.loc()]],
                }),
                DslIR::SubV(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::SubV,
                    args: vec![vec![a.loc()], vec![b.loc()], vec![c.loc()]],
                }),
                DslIR::SubF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::SubF,
                    args: vec![vec![a.loc()], vec![b.loc()], vec![c.loc()]],
                }),
                DslIR::SubE(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::SubE,
                    args: vec![vec![a.loc()], vec![b.loc()], vec![c.loc()]],
                }),
                DslIR::SubEF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::SubEF,
                    args: vec![vec![a.loc()], vec![b.loc()], vec![c.loc()]],
                }),
                DslIR::DivF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::DivF,
                    args: vec![vec![a.loc()], vec![b.loc()], vec![c.loc()]],
                }),
                DslIR::DivE(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::DivE,
                    args: vec![vec![a.loc()], vec![b.loc()], vec![c.loc()]],
                }),
                DslIR::DivEF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::DivEF,
                    args: vec![vec![a.loc()], vec![b.loc()], vec![c.loc()]],
                }),
                DslIR::NegV(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::NegV,
                    args: vec![vec![a.loc()], vec![b.loc()]],
                }),
                DslIR::NegF(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::NegF,
                    args: vec![vec![a.loc()], vec![b.loc()]],
                }),
                DslIR::NegE(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::NegE,
                    args: vec![vec![a.loc()], vec![b.loc()]],
                }),
                DslIR::InvV(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::InvV,
                    args: vec![vec![a.loc()], vec![b.loc()]],
                }),
                DslIR::InvF(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::InvF,
                    args: vec![vec![a.loc()], vec![b.loc()]],
                }),
                DslIR::InvE(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::InvE,
                    args: vec![vec![a.loc()], vec![b.loc()]],
                }),
                DslIR::AssertEqV(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AssertEqV,
                    args: vec![vec![a.loc()], vec![b.loc()]],
                }),
                DslIR::AssertEqF(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AssertEqF,
                    args: vec![vec![a.loc()], vec![b.loc()]],
                }),
                DslIR::AssertEqE(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AssertEqE,
                    args: vec![vec![a.loc()], vec![b.loc()]],
                }),
                DslIR::PrintV(a) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::PrintV,
                    args: vec![vec![a.loc()]],
                }),
                DslIR::PrintF(a) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::PrintF,
                    args: vec![vec![a.loc()]],
                }),
                DslIR::PrintE(a) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::PrintE,
                    args: vec![vec![a.loc()]],
                }),
                _ => todo!(),
            };
        }
        constraints
    }
}

#[cfg(test)]
mod tests {

    use p3_baby_bear::BabyBear;
    use p3_field::{extension::BinomialExtensionField, AbstractField};

    use super::*;
    use crate::{
        ir::Var,
        prelude::{Ext, Felt},
    };

    #[derive(Clone, Default)]
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
            DslIR::ImmFelt(Felt::new(1), BabyBear::one()),
            DslIR::ImmExt(Ext::new(2), BinomialExtensionField::<BabyBear, 4>::one()),
        ];
        let mut backend = R1CSBackend::<BabyBearConfig>::default();
        let result = backend.emit(program);
        let serialized = serde_json::to_string(&result).unwrap();
        println!("{:}", serialized);
    }
}
