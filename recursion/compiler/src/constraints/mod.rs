pub mod gnark_ffi;

use core::fmt::Debug;
use p3_field::AbstractExtensionField;
use p3_field::PrimeField;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use crate::prelude::{Config, DslIR};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConstraintOpcode {
    ImmV,
    ImmF,
    ImmE,
    AddV,
    AddF,
    AddE,
    AddEF,
    SubV,
    SubF,
    SubE,
    MulV,
    MulF,
    MulE,
    MulEF,
    DivF,
    DivE,
    DivEF,
    NegV,
    NegF,
    NegE,
    InvV,
    InvF,
    InvE,
    AssertEqV,
    AssertEqF,
    AssertEqE,
    Permute,
    Num2BitsV,
    Num2BitsF,
    SelectV,
    SelectF,
    Ext2Felt,
    PrintV,
    PrintF,
    PrintE,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    pub opcode: ConstraintOpcode,
    pub args: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Default)]
pub struct ConstraintBackend<C: Config> {
    pub allocator: usize,
    pub phantom: PhantomData<C>,
}

impl<C: Config + Debug> ConstraintBackend<C> {
    pub fn alloc_id(&mut self) -> String {
        let id = self.allocator;
        self.allocator += 1;
        format!("backend{}", id)
    }

    pub fn alloc_v(&mut self, constraints: &mut Vec<Constraint>, value: C::N) -> String {
        let tmp_id = self.alloc_id();
        constraints.push(Constraint {
            opcode: ConstraintOpcode::ImmV,
            args: vec![
                vec![tmp_id.clone()],
                vec![value.as_canonical_biguint().to_string()],
            ],
        });
        tmp_id
    }

    pub fn alloc_f(&mut self, constraints: &mut Vec<Constraint>, value: C::F) -> String {
        let tmp_id = self.alloc_id();
        constraints.push(Constraint {
            opcode: ConstraintOpcode::ImmF,
            args: vec![
                vec![tmp_id.clone()],
                vec![value.as_canonical_biguint().to_string()],
            ],
        });
        tmp_id
    }

    pub fn alloc_e(&mut self, constraints: &mut Vec<Constraint>, value: C::EF) -> String {
        let tmp_id = self.alloc_id();
        constraints.push(Constraint {
            opcode: ConstraintOpcode::ImmE,
            args: vec![
                vec![tmp_id.clone()],
                value
                    .as_base_slice()
                    .iter()
                    .map(|x| x.as_canonical_biguint().to_string())
                    .collect(),
            ],
        });
        tmp_id
    }

    pub fn emit(&mut self, operations: Vec<DslIR<C>>) -> Vec<Constraint> {
        let mut constraints: Vec<Constraint> = Vec::new();
        for instruction in operations {
            match instruction {
                DslIR::Imm(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::ImmV,
                    args: vec![vec![a.id()], vec![b.as_canonical_biguint().to_string()]],
                }),
                DslIR::ImmFelt(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::ImmF,
                    args: vec![vec![a.id()], vec![b.as_canonical_biguint().to_string()]],
                }),
                DslIR::ImmExt(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::ImmE,
                    args: vec![
                        vec![a.id()],
                        b.as_base_slice()
                            .iter()
                            .map(|x| x.as_canonical_biguint().to_string())
                            .collect(),
                    ],
                }),
                DslIR::AddV(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AddV,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIR::AddVI(a, b, c) => {
                    let tmp = self.alloc_v(&mut constraints, c);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AddV,
                        args: vec![vec![a.id()], vec![b.id()], vec![tmp]],
                    });
                }
                DslIR::AddF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AddF,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIR::AddFI(a, b, c) => {
                    let tmp = self.alloc_f(&mut constraints, c);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AddF,
                        args: vec![vec![a.id()], vec![b.id()], vec![tmp]],
                    });
                }
                DslIR::AddE(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AddE,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIR::AddEF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AddEF,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIR::AddEI(a, b, c) => {
                    let tmp = self.alloc_e(&mut constraints, c);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AddE,
                        args: vec![vec![a.id()], vec![b.id()], vec![tmp]],
                    });
                }
                DslIR::AddEFFI(a, b, c) => {
                    let tmp = self.alloc_e(&mut constraints, c);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AddEF,
                        args: vec![vec![a.id()], vec![tmp], vec![b.id()]],
                    });
                }
                DslIR::SubV(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::SubV,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIR::SubF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::SubF,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIR::SubE(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::SubE,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIR::MulV(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::MulV,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIR::MulVI(a, b, c) => {
                    let tmp = self.alloc_v(&mut constraints, c);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::MulV,
                        args: vec![vec![a.id()], vec![b.id()], vec![tmp]],
                    });
                }
                DslIR::MulF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::MulF,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIR::MulE(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::MulE,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIR::MulEI(a, b, c) => {
                    let tmp = self.alloc_e(&mut constraints, c);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::MulE,
                        args: vec![vec![a.id()], vec![b.id()], vec![tmp]],
                    });
                }
                DslIR::MulEF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::MulEF,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIR::DivE(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::DivE,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIR::NegE(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::NegE,
                    args: vec![vec![a.id()], vec![b.id()]],
                }),
                DslIR::CircuitNum2BitsV(value, bits, output) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::Num2BitsV,
                    args: vec![
                        output.iter().map(|x| x.id()).collect(),
                        vec![value.id()],
                        vec![bits.to_string()],
                    ],
                }),
                DslIR::CircuitNum2BitsF(value, output) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::Num2BitsF,
                    args: vec![output.iter().map(|x| x.id()).collect(), vec![value.id()]],
                }),
                DslIR::CircuitPoseidon2Permute(state) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::Permute,
                    args: state.iter().map(|x| vec![x.id()]).collect(),
                }),
                DslIR::CircuitSelectV(cond, a, b, out) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::SelectV,
                        args: vec![vec![out.id()], vec![cond.id()], vec![a.id()], vec![b.id()]],
                    });
                }
                DslIR::CircuitSelectF(cond, a, b, out) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::SelectF,
                        args: vec![vec![out.id()], vec![cond.id()], vec![a.id()], vec![b.id()]],
                    });
                }
                DslIR::CircuitExt2Felt(a, b) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::Ext2Felt,
                        args: vec![
                            vec![a[0].id()],
                            vec![a[1].id()],
                            vec![a[2].id()],
                            vec![a[3].id()],
                            vec![b.id()],
                        ],
                    });
                }
                DslIR::AssertEqV(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AssertEqV,
                    args: vec![vec![a.id()], vec![b.id()]],
                }),
                DslIR::AssertEqVI(a, b) => {
                    let tmp = self.alloc_v(&mut constraints, b);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AssertEqV,
                        args: vec![vec![a.id()], vec![tmp]],
                    });
                }
                DslIR::AssertEqF(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AssertEqF,
                    args: vec![vec![a.id()], vec![b.id()]],
                }),
                DslIR::AssertEqFI(a, b) => {
                    let tmp = self.alloc_f(&mut constraints, b);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AssertEqF,
                        args: vec![vec![a.id()], vec![tmp]],
                    });
                }
                DslIR::AssertEqE(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AssertEqE,
                    args: vec![vec![a.id()], vec![b.id()]],
                }),
                DslIR::AssertEqEI(a, b) => {
                    let tmp = self.alloc_e(&mut constraints, b);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AssertEqE,
                        args: vec![vec![a.id()], vec![tmp]],
                    });
                }
                DslIR::PrintV(a) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::PrintV,
                    args: vec![vec![a.id()]],
                }),
                DslIR::PrintF(a) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::PrintF,
                    args: vec![vec![a.id()]],
                }),
                DslIR::PrintE(a) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::PrintE,
                    args: vec![vec![a.id()]],
                }),
                _ => panic!("unsupported {:?}", instruction),
            };
        }
        constraints
    }
}

#[cfg(test)]
mod tests {

    use p3_baby_bear::BabyBear;
    use p3_bn254_fr::Bn254Fr;
    use p3_field::{extension::BinomialExtensionField, AbstractField};

    use super::*;
    use crate::{
        ir::Var,
        prelude::{Builder, Ext, Felt},
        OuterConfig,
    };

    #[test]
    fn test_imm() {
        let program = vec![
            DslIR::Imm(Var::new(0), Bn254Fr::zero()),
            DslIR::ImmFelt(Felt::new(1), BabyBear::one()),
            DslIR::ImmExt(Ext::new(2), BinomialExtensionField::<BabyBear, 4>::one()),
            DslIR::PrintV(Var::new(0)),
            DslIR::PrintF(Felt::new(1)),
            DslIR::PrintE(Ext::new(2)),
        ];
        let mut backend = ConstraintBackend::<OuterConfig>::default();
        let constraints = backend.emit(program);
        gnark_ffi::test_circuit(constraints);
    }

    #[test]
    fn test_basic_program() {
        let mut builder = Builder::<OuterConfig>::default();
        let a: Var<_> = builder.eval(Bn254Fr::two());
        let b: Var<_> = builder.eval(Bn254Fr::from_canonical_u32(100));
        let c: Var<_> = builder.eval(a * b);
        builder.assert_var_eq(c, Bn254Fr::from_canonical_u32(200));

        let mut backend = ConstraintBackend::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);
        gnark_ffi::test_circuit(constraints);
    }

    #[test]
    fn test_num2bits_v() {
        let mut builder = Builder::<OuterConfig>::default();
        let value_u32 = 100;
        let a: Var<_> = builder.eval(Bn254Fr::from_canonical_u32(value_u32));
        let bits = builder.num2bits_v_circuit(a, 32);
        for i in 0..32 {
            builder.assert_var_eq(bits[i], Bn254Fr::from_canonical_u32((value_u32 >> i) & 1));
        }

        let mut backend = ConstraintBackend::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);
        gnark_ffi::test_circuit(constraints);
    }
}
