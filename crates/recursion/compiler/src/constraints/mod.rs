pub mod opcodes;

use core::fmt::Debug;
use p3_field::{AbstractExtensionField, PrimeField};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use self::opcodes::ConstraintOpcode;
use crate::{
    ir::{Config, DslIr},
    prelude::TracedVec,
};

/// A constraint is an operation and a list of nested arguments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    pub opcode: ConstraintOpcode,
    pub args: Vec<Vec<String>>,
}

/// The backend for the constraint compiler.
#[derive(Debug, Clone, Default)]
pub struct ConstraintCompiler<C: Config> {
    pub allocator: usize,
    pub phantom: PhantomData<C>,
}

impl<C: Config + Debug> ConstraintCompiler<C> {
    /// Allocate a new variable name in the constraint system.
    pub fn alloc_id(&mut self) -> String {
        let id = self.allocator;
        self.allocator += 1;
        format!("backend{}", id)
    }

    /// Allocates a variable in the constraint system.
    pub fn alloc_v(&mut self, constraints: &mut Vec<Constraint>, value: C::N) -> String {
        let tmp_id = self.alloc_id();
        constraints.push(Constraint {
            opcode: ConstraintOpcode::ImmV,
            args: vec![vec![tmp_id.clone()], vec![value.as_canonical_biguint().to_string()]],
        });
        tmp_id
    }

    /// Allocate a felt in the constraint system.
    pub fn alloc_f(&mut self, constraints: &mut Vec<Constraint>, value: C::F) -> String {
        let tmp_id = self.alloc_id();
        constraints.push(Constraint {
            opcode: ConstraintOpcode::ImmF,
            args: vec![vec![tmp_id.clone()], vec![value.as_canonical_biguint().to_string()]],
        });
        tmp_id
    }

    /// Allocate an extension element in the constraint system.
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

    /// Emit the constraints from a list of operations in the DSL.
    pub fn emit(&mut self, operations: TracedVec<DslIr<C>>) -> Vec<Constraint> {
        let mut constraints: Vec<Constraint> = Vec::new();
        for (instruction, _) in operations {
            match instruction {
                DslIr::ImmV(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::ImmV,
                    args: vec![vec![a.id()], vec![b.as_canonical_biguint().to_string()]],
                }),
                DslIr::ImmF(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::ImmF,
                    args: vec![vec![a.id()], vec![b.as_canonical_biguint().to_string()]],
                }),
                DslIr::ImmE(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::ImmE,
                    args: vec![
                        vec![a.id()],
                        b.as_base_slice()
                            .iter()
                            .map(|x| x.as_canonical_biguint().to_string())
                            .collect(),
                    ],
                }),
                DslIr::AddV(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AddV,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::AddVI(a, b, c) => {
                    let tmp = self.alloc_v(&mut constraints, c);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AddV,
                        args: vec![vec![a.id()], vec![b.id()], vec![tmp]],
                    });
                }
                DslIr::AddF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AddF,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::AddFI(a, b, c) => {
                    let tmp = self.alloc_f(&mut constraints, c);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AddF,
                        args: vec![vec![a.id()], vec![b.id()], vec![tmp]],
                    });
                }
                DslIr::AddE(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AddE,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::AddEF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AddEF,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::AddEFI(a, b, c) => {
                    let tmp = self.alloc_f(&mut constraints, c);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AddEF,
                        args: vec![vec![a.id()], vec![b.id()], vec![tmp]],
                    });
                }
                DslIr::AddEI(a, b, c) => {
                    let tmp = self.alloc_e(&mut constraints, c);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AddE,
                        args: vec![vec![a.id()], vec![b.id()], vec![tmp]],
                    });
                }
                DslIr::AddEFFI(a, b, c) => {
                    let tmp = self.alloc_e(&mut constraints, c);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AddEF,
                        args: vec![vec![a.id()], vec![tmp], vec![b.id()]],
                    });
                }
                DslIr::SubV(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::SubV,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::SubF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::SubF,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::SubFI(a, b, c) => {
                    let tmp = self.alloc_f(&mut constraints, c);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::SubF,
                        args: vec![vec![a.id()], vec![b.id()], vec![tmp]],
                    });
                }
                DslIr::SubFIN(a, b, c) => {
                    let temp = self.alloc_f(&mut constraints, b);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::SubF,
                        args: vec![vec![a.id()], vec![temp], vec![c.id()]],
                    });
                }
                DslIr::SubE(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::SubE,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::SubEF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::SubEF,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::SubEI(a, b, c) => {
                    let tmp = self.alloc_e(&mut constraints, c);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::SubE,
                        args: vec![vec![a.id()], vec![b.id()], vec![tmp]],
                    });
                }
                DslIr::SubEIN(a, b, c) => {
                    let tmp = self.alloc_e(&mut constraints, b);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::SubE,
                        args: vec![vec![a.id()], vec![tmp], vec![c.id()]],
                    });
                }
                DslIr::MulV(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::MulV,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::MulVI(a, b, c) => {
                    let tmp = self.alloc_v(&mut constraints, c);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::MulV,
                        args: vec![vec![a.id()], vec![b.id()], vec![tmp]],
                    });
                }
                DslIr::MulF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::MulF,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::MulFI(a, b, c) => {
                    let tmp = self.alloc_f(&mut constraints, c);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::MulF,
                        args: vec![vec![a.id()], vec![b.id()], vec![tmp]],
                    });
                }
                DslIr::MulE(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::MulE,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::MulEI(a, b, c) => {
                    let tmp = self.alloc_e(&mut constraints, c);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::MulE,
                        args: vec![vec![a.id()], vec![b.id()], vec![tmp]],
                    });
                }
                DslIr::MulEF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::MulEF,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::DivFIN(a, b, c) => {
                    let tmp = self.alloc_f(&mut constraints, b);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::DivF,
                        args: vec![vec![a.id()], vec![tmp], vec![c.id()]],
                    });
                }
                DslIr::DivF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::DivF,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::DivEF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::DivEF,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::DivE(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::DivE,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::DivEIN(a, b, c) => {
                    let tmp = self.alloc_e(&mut constraints, b);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::DivE,
                        args: vec![vec![a.id()], vec![tmp], vec![c.id()]],
                    });
                }
                DslIr::NegE(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::NegE,
                    args: vec![vec![a.id()], vec![b.id()]],
                }),
                DslIr::CircuitNum2BitsV(value, bits, output) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::Num2BitsV,
                    args: vec![
                        output.iter().map(|x| x.id()).collect(),
                        vec![value.id()],
                        vec![bits.to_string()],
                    ],
                }),
                DslIr::CircuitNum2BitsF(value, output) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::Num2BitsF,
                    args: vec![output.iter().map(|x| x.id()).collect(), vec![value.id()]],
                }),
                DslIr::CircuitPoseidon2Permute(state) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::Permute,
                    args: state.iter().map(|x| vec![x.id()]).collect(),
                }),
                DslIr::CircuitPoseidon2PermuteBabyBear(state) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::PermuteBabyBear,
                    args: state.iter().map(|x| vec![x.id()]).collect(),
                }),
                DslIr::CircuitSelectV(cond, a, b, out) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::SelectV,
                        args: vec![vec![out.id()], vec![cond.id()], vec![a.id()], vec![b.id()]],
                    });
                }
                DslIr::CircuitSelectF(cond, a, b, out) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::SelectF,
                        args: vec![vec![out.id()], vec![cond.id()], vec![a.id()], vec![b.id()]],
                    });
                }
                DslIr::CircuitSelectE(cond, a, b, out) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::SelectE,
                        args: vec![vec![out.id()], vec![cond.id()], vec![a.id()], vec![b.id()]],
                    });
                }
                DslIr::CircuitExt2Felt(a, b) => {
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
                DslIr::AssertEqV(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AssertEqV,
                    args: vec![vec![a.id()], vec![b.id()]],
                }),
                DslIr::AssertEqVI(a, b) => {
                    let tmp = self.alloc_v(&mut constraints, b);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AssertEqV,
                        args: vec![vec![a.id()], vec![tmp]],
                    });
                }
                DslIr::AssertEqF(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AssertEqF,
                    args: vec![vec![a.id()], vec![b.id()]],
                }),
                DslIr::AssertEqFI(a, b) => {
                    let tmp = self.alloc_f(&mut constraints, b);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AssertEqF,
                        args: vec![vec![a.id()], vec![tmp]],
                    });
                }
                DslIr::AssertEqE(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AssertEqE,
                    args: vec![vec![a.id()], vec![b.id()]],
                }),
                DslIr::AssertNeF(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AssertNeF,
                    args: vec![vec![a.id()], vec![b.id()]],
                }),
                DslIr::AssertNeFI(a, b) => {
                    let tmp = self.alloc_f(&mut constraints, b);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AssertNeF,
                        args: vec![vec![a.id()], vec![tmp]],
                    });
                }
                DslIr::AssertEqEI(a, b) => {
                    let tmp = self.alloc_e(&mut constraints, b);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AssertEqE,
                        args: vec![vec![a.id()], vec![tmp]],
                    });
                }
                DslIr::PrintV(a) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::PrintV,
                    args: vec![vec![a.id()]],
                }),
                DslIr::PrintF(a) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::PrintF,
                    args: vec![vec![a.id()]],
                }),
                DslIr::PrintE(a) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::PrintE,
                    args: vec![vec![a.id()]],
                }),
                DslIr::WitnessVar(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::WitnessV,
                    args: vec![vec![a.id()], vec![b.to_string()]],
                }),
                DslIr::WitnessFelt(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::WitnessF,
                    args: vec![vec![a.id()], vec![b.to_string()]],
                }),
                DslIr::WitnessExt(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::WitnessE,
                    args: vec![vec![a.id()], vec![b.to_string()]],
                }),
                DslIr::CircuitCommitVkeyHash(a) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::CommitVkeyHash,
                    args: vec![vec![a.id()]],
                }),
                DslIr::CircuitCommitCommittedValuesDigest(a) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::CommitCommitedValuesDigest,
                    args: vec![vec![a.id()]],
                }),
                DslIr::CircuitFelts2Ext(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::CircuitFelts2Ext,
                    args: vec![
                        vec![b.id()],
                        vec![a[0].id()],
                        vec![a[1].id()],
                        vec![a[2].id()],
                        vec![a[3].id()],
                    ],
                }),
                // Ignore cycle tracker instruction.
                // It currently serves as a marker for calculation at compile time.
                DslIr::CycleTracker(_) => (),
                DslIr::CycleTrackerV2Enter(_) => (),
                DslIr::CycleTrackerV2Exit => (),
                DslIr::ReduceE(a) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::ReduceE,
                    args: vec![vec![a.id()]],
                }),
                DslIr::CircuitFelt2Var(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::CircuitFelt2Var,
                    args: vec![vec![b.id()], vec![a.id()]],
                }),

                // Version 2 instructions
                DslIr::CircuitV2CommitPublicValues(_) => {}
                _ => panic!("unsupported {:?}", instruction),
            };
        }
        constraints
    }
}
