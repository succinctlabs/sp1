use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use sp1_core::stark::{Chip, StarkGenericConfig, StarkMachine, PROOF_MAX_NUM_PVS};
use sp1_derive::MachineAir;
use sp1_recursion_core::runtime::D;

use crate::{alu_base::BaseAluChip, alu_ext::ExtAluChip, mem::MemoryChip, program::ProgramChip};

#[derive(MachineAir)]
#[sp1_core_path = "sp1_core"]
#[execution_record_path = "crate::ExecutionRecord<F>"]
#[program_path = "crate::RecursionProgram<F>"]
#[builder_path = "crate::builder::SP1RecursionAirBuilder<F = F>"]
#[eval_trait_bound = "AB::Var: 'static"]
pub enum RecursionAir<F: PrimeField32 + BinomiallyExtendable<D>> {
    Program(ProgramChip<F>),
    Memory(MemoryChip),
    BaseAlu(BaseAluChip),
    ExtAlu(ExtAluChip),
    // Cpu(CpuChip<F, DEGREE>),
    // MemoryGlobal(MemoryGlobalChip),
    // Poseidon2Wide(Poseidon2WideChip<DEGREE>),
    // FriFold(FriFoldChip<DEGREE>),
    // RangeCheck(RangeCheckChip<F>),
    // Multi(MultiChip<DEGREE>),
    // ExpReverseBitsLen(ExpReverseBitsLenChip<DEGREE>),
}

impl<F: PrimeField32 + BinomiallyExtendable<D>> RecursionAir<F> {
    /// A recursion machine that can have dynamic trace sizes.
    pub fn machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
        let chips = Self::get_all()
            .into_iter()
            .map(Chip::new)
            .collect::<Vec<_>>();
        StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    }

    // /// A recursion machine with fixed trace sizes tuned to work specifically for the wrap layer.
    // pub fn wrap_machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
    //     let chips = Self::get_wrap_all()
    //         .into_iter()
    //         .map(Chip::new)
    //         .collect::<Vec<_>>();
    //     StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    // }

    // /// A recursion machine with fixed trace sizes tuned to work specifically for the wrap layer.
    // pub fn wrap_machine_dyn<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
    //     let chips = Self::get_wrap_dyn_all()
    //         .into_iter()
    //         .map(Chip::new)
    //         .collect::<Vec<_>>();
    //     StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    // }

    pub fn get_all() -> Vec<Self> {
        vec![
            RecursionAir::Program(ProgramChip::default()),
            RecursionAir::Memory(MemoryChip::default()),
            RecursionAir::BaseAlu(BaseAluChip::default()),
            RecursionAir::ExtAlu(ExtAluChip::default()),
        ]
    }

    // pub fn get_wrap_dyn_all() -> Vec<Self> {
    //     once(RecursionAir::Program(ProgramChip))
    //         .chain(once(RecursionAir::Cpu(CpuChip {
    //             fixed_log2_rows: None,
    //             _phantom: PhantomData,
    //         })))
    //         .chain(once(RecursionAir::MemoryGlobal(MemoryGlobalChip {
    //             fixed_log2_rows: None,
    //         })))
    //         .chain(once(RecursionAir::Multi(MultiChip {
    //             fixed_log2_rows: None,
    //         })))
    //         .chain(once(RecursionAir::RangeCheck(RangeCheckChip::default())))
    //         .chain(once(RecursionAir::ExpReverseBitsLen(
    //             ExpReverseBitsLenChip::<DEGREE> {
    //                 fixed_log2_rows: None,
    //                 pad: true,
    //             },
    //         )))
    //         .collect()
    // }

    // pub fn get_wrap_all() -> Vec<Self> {
    //     once(RecursionAir::Program(ProgramChip))
    //         .chain(once(RecursionAir::Cpu(CpuChip {
    //             fixed_log2_rows: Some(19),
    //             _phantom: PhantomData,
    //         })))
    //         .chain(once(RecursionAir::MemoryGlobal(MemoryGlobalChip {
    //             fixed_log2_rows: Some(20),
    //         })))
    //         .chain(once(RecursionAir::Multi(MultiChip {
    //             fixed_log2_rows: Some(17),
    //         })))
    //         .chain(once(RecursionAir::RangeCheck(RangeCheckChip::default())))
    //         .chain(once(RecursionAir::ExpReverseBitsLen(
    //             ExpReverseBitsLenChip::<DEGREE> {
    //                 fixed_log2_rows: None,
    //                 pad: true,
    //             },
    //         )))
    //         .collect()
    // }
}

#[cfg(test)]
mod tests {

    use p3_baby_bear::BabyBear;
    use p3_field::{
        extension::{BinomialExtensionField, HasFrobenius},
        AbstractExtensionField, AbstractField,
    };
    use rand::prelude::*;
    use sp1_core::utils::{run_test_machine, BabyBearPoseidon2};
    use sp1_recursion_core::{air::Block, runtime::D};
    // use sp1_recursion_core::air::SP1RecursionAirBuilder;

    use crate::{
        machine::RecursionAir, AddressValue, BaseAluEvent, ExecutionRecord, ExtAluEvent,
        MemAccessKind, MemEvent, Opcode, RecursionProgram,
    };

    #[test]
    pub fn basicer() {
        type F = BabyBear;
        let embed = F::from_canonical_u32;

        // TODO figure out how to write a program lol
        let program = RecursionProgram::default();
        // that's a trait, find the builder struct to use
        // let builder = SP1RecursionAirBuilder::<BabyBear>::new();

        // let program = builder.compile_program();

        let machine = RecursionAir::machine(BabyBearPoseidon2::default());
        let (pk, vk) = machine.setup(&program);
        let record = ExecutionRecord {
            mem_events: vec![
                MemEvent {
                    address_value: AddressValue::new(embed(1), Block::from(embed(2))),
                    multiplicity: F::one(),
                    kind: MemAccessKind::Write,
                },
                MemEvent {
                    address_value: AddressValue::new(embed(1), Block::from(embed(2))),
                    multiplicity: F::one(),
                    kind: MemAccessKind::Read,
                },
            ],
            ..Default::default()
        };
        let result = run_test_machine(record, machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }
    }

    #[test]
    pub fn basic() {
        type F = BabyBear;
        let embed = F::from_canonical_u32;

        // TODO figure out how to write a program lol
        let program = RecursionProgram::default();
        // that's a trait, find the builder struct to use
        // let builder = SP1RecursionAirBuilder::<BabyBear>::new();

        // let program = builder.compile_program();

        let machine = RecursionAir::machine(BabyBearPoseidon2::default());
        let (pk, vk) = machine.setup(&program);
        let record = ExecutionRecord {
            base_alu_events: vec![
                BaseAluEvent {
                    out: AddressValue::new(embed(100), embed(2)),
                    in1: AddressValue::new(embed(101), embed(1)),
                    in2: AddressValue::new(embed(101), embed(1)),
                    mult: embed(1),
                    opcode: Opcode::AddF,
                },
                //
            ],
            mem_events: vec![
                MemEvent {
                    address_value: AddressValue::new(embed(101), embed(1).into()),
                    multiplicity: F::two(),
                    kind: MemAccessKind::Write,
                },
                MemEvent {
                    address_value: AddressValue::new(embed(100), embed(2).into()),
                    multiplicity: F::one(),
                    kind: MemAccessKind::Read,
                },
            ],
            ..Default::default()
        };
        let result = run_test_machine(record, machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }
    }

    #[test]
    pub fn iterate() {
        type F = BabyBear;
        let embed = F::from_canonical_u32;

        // TODO figure out how to write a program lol
        let program = RecursionProgram::default();
        // that's a trait, find the builder struct to use
        // let builder = SP1RecursionAirBuilder::<BabyBear>::new();

        // let program = builder.compile_program();

        let machine = RecursionAir::machine(BabyBearPoseidon2::default());
        let (pk, vk) = machine.setup(&program);

        let mut record = ExecutionRecord::default();

        let mut x = AddressValue::new(F::zero(), F::one());
        record.mem_events.push(MemEvent {
            address_value: AddressValue::new(x.addr, Block::from(x.val)),
            multiplicity: embed(3),
            kind: MemAccessKind::Write,
        });
        for _ in 0..100 {
            let prod = AddressValue::new(x.addr + embed(1), x.val * x.val);
            let sum = AddressValue::new(x.addr + embed(2), prod.val + x.val);
            record.base_alu_events.push(BaseAluEvent {
                opcode: Opcode::MulF,
                out: prod,
                in1: x,
                in2: x,
                mult: embed(1),
            });
            record.base_alu_events.push(BaseAluEvent {
                opcode: Opcode::AddF,
                out: sum,
                in1: prod,
                in2: x,
                mult: embed(3),
            });
            x = sum;
        }
        record.mem_events.push(MemEvent {
            address_value: AddressValue::new(x.addr, Block::from(x.val)),
            multiplicity: embed(3),
            kind: MemAccessKind::Read,
        });

        let result = run_test_machine(record, machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }
    }

    #[test]
    pub fn iterate_alu() {
        type F = BabyBear;
        let embed = F::from_canonical_u32;

        let program = RecursionProgram::default();

        let machine = RecursionAir::machine(BabyBearPoseidon2::default());
        let (pk, vk) = machine.setup(&program);

        let mut record = ExecutionRecord::default();

        let mut x = AddressValue::new(F::zero(), F::one());
        record.mem_events.push(MemEvent {
            address_value: AddressValue::new(x.addr, Block::from(x.val)),
            multiplicity: embed(3),
            kind: MemAccessKind::Write,
        });
        for _ in 0..100 {
            let prod = AddressValue::new(x.addr + embed(1), x.val * x.val);
            let sum = AddressValue::new(x.addr + embed(2), prod.val + x.val);
            record.base_alu_events.push(BaseAluEvent {
                opcode: Opcode::MulF,
                out: prod,
                in1: x,
                in2: x,
                mult: embed(1),
            });
            record.base_alu_events.push(BaseAluEvent {
                opcode: Opcode::AddF,
                out: sum,
                in1: prod,
                in2: x,
                mult: embed(3),
            });
            x = sum;
        }
        record.mem_events.push(MemEvent {
            address_value: AddressValue::new(x.addr, Block::from(x.val)),
            multiplicity: embed(3),
            kind: MemAccessKind::Read,
        });

        let result = run_test_machine(record, machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }
    }

    #[test]
    pub fn four_ops() {
        type F = BabyBear;
        let embed = F::from_canonical_u32;

        let program = RecursionProgram::default();

        let machine = RecursionAir::machine(BabyBearPoseidon2::default());
        let (pk, vk) = machine.setup(&program);

        let mut record = ExecutionRecord::default();

        let four = AddressValue::new(embed(0), embed(3));
        record.mem_events.push(MemEvent {
            address_value: AddressValue::new(four.addr, Block::from(four.val)),
            multiplicity: embed(4),
            kind: MemAccessKind::Write,
        });
        let three = AddressValue::new(embed(1), embed(4));
        record.mem_events.push(MemEvent {
            address_value: AddressValue::new(three.addr, Block::from(three.val)),
            multiplicity: embed(4),
            kind: MemAccessKind::Write,
        });

        let sum = AddressValue::new(embed(1), four.val + three.val);
        record.base_alu_events.push(BaseAluEvent {
            opcode: Opcode::AddF,
            out: sum,
            in1: four,
            in2: three,
            mult: embed(0),
        });

        let diff = AddressValue::new(embed(1), four.val - three.val);
        record.base_alu_events.push(BaseAluEvent {
            opcode: Opcode::SubF,
            out: diff,
            in1: four,
            in2: three,
            mult: embed(0),
        });

        let prod = AddressValue::new(embed(1), four.val * three.val);
        record.base_alu_events.push(BaseAluEvent {
            opcode: Opcode::MulF,
            out: prod,
            in1: four,
            in2: three,
            mult: embed(0),
        });

        let quot = AddressValue::new(embed(1), four.val / three.val);
        record.base_alu_events.push(BaseAluEvent {
            opcode: Opcode::DivF,
            out: quot,
            in1: four,
            in2: three,
            mult: embed(0),
        });

        let result = run_test_machine(record, machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }
    }

    #[test]
    pub fn field_norm() {
        type F = BabyBear;
        let embed = F::from_canonical_u32;

        let program = RecursionProgram::default();

        let machine = RecursionAir::machine(BabyBearPoseidon2::default());
        let (pk, vk) = machine.setup(&program);

        let mut record = ExecutionRecord::default();

        let mut rng = StdRng::seed_from_u64(0);
        let mut addr = F::zero();
        for _ in 0..1000 {
            let inner: [F; 4] = core::array::from_fn(|_| rng.sample(rand::distributions::Standard));
            let x = BinomialExtensionField::<F, D>::from_base_slice(&inner);
            let gal = x.galois_group();

            let mut acc = BinomialExtensionField::one();

            record.mem_events.push(MemEvent {
                address_value: AddressValue::new(addr, F::one().into()),
                multiplicity: embed(1),
                kind: MemAccessKind::Write,
            });
            for conj in gal {
                record.mem_events.push(MemEvent {
                    address_value: AddressValue::new(addr + embed(1), conj.as_base_slice().into()),
                    multiplicity: embed(1),
                    kind: MemAccessKind::Write,
                });
                let prod = acc * conj;
                let in1 = AddressValue::new(addr, acc.as_base_slice().into());
                let in2 = AddressValue::new(addr + embed(1), conj.as_base_slice().into());
                let out = AddressValue::new(addr + embed(2), prod.as_base_slice().into());
                record.ext_alu_events.push(ExtAluEvent {
                    opcode: Opcode::MulE,
                    out,
                    in1,
                    in2,
                    mult: embed(1),
                });
                addr += embed(2);
                acc = prod;
            }
            let base_component: F = acc.as_base_slice()[0];
            record.mem_events.push(MemEvent {
                address_value: AddressValue::new(addr, Block::from(base_component)),
                multiplicity: embed(1),
                kind: MemAccessKind::Read,
            });
        }

        let result = run_test_machine(record, machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }
    }
}
