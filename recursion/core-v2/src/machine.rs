use core::iter::once;
use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use sp1_core::stark::{Chip, StarkGenericConfig, StarkMachine, PROOF_MAX_NUM_PVS};
use sp1_derive::MachineAir;

use crate::{add::AddChip, mem::MemoryChip, mul::MulChip, program::ProgramChip};

use std::marker::PhantomData;

#[derive(MachineAir)]
#[sp1_core_path = "sp1_core"]
#[execution_record_path = "crate::ExecutionRecord<F>"]
#[program_path = "crate::RecursionProgram<F>"]
#[builder_path = "sp1_recursion_core::air::SP1RecursionAirBuilder<F = F>"]
#[eval_trait_bound = "AB::Var: 'static"]
pub enum RecursionAir<F: PrimeField32> {
    Program(ProgramChip<F>),
    Memory(MemoryChip),
    Add(AddChip),
    Mul(MulChip),
    // Cpu(CpuChip<F, DEGREE>),
    // MemoryGlobal(MemoryGlobalChip),
    // Poseidon2Wide(Poseidon2WideChip<DEGREE>),
    // FriFold(FriFoldChip<DEGREE>),
    // RangeCheck(RangeCheckChip<F>),
    // Multi(MultiChip<DEGREE>),
    // ExpReverseBitsLen(ExpReverseBitsLenChip<DEGREE>),
}

impl<F: PrimeField32> RecursionAir<F> {
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
            RecursionAir::Add(AddChip::default()),
            RecursionAir::Mul(MulChip::default()),
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
    use p3_field::AbstractField;
    use sp1_core::utils::{run_test_machine, BabyBearPoseidon2};
    // use sp1_recursion_core::air::SP1RecursionAirBuilder;

    use crate::{
        machine::RecursionAir, AddressValue, AluEvent, ExecutionRecord, MemAccessKind, MemEvent,
        Opcode, RecursionProgram,
    };

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
            add_events: vec![
                AluEvent {
                    a: AddressValue::new(embed(100), embed(2)),
                    b: AddressValue::new(embed(101), embed(1)),
                    c: AddressValue::new(embed(101), embed(1)),
                    mult: embed(1),
                    opcode: Opcode::Add,
                },
                //
            ],
            mul_events: vec![],
            mem_events: vec![
                MemEvent {
                    address_value: AddressValue::new(embed(1), embed(2)),
                    multiplicity: F::two(),
                    kind: MemAccessKind::Write,
                },
                MemEvent {
                    address_value: AddressValue::new(embed(1), embed(2)),
                    multiplicity: F::one(),
                    kind: MemAccessKind::Read,
                },
                MemEvent {
                    address_value: AddressValue::new(embed(1), embed(2)),
                    multiplicity: F::one(),
                    kind: MemAccessKind::Read,
                },
                MemEvent {
                    address_value: AddressValue::new(embed(101), embed(1)),
                    multiplicity: F::two(),
                    kind: MemAccessKind::Write,
                },
                MemEvent {
                    address_value: AddressValue::new(embed(100), embed(2)),
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
            address_value: x,
            multiplicity: embed(3),
            kind: MemAccessKind::Write,
        });
        for _ in 0..100 {
            let prod = AddressValue::new(x.addr + embed(1), x.val * x.val);
            let sum = AddressValue::new(x.addr + embed(2), prod.val + x.val);
            record.mul_events.push(AluEvent {
                opcode: Opcode::Mul,
                a: prod,
                b: x,
                c: x,
                mult: embed(1),
            });
            record.add_events.push(AluEvent {
                opcode: Opcode::Add,
                a: sum,
                b: prod,
                c: x,
                mult: embed(3),
            });
            x = sum;
        }
        record.mem_events.push(MemEvent {
            address_value: x,
            multiplicity: embed(3),
            kind: MemAccessKind::Read,
        });

        let result = run_test_machine(record, machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }
    }
}
