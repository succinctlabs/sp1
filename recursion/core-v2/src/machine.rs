use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use sp1_core::stark::{Chip, StarkGenericConfig, StarkMachine, PROOF_MAX_NUM_PVS};
use sp1_derive::MachineAir;
use sp1_recursion_core::runtime::D;

use crate::{
    alu_base::BaseAluChip, alu_ext::ExtAluChip, exp_reverse_bits::ExpReverseBitsLenChip,
    fri_fold::FriFoldChip, mem::MemoryChip, poseidon2_wide::Poseidon2WideChip,
    program::ProgramChip,
};

#[derive(MachineAir)]
#[sp1_core_path = "sp1_core"]
#[execution_record_path = "crate::ExecutionRecord<F>"]
#[program_path = "crate::RecursionProgram<F>"]
#[builder_path = "crate::builder::SP1RecursionAirBuilder<F = F>"]
#[eval_trait_bound = "AB::Var: 'static"]
pub enum RecursionAir<F: PrimeField32 + BinomiallyExtendable<D>, const DEGREE: usize> {
    Program(ProgramChip<F>),
    Memory(MemoryChip),
    BaseAlu(BaseAluChip),
    ExtAlu(ExtAluChip),
    // Cpu(CpuChip<F, DEGREE>),
    // MemoryGlobal(MemoryGlobalChip),
    Poseidon2Wide(Poseidon2WideChip<DEGREE>),
    FriFold(FriFoldChip<DEGREE>),
    // RangeCheck(RangeCheckChip<F>),
    // Multi(MultiChip<DEGREE>),
    ExpReverseBitsLen(ExpReverseBitsLenChip<DEGREE>),
}

impl<F: PrimeField32 + BinomiallyExtendable<D>, const DEGREE: usize> RecursionAir<F, DEGREE> {
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
            RecursionAir::Poseidon2Wide(Poseidon2WideChip::<DEGREE>::default()),
            RecursionAir::ExpReverseBitsLen(ExpReverseBitsLenChip::<DEGREE>::default()),
            RecursionAir::FriFold(FriFoldChip::<DEGREE>::default()),
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

    use machine::RecursionAir;
    use p3_baby_bear::DiffusionMatrixBabyBear;
    use p3_field::{
        extension::{BinomialExtensionField, HasFrobenius},
        AbstractExtensionField, AbstractField, Field,
    };
    use rand::prelude::*;
    use sp1_core::{
        stark::StarkGenericConfig,
        utils::{run_test_machine, BabyBearPoseidon2Inner},
    };
    use sp1_recursion_core::stark::config::BabyBearPoseidon2Outer;

    // TODO expand glob import
    use crate::{runtime::instruction as instr, *};

    type SC = BabyBearPoseidon2Outer;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    type A = RecursionAir<F, 3>;

    fn test_instructions(instructions: Vec<Instruction<F>>) {
        let program = RecursionProgram { instructions };
        let mut runtime = Runtime::<F, EF, DiffusionMatrixBabyBear>::new(
            &program,
            BabyBearPoseidon2Inner::new().perm,
        );
        runtime.run();

        let config = SC::new();
        let machine = A::machine(config);
        let (pk, vk) = machine.setup(&program);
        let result = run_test_machine(runtime.record, machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }
    }

    #[test]
    pub fn fibonacci() {
        let n = 10;

        let instructions = once(instr::mem(MemAccessKind::Write, 1, 0, 0))
            .chain(once(instr::mem(MemAccessKind::Write, 2, 1, 1)))
            .chain((2..=n).map(|i| instr::base_alu(BaseAluOpcode::AddF, 2, i, i - 2, i - 1)))
            .chain(once(instr::mem(MemAccessKind::Read, 1, n - 1, 34)))
            .chain(once(instr::mem(MemAccessKind::Read, 2, n, 55)))
            .collect::<Vec<_>>();

        test_instructions(instructions);
    }

    #[test]
    #[should_panic]
    pub fn div_nonzero_by_zero() {
        let instructions = vec![
            instr::mem(MemAccessKind::Write, 1, 0, 0),
            instr::mem(MemAccessKind::Write, 1, 1, 1),
            instr::base_alu(BaseAluOpcode::DivF, 1, 2, 1, 0),
            instr::mem(MemAccessKind::Read, 1, 2, 1),
        ];

        test_instructions(instructions);
    }

    #[test]
    pub fn div_zero_by_zero() {
        let instructions = vec![
            instr::mem(MemAccessKind::Write, 1, 0, 0),
            instr::mem(MemAccessKind::Write, 1, 1, 0),
            instr::base_alu(BaseAluOpcode::DivF, 1, 2, 1, 0),
            instr::mem(MemAccessKind::Read, 1, 2, 1),
        ];

        test_instructions(instructions);
    }

    #[test]
    pub fn field_norm() {
        let mut instructions = Vec::new();

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut addr = 0;
        for _ in 0..100 {
            let inner: [F; 4] = std::iter::repeat_with(|| {
                core::array::from_fn(|_| rng.sample(rand::distributions::Standard))
            })
            .find(|xs| !xs.iter().all(F::is_zero))
            .unwrap();
            let x = BinomialExtensionField::<F, D>::from_base_slice(&inner);
            let gal = x.galois_group();

            let mut acc = BinomialExtensionField::one();

            instructions.push(instr::mem_ext(MemAccessKind::Write, 1, addr, acc));
            for conj in gal {
                instructions.push(instr::mem_ext(MemAccessKind::Write, 1, addr + 1, conj));
                instructions.push(instr::ext_alu(
                    ExtAluOpcode::MulE,
                    1,
                    addr + 2,
                    addr,
                    addr + 1,
                ));

                addr += 2;
                acc *= conj;
            }
            let base_cmp: F = acc.as_base_slice()[0];
            instructions.push(instr::mem_single(MemAccessKind::Read, 1, addr, base_cmp));
            addr += 1;
        }

        test_instructions(instructions);
    }
}
