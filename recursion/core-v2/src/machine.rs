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

    use machine::RecursionAir;
    use p3_baby_bear::DiffusionMatrixBabyBear;
    use p3_field::{
        extension::{BinomialExtensionField, HasFrobenius},
        AbstractExtensionField, AbstractField, Field,
    };
    use rand::prelude::*;
    use sp1_core::{stark::StarkGenericConfig, utils::run_test_machine};
    use sp1_recursion_core::{air::Block, stark::config::BabyBearPoseidon2Outer};

    // TODO expand glob import
    use crate::{runtime::Runtime, *};

    mod instr {
        use super::*;
        pub fn base_alu<F: AbstractField>(
            opcode: Opcode,
            mult: u32,
            out: u32,
            in1: u32,
            in2: u32,
        ) -> Instruction<F> {
            Instruction::BaseAlu(BaseAluInstr {
                opcode,
                mult: F::from_canonical_u32(mult),
                addrs: BaseAluIo {
                    out: Address(F::from_canonical_u32(out)),
                    in1: Address(F::from_canonical_u32(in1)),
                    in2: Address(F::from_canonical_u32(in2)),
                },
            })
        }

        pub fn ext_alu<F: AbstractField>(
            opcode: Opcode,
            mult: u32,
            out: u32,
            in1: u32,
            in2: u32,
        ) -> Instruction<F> {
            Instruction::ExtAlu(ExtAluInstr {
                opcode,
                mult: F::from_canonical_u32(mult),
                addrs: ExtAluIo {
                    out: Address(F::from_canonical_u32(out)),
                    in1: Address(F::from_canonical_u32(in1)),
                    in2: Address(F::from_canonical_u32(in2)),
                },
            })
        }

        pub fn mem_int<F: AbstractField>(
            kind: MemAccessKind,
            mult: u32,
            addr: u32,
            val: u32,
        ) -> Instruction<F> {
            mem_single(kind, mult, addr, F::from_canonical_u32(val))
        }

        pub fn mem_single<F: AbstractField>(
            kind: MemAccessKind,
            mult: u32,
            addr: u32,
            val: F,
        ) -> Instruction<F> {
            mem_block(kind, mult, addr, Block::from(val))
        }

        pub fn mem_ext<F: AbstractField + Copy, EF: AbstractExtensionField<F>>(
            kind: MemAccessKind,
            mult: u32,
            addr: u32,
            val: EF,
        ) -> Instruction<F> {
            mem_block(kind, mult, addr, val.as_base_slice().into())
        }

        pub fn mem_block<F: AbstractField>(
            kind: MemAccessKind,
            mult: u32,
            addr: u32,
            val: Block<F>,
        ) -> Instruction<F> {
            Instruction::Mem(MemInstr {
                addrs: MemIo {
                    inner: Address(F::from_canonical_u32(addr)),
                },
                vals: MemIo { inner: val },
                mult: F::from_canonical_u32(mult),
                kind,
            })
        }
    }

    #[test]
    pub fn basic_mem() {
        type SC = BabyBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;
        type A = RecursionAir<F>;

        let instructions = vec![
            instr::mem_int(MemAccessKind::Write, 1, 1, 2),
            instr::mem_int(MemAccessKind::Read, 1, 1, 2),
        ];
        let program = RecursionProgram { instructions };
        let mut runtime = Runtime::<F, EF, DiffusionMatrixBabyBear>::new_no_perm(&program);
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
    #[should_panic]
    pub fn basic_mem_bad_mult() {
        type SC = BabyBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;
        type A = RecursionAir<F>;

        let instructions = vec![
            instr::mem_int(MemAccessKind::Write, 1, 1, 2),
            instr::mem_int(MemAccessKind::Read, 999, 1, 2),
        ];
        let program = RecursionProgram { instructions };
        let mut runtime = Runtime::<F, EF, DiffusionMatrixBabyBear>::new_no_perm(&program);
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
    #[should_panic]
    pub fn basic_mem_bad_address() {
        type SC = BabyBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;
        type A = RecursionAir<F>;

        let instructions = vec![
            instr::mem_int(MemAccessKind::Write, 1, 1, 2),
            instr::mem_int(MemAccessKind::Read, 1, 999, 2),
        ];
        let program = RecursionProgram { instructions };
        let mut runtime = Runtime::<F, EF, DiffusionMatrixBabyBear>::new_no_perm(&program);
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
    #[should_panic]
    pub fn basic_mem_bad_value() {
        type SC = BabyBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;
        type A = RecursionAir<F>;

        let instructions = vec![
            instr::mem_int(MemAccessKind::Write, 1, 1, 2),
            instr::mem_int(MemAccessKind::Read, 1, 1, 999),
        ];
        let program = RecursionProgram { instructions };
        let mut runtime = Runtime::<F, EF, DiffusionMatrixBabyBear>::new_no_perm(&program);
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
    pub fn basic_mem_and_alu() {
        type SC = BabyBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;
        type A = RecursionAir<F>;

        let instructions = vec![
            instr::mem_int(MemAccessKind::Write, 1, 0, 9),
            instr::mem_int(MemAccessKind::Write, 1, 1, 10),
            instr::base_alu(Opcode::AddF, 1, 2, 0, 1),
            instr::mem_int(MemAccessKind::Read, 1, 2, 19),
        ];
        let program = RecursionProgram { instructions };
        let mut runtime = Runtime::<F, EF, DiffusionMatrixBabyBear>::new_no_perm(&program);
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
        type SC = BabyBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;
        type A = RecursionAir<F>;

        let n = 10;

        let instructions = once(instr::mem_int(MemAccessKind::Write, 1, 0, 0))
            .chain(once(instr::mem_int(MemAccessKind::Write, 2, 1, 1)))
            .chain((2..=n).map(|i| instr::base_alu(Opcode::AddF, 2, i, i - 2, i - 1)))
            .chain(once(instr::mem_int(MemAccessKind::Read, 1, n - 1, 34)))
            .chain(once(instr::mem_int(MemAccessKind::Read, 2, n, 55)))
            .collect::<Vec<_>>();

        let program = RecursionProgram { instructions };
        let mut runtime = Runtime::<F, EF, DiffusionMatrixBabyBear>::new_no_perm(&program);
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
    pub fn four_ops() {
        type SC = BabyBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;
        type A = RecursionAir<F>;

        let instructions = vec![
            instr::mem_int(MemAccessKind::Write, 4, 0, 6),
            instr::mem_int(MemAccessKind::Write, 4, 1, 3),
            instr::base_alu(Opcode::AddF, 1, 2, 0, 1),
            instr::mem_int(MemAccessKind::Read, 1, 2, 6 + 3),
            instr::base_alu(Opcode::SubF, 1, 3, 0, 1),
            instr::mem_int(MemAccessKind::Read, 1, 3, 6 - 3),
            instr::base_alu(Opcode::MulF, 1, 4, 0, 1),
            instr::mem_int(MemAccessKind::Read, 1, 4, 6 * 3),
            instr::base_alu(Opcode::DivF, 1, 5, 0, 1),
            instr::mem_int(MemAccessKind::Read, 1, 5, 6 / 3),
        ];
        let program = RecursionProgram { instructions };
        let mut runtime = Runtime::<F, EF, DiffusionMatrixBabyBear>::new_no_perm(&program);
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
    pub fn field_norm() {
        type SC = BabyBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;
        type A = RecursionAir<F>;

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
                instructions.push(instr::ext_alu(Opcode::MulE, 1, addr + 2, addr, addr + 1));

                addr += 2;
                acc *= conj;
            }
            let base_cmp: F = acc.as_base_slice()[0];
            instructions.push(instr::mem_single(MemAccessKind::Read, 1, addr, base_cmp));
            addr += 1;
        }

        let program = RecursionProgram { instructions };
        let mut runtime = Runtime::<F, EF, DiffusionMatrixBabyBear>::new_no_perm(&program);
        runtime.run();

        let config = SC::new();
        let machine = A::machine(config);
        let (pk, vk) = machine.setup(&program);
        let result = run_test_machine(runtime.record, machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }
    }
}
