use std::marker::PhantomData;

use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use sp1_recursion_core::runtime::D;
use sp1_stark::{Chip, StarkGenericConfig, StarkMachine, PROOF_MAX_NUM_PVS};

use crate::chips::{
    alu_base::BaseAluChip,
    alu_ext::ExtAluChip,
    dummy::DummyChip,
    exp_reverse_bits::ExpReverseBitsLenChip,
    fri_fold::FriFoldChip,
    mem::{MemoryConstChip, MemoryVarChip},
    poseidon2_skinny::Poseidon2SkinnyChip,
    poseidon2_wide::Poseidon2WideChip,
    public_values::PublicValuesChip,
};

#[derive(sp1_derive::MachineAir)]
#[sp1_core_path = "sp1_core_machine"]
#[execution_record_path = "crate::ExecutionRecord<F>"]
#[program_path = "crate::RecursionProgram<F>"]
#[builder_path = "crate::builder::SP1RecursionAirBuilder<F = F>"]
#[eval_trait_bound = "AB::Var: 'static"]
pub enum RecursionAir<
    F: PrimeField32 + BinomiallyExtendable<D>,
    const DEGREE: usize,
    const COL_PADDING: usize,
> {
    MemoryConst(MemoryConstChip<F>),
    MemoryVar(MemoryVarChip<F>),
    BaseAlu(BaseAluChip),
    ExtAlu(ExtAluChip),
    Poseidon2Skinny(Poseidon2SkinnyChip<DEGREE>),
    Poseidon2Wide(Poseidon2WideChip<DEGREE>),
    FriFold(FriFoldChip<DEGREE>),
    ExpReverseBitsLen(ExpReverseBitsLenChip<DEGREE>),
    PublicValues(PublicValuesChip),
    DummyWide(DummyChip<COL_PADDING>),
}

impl<F: PrimeField32 + BinomiallyExtendable<D>, const DEGREE: usize, const COL_PADDING: usize>
    RecursionAir<F, DEGREE, COL_PADDING>
{
    /// Get a machine with all chips, except the dummy chip.
    pub fn machine_wide_with_all_chips<SC: StarkGenericConfig<Val = F>>(
        config: SC,
    ) -> StarkMachine<SC, Self> {
        let chips = [
            RecursionAir::MemoryConst(MemoryConstChip::default()),
            RecursionAir::MemoryVar(MemoryVarChip::default()),
            RecursionAir::BaseAlu(BaseAluChip::default()),
            RecursionAir::ExtAlu(ExtAluChip::default()),
            RecursionAir::Poseidon2Wide(Poseidon2WideChip::<DEGREE>::default()),
            RecursionAir::FriFold(FriFoldChip::<DEGREE>::default()),
            RecursionAir::ExpReverseBitsLen(ExpReverseBitsLenChip::<DEGREE>::default()),
            RecursionAir::PublicValues(PublicValuesChip::default()),
        ]
        .map(Chip::new)
        .into_iter()
        .collect::<Vec<_>>();
        StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    }

    /// Get a machine with all chips, except the dummy chip.
    pub fn machine_skinny_with_all_chips<SC: StarkGenericConfig<Val = F>>(
        config: SC,
    ) -> StarkMachine<SC, Self> {
        let chips = [
            RecursionAir::MemoryConst(MemoryConstChip::default()),
            RecursionAir::MemoryVar(MemoryVarChip::default()),
            RecursionAir::BaseAlu(BaseAluChip::default()),
            RecursionAir::ExtAlu(ExtAluChip::default()),
            RecursionAir::Poseidon2Skinny(Poseidon2SkinnyChip::<DEGREE>::default()),
            RecursionAir::FriFold(FriFoldChip::<DEGREE>::default()),
            RecursionAir::ExpReverseBitsLen(ExpReverseBitsLenChip::<DEGREE>::default()),
            RecursionAir::PublicValues(PublicValuesChip::default()),
        ]
        .map(Chip::new)
        .into_iter()
        .collect::<Vec<_>>();
        StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    }

    /// A machine with dyunamic chip sizes that includes the wide variant of the Poseidon2 chip.
    pub fn compress_machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
        let chips = [
            RecursionAir::MemoryConst(MemoryConstChip::default()),
            RecursionAir::MemoryVar(MemoryVarChip::default()),
            RecursionAir::BaseAlu(BaseAluChip::default()),
            RecursionAir::ExtAlu(ExtAluChip::default()),
            RecursionAir::Poseidon2Wide(Poseidon2WideChip::<DEGREE>::default()),
            RecursionAir::ExpReverseBitsLen(ExpReverseBitsLenChip::<DEGREE>::default()),
            RecursionAir::PublicValues(PublicValuesChip::default()),
        ]
        .map(Chip::new)
        .into_iter()
        .collect::<Vec<_>>();
        StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    }

    /// A machine with fixed chip sizes to standartize the verification key.
    pub fn shrink_machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
        let chips = [
            RecursionAir::MemoryConst(MemoryConstChip {
                fixed_log2_rows: Some(16),
                _data: PhantomData,
            }),
            RecursionAir::MemoryVar(MemoryVarChip {
                fixed_log2_rows: Some(18),
                _data: PhantomData,
            }),
            RecursionAir::BaseAlu(BaseAluChip { fixed_log2_rows: Some(20) }),
            RecursionAir::ExtAlu(ExtAluChip { fixed_log2_rows: Some(22) }),
            RecursionAir::Poseidon2Wide(Poseidon2WideChip::<DEGREE> { fixed_log2_rows: Some(16) }),
            RecursionAir::ExpReverseBitsLen(ExpReverseBitsLenChip::<DEGREE> {
                fixed_log2_rows: Some(16),
            }),
            RecursionAir::PublicValues(PublicValuesChip::default()),
        ]
        .map(Chip::new)
        .into_iter()
        .collect::<Vec<_>>();
        StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    }

    /// A machine with dynamic chip sizes that includes the skinny variant of the Poseidon2 chip.
    ///
    /// This machine assumes that the `shrink` stage has a fixed shape, so there is no need to
    /// fix the trace sizes.
    pub fn wrap_machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
        let chips = [
            RecursionAir::MemoryConst(MemoryConstChip::default()),
            RecursionAir::MemoryVar(MemoryVarChip::default()),
            RecursionAir::BaseAlu(BaseAluChip::default()),
            RecursionAir::ExtAlu(ExtAluChip::default()),
            RecursionAir::Poseidon2Skinny(Poseidon2SkinnyChip::<DEGREE>::default()),
            RecursionAir::ExpReverseBitsLen(ExpReverseBitsLenChip::<DEGREE>::default()),
            RecursionAir::PublicValues(PublicValuesChip::default()),
        ]
        .map(Chip::new)
        .into_iter()
        .collect::<Vec<_>>();
        StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    }
}

#[cfg(test)]
pub mod tests {

    use std::sync::Arc;

    use machine::RecursionAir;
    use p3_baby_bear::DiffusionMatrixBabyBear;
    use p3_field::{
        extension::{BinomialExtensionField, HasFrobenius},
        AbstractExtensionField, AbstractField, Field,
    };
    use rand::prelude::*;
    use sp1_core_machine::utils::run_test_machine;
    use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, StarkGenericConfig};

    // TODO expand glob import
    use crate::{runtime::instruction as instr, *};

    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    type A = RecursionAir<F, 3, 0>;
    type B = RecursionAir<F, 9, 0>;

    /// Runs the given program on machines that use the wide and skinny Poseidon2 chips.
    pub fn run_recursion_test_machines(program: RecursionProgram<F>) {
        let program = Arc::new(program);
        let mut runtime =
            Runtime::<F, EF, DiffusionMatrixBabyBear>::new(program.clone(), SC::new().perm);
        runtime.run().unwrap();

        // Run with the poseidon2 wide chip.
        let machine = A::machine_wide_with_all_chips(BabyBearPoseidon2::default());
        let (pk, vk) = machine.setup(&program);
        let result = run_test_machine(vec![runtime.record.clone()], machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }

        // Run with the poseidon2 skinny chip.
        let skinny_machine = B::machine_skinny_with_all_chips(BabyBearPoseidon2::compressed());
        let (pk, vk) = skinny_machine.setup(&program);
        let result = run_test_machine(vec![runtime.record], skinny_machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }
    }

    fn test_instructions(instructions: Vec<Instruction<F>>) {
        let program = RecursionProgram { instructions, ..Default::default() };
        run_recursion_test_machines(program);
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
                instructions.push(instr::ext_alu(ExtAluOpcode::MulE, 1, addr + 2, addr, addr + 1));

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
