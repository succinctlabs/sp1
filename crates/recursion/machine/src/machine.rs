use std::fmt;

use slop_algebra::{extension::BinomiallyExtendable, PrimeField32};
use sp1_hypercube::{air::MachineAir, Chip, Machine, MachineShape, PROOF_MAX_NUM_PVS};
use sp1_recursion_executor::{ExecutionRecord, RecursionAirEventCount, RecursionProgram, D};

use crate::chips::{
    alu_base::{BaseAluChip, NUM_BASE_ALU_ENTRIES_PER_ROW},
    alu_ext::{ExtAluChip, NUM_EXT_ALU_ENTRIES_PER_ROW},
    mem::{constant::NUM_CONST_MEM_ENTRIES_PER_ROW, MemoryConstChip, MemoryVarChip},
    poseidon2_helper::{
        convert::{ConvertChip, NUM_CONVERT_ENTRIES_PER_ROW},
        linear::{Poseidon2LinearLayerChip, NUM_LINEAR_ENTRIES_PER_ROW},
        sbox::{Poseidon2SBoxChip, NUM_SBOX_ENTRIES_PER_ROW},
    },
    poseidon2_wide::Poseidon2WideChip,
    public_values::{PublicValuesChip, PUB_VALUES_LOG_HEIGHT},
    select::SelectChip,
};
use std::mem::MaybeUninit;
use strum::{EnumDiscriminants, EnumIter};

#[derive(sp1_derive::MachineAir, EnumDiscriminants, Clone)]
#[execution_record_path = "ExecutionRecord<F>"]
#[program_path = "RecursionProgram<F>"]
#[builder_path = "crate::builder::SP1RecursionAirBuilder<F = F>"]
#[eval_trait_bound = "AB::Var: 'static"]
#[strum_discriminants(derive(Hash, EnumIter))]
pub enum RecursionAir<
    F: PrimeField32 + BinomiallyExtendable<D>,
    const DEGREE: usize,
    const VAR_EVENTS_PER_ROW: usize,
> {
    MemoryConst(MemoryConstChip<F>),
    MemoryVar(MemoryVarChip<F, VAR_EVENTS_PER_ROW>),
    BaseAlu(BaseAluChip),
    ExtAlu(ExtAluChip),
    Poseidon2Wide(Poseidon2WideChip<DEGREE>),
    Poseidon2LinearLayer(Poseidon2LinearLayerChip),
    Poseidon2SBox(Poseidon2SBoxChip),
    ExtFeltConvert(ConvertChip),
    Select(SelectChip),
    PublicValues(PublicValuesChip),
}

impl<
        F: PrimeField32 + BinomiallyExtendable<D>,
        const DEGREE: usize,
        const VAR_EVENTS_PER_ROW: usize,
    > fmt::Debug for RecursionAir<F, DEGREE, VAR_EVENTS_PER_ROW>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl<
        F: PrimeField32 + BinomiallyExtendable<D>,
        const DEGREE: usize,
        const VAR_EVENTS_PER_ROW: usize,
    > RecursionAir<F, DEGREE, VAR_EVENTS_PER_ROW>
{
    /// Get a machine with all chips, except the dummy chip.
    pub fn machine_wide_with_all_chips() -> Machine<F, Self> {
        let chips = [
            RecursionAir::MemoryConst(MemoryConstChip::default()),
            RecursionAir::MemoryVar(MemoryVarChip::<F, VAR_EVENTS_PER_ROW>::default()),
            RecursionAir::BaseAlu(BaseAluChip),
            RecursionAir::ExtAlu(ExtAluChip),
            RecursionAir::Poseidon2Wide(Poseidon2WideChip::<DEGREE>),
            RecursionAir::Poseidon2LinearLayer(Poseidon2LinearLayerChip),
            RecursionAir::Poseidon2SBox(Poseidon2SBoxChip),
            RecursionAir::ExtFeltConvert(ConvertChip),
            RecursionAir::Select(SelectChip),
            RecursionAir::PublicValues(PublicValuesChip),
        ]
        .map(Chip::new)
        .into_iter()
        .collect::<Vec<_>>();

        let shape = MachineShape::all(&chips);
        Machine::new(chips, PROOF_MAX_NUM_PVS, shape)
    }

    /// A machine with dyunamic chip sizes.
    pub fn compress_machine() -> Machine<F, Self> {
        let chips = [
            RecursionAir::MemoryConst(MemoryConstChip::default()),
            RecursionAir::MemoryVar(MemoryVarChip::<F, VAR_EVENTS_PER_ROW>::default()),
            RecursionAir::BaseAlu(BaseAluChip),
            RecursionAir::ExtAlu(ExtAluChip),
            RecursionAir::Poseidon2Wide(Poseidon2WideChip::<DEGREE>),
            RecursionAir::Select(SelectChip),
            RecursionAir::PublicValues(PublicValuesChip),
        ]
        .map(Chip::new)
        .into_iter()
        .collect::<Vec<_>>();
        let shape = MachineShape::all(&chips);
        Machine::new(chips, PROOF_MAX_NUM_PVS, shape)
    }

    pub fn shrink_machine() -> Machine<F, Self> {
        Self::compress_machine()
    }

    /// A machine with dynamic chip sizes.
    ///
    /// This machine assumes that the `shrink` stage has a fixed shape, so there is no need to
    /// fix the trace sizes.
    pub fn wrap_machine() -> Machine<F, Self> {
        let chips = [
            RecursionAir::MemoryConst(MemoryConstChip::default()),
            RecursionAir::MemoryVar(MemoryVarChip::<F, VAR_EVENTS_PER_ROW>::default()),
            RecursionAir::BaseAlu(BaseAluChip),
            RecursionAir::ExtAlu(ExtAluChip),
            RecursionAir::Poseidon2LinearLayer(Poseidon2LinearLayerChip),
            RecursionAir::Poseidon2SBox(Poseidon2SBoxChip),
            RecursionAir::ExtFeltConvert(ConvertChip),
            RecursionAir::Select(SelectChip),
            RecursionAir::PublicValues(PublicValuesChip),
        ]
        .map(Chip::new)
        .into_iter()
        .collect::<Vec<_>>();
        let shape = MachineShape::all(&chips);
        Machine::new(chips, PROOF_MAX_NUM_PVS, shape)
    }

    pub fn heights(program: &RecursionProgram<F>) -> Vec<(String, usize)> {
        let heights =
            program.inner.iter().fold(RecursionAirEventCount::default(), |heights, instruction| {
                heights + instruction.inner()
            });

        [
            (
                Self::MemoryConst(MemoryConstChip::default()),
                heights.mem_const_events.div_ceil(NUM_CONST_MEM_ENTRIES_PER_ROW),
            ),
            (
                Self::MemoryVar(MemoryVarChip::default()),
                heights.mem_var_events.div_ceil(VAR_EVENTS_PER_ROW),
            ),
            (
                Self::BaseAlu(BaseAluChip),
                heights.base_alu_events.div_ceil(NUM_BASE_ALU_ENTRIES_PER_ROW),
            ),
            (
                Self::ExtAlu(ExtAluChip),
                heights.ext_alu_events.div_ceil(NUM_EXT_ALU_ENTRIES_PER_ROW),
            ),
            (Self::Poseidon2Wide(Poseidon2WideChip::<DEGREE>), heights.poseidon2_wide_events),
            (
                Self::Poseidon2LinearLayer(Poseidon2LinearLayerChip),
                heights.poseidon2_linear_layer_events.div_ceil(NUM_LINEAR_ENTRIES_PER_ROW),
            ),
            (
                Self::Poseidon2SBox(Poseidon2SBoxChip),
                heights.poseidon2_sbox_events.div_ceil(NUM_SBOX_ENTRIES_PER_ROW),
            ),
            (
                Self::ExtFeltConvert(ConvertChip),
                heights.ext_felt_conversion_events.div_ceil(NUM_CONVERT_ENTRIES_PER_ROW),
            ),
            (Self::Select(SelectChip), heights.select_events),
            (Self::PublicValues(PublicValuesChip), 1 << PUB_VALUES_LOG_HEIGHT),
        ]
        .map(|(chip, log_height)| (chip.name().to_string(), log_height))
        .to_vec()
    }
}

#[cfg(test)]
pub mod tests {

    use std::iter::once;

    use rand::{rngs::StdRng, Rng, SeedableRng};
    use slop_algebra::{
        extension::{BinomialExtensionField, HasFrobenius},
        AbstractExtensionField, AbstractField, Field,
    };

    use sp1_recursion_executor::{
        instruction as instr, BaseAluOpcode, ExtAluOpcode, MemAccessKind, D,
    };

    use crate::test::test_recursion_linear_program;

    #[tokio::test]
    pub async fn fibonacci() {
        let n = 10;

        let instructions = once(instr::mem(MemAccessKind::Write, 1, 0, 0))
            .chain(once(instr::mem(MemAccessKind::Write, 2, 1, 1)))
            .chain((2..=n).map(|i| instr::base_alu(BaseAluOpcode::AddF, 2, i, i - 2, i - 1)))
            .chain(once(instr::mem(MemAccessKind::Read, 1, n - 1, 34)))
            .chain(once(instr::mem(MemAccessKind::Read, 2, n, 55)))
            .collect::<Vec<_>>();

        test_recursion_linear_program(instructions).await;
    }

    #[tokio::test]
    #[should_panic]
    pub async fn div_nonzero_by_zero() {
        let instructions = vec![
            instr::mem(MemAccessKind::Write, 1, 0, 0),
            instr::mem(MemAccessKind::Write, 1, 1, 1),
            instr::base_alu(BaseAluOpcode::DivF, 1, 2, 1, 0),
            instr::mem(MemAccessKind::Read, 1, 2, 1),
        ];

        test_recursion_linear_program(instructions).await;
    }

    #[tokio::test]
    pub async fn div_zero_by_zero() {
        let instructions = vec![
            instr::mem(MemAccessKind::Write, 1, 0, 0),
            instr::mem(MemAccessKind::Write, 1, 1, 0),
            instr::base_alu(BaseAluOpcode::DivF, 1, 2, 1, 0),
            instr::mem(MemAccessKind::Read, 1, 2, 1),
        ];

        test_recursion_linear_program(instructions).await;
    }

    #[tokio::test]
    pub async fn field_norm() {
        use sp1_primitives::SP1Field;
        type F = SP1Field;

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

        test_recursion_linear_program(instructions).await;
    }
}
