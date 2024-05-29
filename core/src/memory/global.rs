use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use p3_air::BaseAir;
use p3_air::{Air, AirBuilder};
use p3_field::AbstractField;
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_derive::AlignedBorrow;

use super::MemoryInitializeFinalizeEvent;
use crate::air::{AirInteraction, BaseAirBuilder, SP1AirBuilder, Word};
use crate::air::{MachineAir, WordAirBuilder};
use crate::operations::BabyBearBitDecomposition;
use crate::runtime::{ExecutionRecord, Program};
use crate::utils::pad_to_power_of_two;

/// The type of memory chip that is being initialized.
#[derive(PartialEq)]
pub enum MemoryChipType {
    Initialize,
    Finalize,
}

/// A memory chip that can initialize or finalize values in memory.
pub struct MemoryChip {
    pub kind: MemoryChipType,
}

impl MemoryChip {
    /// Creates a new memory chip with a certain type.
    pub const fn new(kind: MemoryChipType) -> Self {
        Self { kind }
    }
}

impl<F> BaseAir<F> for MemoryChip {
    fn width(&self) -> usize {
        NUM_MEMORY_INIT_COLS
    }
}

impl<F: PrimeField> MachineAir<F> for MemoryChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        match self.kind {
            MemoryChipType::Initialize => "MemoryInit".to_string(),
            MemoryChipType::Finalize => "MemoryFinalize".to_string(),
        }
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut memory_events = match self.kind {
            MemoryChipType::Initialize => input.memory_initialize_events.clone(),
            MemoryChipType::Finalize => input.memory_finalize_events.clone(),
        };
        memory_events.sort_by_key(|event| event.addr);
        let rows: Vec<[F; NUM_MEMORY_INIT_COLS]> = (0..memory_events.len()) // TODO: change this back to par_iter
            .map(|i| {
                let MemoryInitializeFinalizeEvent {
                    addr,
                    value,
                    shard,
                    timestamp,
                    used,
                } = memory_events[i];

                let mut row = [F::zero(); NUM_MEMORY_INIT_COLS];
                let cols: &mut MemoryInitCols<F> = row.as_mut_slice().borrow_mut();
                cols.addr = F::from_canonical_u32(addr);
                cols.addr_bits.populate(addr);
                cols.shard = F::from_canonical_u32(shard);
                cols.timestamp = F::from_canonical_u32(timestamp);
                cols.value = value.into();
                cols.is_real = F::from_canonical_u32(used);

                if i != memory_events.len() - 1 {
                    let next_addr = memory_events[i + 1].addr;
                    assert_ne!(next_addr, addr);

                    cols.addr_bits.populate(addr);

                    for j in (0..32).rev() {
                        let next_bit = (next_addr >> j) & 1;
                        let local_bit = (addr >> j) & 1;
                        if j == 31 {
                            cols.seen_larger_bit[j] = F::from_bool(next_bit > local_bit);
                        } else {
                            cols.seen_larger_bit[j] = cols.seen_larger_bit[j + 1]
                                + (F::one() - cols.seen_larger_bit[j + 1])
                                    * F::from_bool(next_bit > local_bit);
                        }
                    }
                    assert_eq!(cols.seen_larger_bit[0], F::one());
                }

                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_INIT_COLS,
        );

        pad_to_power_of_two::<NUM_MEMORY_INIT_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        match self.kind {
            MemoryChipType::Initialize => !shard.memory_initialize_events.is_empty(),
            MemoryChipType::Finalize => !shard.memory_finalize_events.is_empty(),
        }
    }
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryInitCols<T> {
    /// The shard number of the memory access.
    pub shard: T,

    /// The timestamp of the memory access.
    pub timestamp: T,

    /// The address of the memory access.
    pub addr: T,

    /// A bit decomposition of `addr`.
    pub addr_bits: BabyBearBitDecomposition<T>,

    // Whether we've seen a larger bit.
    pub seen_larger_bit: [T; 32],

    /// The value of the memory access.
    pub value: Word<T>,

    /// Whether the memory access is a real access.
    pub is_real: T,
}

pub(crate) const NUM_MEMORY_INIT_COLS: usize = size_of::<MemoryInitCols<u8>>();

impl<AB> Air<AB> for MemoryChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryInitCols<AB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &MemoryInitCols<AB::Var> = (*next).borrow();

        builder.assert_bool(local.is_real);

        if self.kind == MemoryChipType::Initialize {
            let mut values = vec![AB::Expr::zero(), AB::Expr::zero(), local.addr.into()];
            values.extend(local.value.map(Into::into));
            builder.receive(AirInteraction::new(
                values,
                local.is_real.into(),
                crate::lookup::InteractionKind::Memory,
            ));
        } else {
            let mut values = vec![
                local.shard.into(),
                local.timestamp.into(),
                local.addr.into(),
            ];
            values.extend(local.value.map(Into::into));
            builder.send(AirInteraction::new(
                values,
                local.is_real.into(),
                crate::lookup::InteractionKind::Memory,
            ));
        }

        // Calculate whether we've seen a larger bit.
        for i in (0..local.addr_bits.bits.len()).rev() {
            // If we're in the first iteration, just compute whether next > local.
            if i == 31 {
                builder.when_transition().assert_eq(
                    local.seen_larger_bit[i],
                    next.addr_bits.bits[i] * (AB::Expr::one() - local.addr_bits.bits[i]),
                );
            // If we're in any other iteration, compute whether seen_larger_bit_prev +
            // (1-seen_larger_bit_prev) * (next > local).
            } else {
                builder.when_transition().assert_eq(
                    local.seen_larger_bit[i],
                    local.seen_larger_bit[i + 1]
                        + (AB::Expr::one() - local.seen_larger_bit[i + 1])
                            * next.addr_bits.bits[i]
                            * (AB::Expr::one() - local.addr_bits.bits[i]),
                );
            }
        }

        // Assert that the address must be increasing for rows that have a next row.
        builder
            .when_transition()
            .when(next.is_real)
            .assert_eq(local.seen_larger_bit[0], AB::Expr::one());

        // Canonically decompose the address into bits so we can do comparisons.
        BabyBearBitDecomposition::<AB::F>::range_check(
            builder,
            local.addr,
            local.addr_bits,
            local.is_real.into(),
        );

        // Assert that the real rows are all padded to the top.
        builder
            .when_transition()
            .when_not(local.is_real)
            .assert_zero(next.is_real);

        if self.kind == MemoryChipType::Initialize {
            builder
                .when(local.is_real)
                .assert_eq(local.timestamp, AB::F::one());
        }

        // Register %x0 should always be 0. See 2.6 Load and Store Instruction on
        // P.18 of the RISC-V spec.  To ensure that, we expect that the first row of the Initialize
        // and Finalize global memory chip is for register %x0 (i.e. addr = 0x0), and that those rows
        // have a value of 0.  Additionally, in the CPU air, we ensure that whenever op_a is set to
        // %x0, its value is 0.
        if self.kind == MemoryChipType::Initialize || self.kind == MemoryChipType::Finalize {
            builder.when_first_row().assert_zero(local.addr);
            builder.when_first_row().assert_word_zero(local.value);
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::lookup::{debug_interactions_with_all_chips, InteractionKind};
    use crate::runtime::tests::simple_program;
    use crate::runtime::Runtime;
    use crate::stark::MachineRecord;
    use crate::stark::{RiscvAir, StarkGenericConfig};
    use crate::syscall::precompiles::sha256::extend_tests::sha_extend_program;
    use crate::utils::{setup_logger, BabyBearPoseidon2, SP1CoreOpts};
    use crate::utils::{uni_stark_prove as prove, uni_stark_verify as verify};
    use p3_baby_bear::BabyBear;

    #[test]
    fn test_memory_generate_trace() {
        let program = simple_program();
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        let shard = runtime.record.clone();

        let chip: MemoryChip = MemoryChip::new(MemoryChipType::Initialize);

        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values);

        let chip: MemoryChip = MemoryChip::new(MemoryChipType::Finalize);
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values);

        for mem_event in shard.memory_finalize_events {
            println!("{:?}", mem_event);
        }
    }

    #[test]
    fn test_memory_prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let program = simple_program();
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();

        let chip = MemoryChip::new(MemoryChipType::Initialize);

        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&runtime.record, &mut ExecutionRecord::default());
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }

    #[test]
    fn test_memory_lookup_interactions() {
        setup_logger();
        let program = sha_extend_program();
        let program_clone = program.clone();
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        let machine: crate::stark::StarkMachine<BabyBearPoseidon2, RiscvAir<BabyBear>> =
            RiscvAir::machine(BabyBearPoseidon2::new());
        let (pkey, _) = machine.setup(&program_clone);
        let shards = machine.shard(
            runtime.record,
            &<ExecutionRecord as MachineRecord>::Config::default(),
        );
        assert_eq!(shards.len(), 1);
        debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
            &machine,
            &pkey,
            &shards,
            vec![InteractionKind::Memory],
        );
    }

    #[test]
    fn test_byte_lookup_interactions() {
        setup_logger();
        let program = sha_extend_program();
        let program_clone = program.clone();
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        let machine = RiscvAir::machine(BabyBearPoseidon2::new());
        let (pkey, _) = machine.setup(&program_clone);
        let shards = machine.shard(
            runtime.record,
            &<ExecutionRecord as MachineRecord>::Config::default(),
        );
        assert_eq!(shards.len(), 1);
        debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
            &machine,
            &pkey,
            &shards,
            vec![InteractionKind::Byte],
        );
    }
}
