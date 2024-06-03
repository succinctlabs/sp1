use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use std::array;

use p3_air::BaseAir;
use p3_air::{Air, AirBuilder};
use p3_field::AbstractField;
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_derive::AlignedBorrow;

use super::MemoryInitializeFinalizeEvent;
use crate::air::MachineAir;
use crate::air::{AirInteraction, BaseAirBuilder, SP1AirBuilder};
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
        let rows: Vec<[F; NUM_MEMORY_INIT_COLS]> = (0..memory_events.len()) // OPT: change this to par_iter
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
                cols.value = array::from_fn(|i| F::from_canonical_u32((value >> i) & 1));
                cols.is_real = F::from_canonical_u32(used);

                if i != memory_events.len() - 1 {
                    let next_addr = memory_events[i + 1].addr;
                    assert_ne!(next_addr, addr);

                    cols.addr_bits.populate(addr);

                    cols.seen_diff_bits[0] = F::zero();
                    for j in 0..32 {
                        let rev_j = 32 - j - 1;
                        let next_bit = ((next_addr >> rev_j) & 1) == 1;
                        let local_bit = ((addr >> rev_j) & 1) == 1;
                        cols.match_bits[j] =
                            F::from_bool((local_bit && next_bit) || (!local_bit && !next_bit));
                        cols.seen_diff_bits[j + 1] = cols.seen_diff_bits[j]
                            + (F::one() - cols.seen_diff_bits[j]) * (F::one() - cols.match_bits[j]);
                        cols.not_match_and_not_seen_diff_bits[j] =
                            (F::one() - cols.match_bits[j]) * (F::one() - cols.seen_diff_bits[j]);
                    }
                    assert_eq!(cols.seen_diff_bits[cols.seen_diff_bits.len() - 1], F::one());
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

#[derive(AlignedBorrow, Debug, Clone, Copy)]
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

    // Whether the i'th bit matches the next addr's bit.
    pub match_bits: [T; 32],

    // Whether we've seen a different bit in the comparison.
    pub seen_diff_bits: [T; 33],

    // Whether the i'th bit doesn't match the next addr's bit and we haven't seen a diff bitn yet.
    pub not_match_and_not_seen_diff_bits: [T; 32],

    /// The value of the memory access.
    pub value: [T; 32],

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
        for i in 0..32 {
            builder.assert_bool(local.value[i]);
        }

        let mut byte1 = AB::Expr::zero();
        let mut byte2 = AB::Expr::zero();
        let mut byte3 = AB::Expr::zero();
        let mut byte4 = AB::Expr::zero();
        for i in 0..8 {
            byte1 += local.value[i].into() * AB::F::from_canonical_u8(1 << i);
            byte2 += local.value[i + 8].into() * AB::F::from_canonical_u8(1 << i);
            byte3 += local.value[i + 16].into() * AB::F::from_canonical_u8(1 << i);
            byte4 += local.value[i + 24].into() * AB::F::from_canonical_u8(1 << i);
        }
        let value = [byte1, byte2, byte3, byte4];

        if self.kind == MemoryChipType::Initialize {
            let mut values = vec![AB::Expr::zero(), AB::Expr::zero(), local.addr.into()];
            values.extend(value.map(Into::into));
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
            values.extend(value);
            builder.send(AirInteraction::new(
                values,
                local.is_real.into(),
                crate::lookup::InteractionKind::Memory,
            ));
        }

        // We want to assert addr < addr'. Assume seen_diff_0 = 0.
        //
        // match_i = (addr_i & addr'_i) || (!addr_i & !addr'_i)
        // =>
        // match_i == addr_i * addr_i + (1 - addr_i) * (1 - addr'_i)
        //
        // when !match_i and !seen_diff_i, then enforce (addr_i == 0) and (addr'_i == 1).
        // if seen_diff_i:
        //     seen_diff_{i+1} = 1
        // else:
        //     seen_diff_{i+1} = !match_i
        // =>
        // builder.when(!match_i * !seen_diff_i).assert_zero(addr_i)
        // builder.when(!match_i * !seen_diff_i).assert_one(addr'_i)
        // seen_diff_bit_{i+1} == seen_diff_i + (1-seen_diff_i) * (1 - match_i)
        //
        // at the end of the algorithm, assert that we've seen a diff bit.
        // =>
        // seen_diff_bit_{last} == 1

        // Assert that we start with assuming that we haven't seen a diff bit.
        builder.assert_zero(local.seen_diff_bits[0]);

        for i in 0..local.addr_bits.bits.len() {
            // Compute the i'th msb bit's index.
            let rev_i = local.addr_bits.bits.len() - i - 1;

            // Compute whether the i'th msb bit matches.
            let match_i = local.addr_bits.bits[rev_i] * next.addr_bits.bits[rev_i]
                + (AB::Expr::one() - local.addr_bits.bits[rev_i])
                    * (AB::Expr::one() - next.addr_bits.bits[rev_i]);
            builder
                .when_transition()
                .when(next.is_real)
                .assert_eq(match_i.clone(), local.match_bits[i]);

            // Compute whether it's not a match and we haven't seen a diff bit.
            let not_match_and_not_seen_diff_i = (AB::Expr::one() - local.match_bits[i])
                * (AB::Expr::one() - local.seen_diff_bits[i]);
            builder.when_transition().when(next.is_real).assert_eq(
                local.not_match_and_not_seen_diff_bits[i],
                not_match_and_not_seen_diff_i,
            );

            // If the i'th msb bit doesn't match and it's the first time we've seen a diff bit,
            // then enforce that the next bit is one and the current bit is zero.
            builder
                .when_transition()
                .when(local.not_match_and_not_seen_diff_bits[i])
                .when(next.is_real)
                .assert_zero(local.addr_bits.bits[rev_i]);
            builder
                .when_transition()
                .when(local.not_match_and_not_seen_diff_bits[i])
                .when(next.is_real)
                .assert_one(next.addr_bits.bits[rev_i]);

            // Update the seen diff bits.
            builder.when_transition().assert_eq(
                local.seen_diff_bits[i + 1],
                local.seen_diff_bits[i] + local.not_match_and_not_seen_diff_bits[i],
            );
        }

        // Assert that on rows where the next row is real, we've seen a diff bit.
        builder
            .when_transition()
            .when(next.is_real)
            .assert_one(local.seen_diff_bits[local.addr_bits.bits.len()]);

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
            for i in 0..32 {
                builder.when_first_row().assert_zero(local.value[i]);
            }
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
