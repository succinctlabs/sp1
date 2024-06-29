use core::borrow::Borrow;
use p3_air::{Air, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::AirInteraction;
use sp1_core::air::MachineAir;
use sp1_core::air::SP1AirBuilder;
use sp1_core::lookup::InteractionKind;
use sp1_core::utils::pad_to_power_of_two;
use sp1_derive::AlignedBorrow;
use std::borrow::BorrowMut;

use crate::*;

pub const NUM_MEM_INIT_COLS: usize = core::mem::size_of::<MemoryCols<u8>>();

#[derive(Default)]
pub struct MemoryChip {}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryCols<T: Copy> {
    pub address_value: AddressValue<T>,
    pub read_mult: T,
    pub write_mult: T,
    pub is_real: T,
}

impl<F> BaseAir<F> for MemoryChip {
    fn width(&self) -> usize {
        NUM_MEM_INIT_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for MemoryChip {
    type Record = crate::ExecutionRecord<F>;

    type Program = crate::RecursionProgram<F>;

    fn name(&self) -> String {
        "Memory".to_string()
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn generate_trace(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let mem_events = input.mem_events.clone();

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let rows = mem_events
            .into_iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_MEM_INIT_COLS];

                let MemEvent {
                    address_value,
                    multiplicity,
                    kind,
                } = event;

                let (read_mult, write_mult): (F, F) = match kind {
                    MemAccessKind::Read => (multiplicity, F::zero()),
                    MemAccessKind::Write => (F::zero(), multiplicity),
                };

                let cols: &mut MemoryCols<_> = row.as_mut_slice().borrow_mut();
                *cols = MemoryCols {
                    address_value,
                    read_mult,
                    write_mult,
                    is_real: F::from_bool(true),
                };

                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEM_INIT_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_MEM_INIT_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB> Air<AB> for MemoryChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryCols<AB::Var> = (*local).borrow();

        // At most one should be true.
        // builder.assert_zero(local.read_mult * local.write_mult);

        let values = vec![
            local.address_value.addr.into(),
            local.address_value.val.into(),
        ];

        builder.receive(AirInteraction::new(
            values.clone(),
            local.read_mult.into(),
            InteractionKind::Memory,
        ));

        builder.send(AirInteraction::new(
            values,
            local.write_mult.into(),
            InteractionKind::Memory,
        ));
    }
}

/*

1) make a dummy program for loop 100: x' = x*x + x
2) make mem_init chip and mul chip with 3 columns each that prove a = b + c and a = b * c respectively.
and then also fill in generate_trace and eval and write test (look at mem_init_sub in core for test example).
you will also need to write your own execution record struct but look at recursion-core for how we did that

*/

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use p3_baby_bear::BabyBear;
    use p3_baby_bear::DiffusionMatrixBabyBear;
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::Matrix;
    use p3_poseidon2::Poseidon2;
    use p3_poseidon2::Poseidon2ExternalMatrixGeneral;

    use std::time::Instant;

    use sp1_core::{air::MachineAir, utils::uni_stark_verify};
    use sp1_core::{
        stark::StarkGenericConfig,
        utils::{uni_stark_prove, BabyBearPoseidon2},
    };

    use super::*;

    #[test]
    fn generate_trace() {
        let shard = ExecutionRecord::<BabyBear> {
            mem_events: vec![
                MemEvent {
                    address_value: AddressValue::new(BabyBear::zero(), BabyBear::one()),
                    multiplicity: BabyBear::one(),
                    kind: MemAccessKind::Write,
                },
                MemEvent {
                    address_value: AddressValue::new(BabyBear::zero(), BabyBear::one()),
                    multiplicity: BabyBear::one(),
                    kind: MemAccessKind::Read,
                },
            ],
            ..Default::default()
        };
        let chip = MemoryChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::compressed();
        let mut challenger = config.challenger();

        let chip = MemoryChip::default();

        let test_xs = (1..8).map(BabyBear::from_canonical_u32).collect_vec();

        // Doesn't test that reads and writes cancel out
        let mut input_exec = ExecutionRecord::<BabyBear>::default();
        input_exec
            .mem_events
            .extend(test_xs.clone().into_iter().map(|x| MemEvent {
                address_value: AddressValue::new(x, x + BabyBear::one()),
                multiplicity: BabyBear::one(),
                kind: MemAccessKind::Write,
            }));
        input_exec
            .mem_events
            .extend(test_xs.clone().into_iter().map(|x| MemEvent {
                address_value: AddressValue::new(x, x + BabyBear::one()),
                multiplicity: BabyBear::one(),
                kind: MemAccessKind::Read,
            }));

        println!("input exec: {:?}", input_exec.mem_events.len());
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());
        println!(
            "trace dims is width: {:?}, height: {:?}",
            trace.width(),
            trace.height()
        );

        let start = Instant::now();
        let proof = uni_stark_prove(&config, &chip, &mut challenger, trace);
        let duration = start.elapsed().as_secs_f64();
        println!("proof duration = {:?}", duration);

        let mut challenger: p3_challenger::DuplexChallenger<
            BabyBear,
            Poseidon2<BabyBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>,
            16,
            8,
        > = config.challenger();
        let start = Instant::now();
        uni_stark_verify(&config, &chip, &mut challenger, &proof)
            .expect("expected proof to be valid");

        let duration = start.elapsed().as_secs_f64();
        println!("verify duration = {:?}", duration);
    }
}
