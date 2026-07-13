//! Device main-trace + dependency generation for the trusted `Mul` chip
//! (MUL/MULH/MULHU/MULHSU/MULW). Uses the register-register `RTypeReader` adapter
//! like `Add`, plus the `mul` (nat-multiply) kernel op for the byte convolution.
//! The convolution makes this the widest gadget (see `WITGEN_MAX_WIRES`).

use core::borrow::BorrowMut;

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_tensor::Tensor;
use sp1_core_executor::{events::AluEvent, RTypeRecord};
use sp1_core_machine::{
    adapter::register::r_type::RTypeReaderWitgenInput,
    air::{columns_as_wires, record_witgen_inputs, WireId},
    alu::mul::{MulChip, MulCols, MulWitgenInput, NUM_MUL_COLS_SUPERVISOR, NUM_MUL_WITGEN_INPUTS},
    SupervisorMode,
};
use sp1_gpu_cudart::{DeviceBuffer, DeviceMle, TaskScope};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Pack each event into one [`MulWitgenInput`] row.
pub(crate) fn pack_mul_inputs(events: &[(AluEvent, RTypeRecord)]) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_MUL_WITGEN_INPUTS];
    inputs.par_chunks_mut(NUM_MUL_WITGEN_INPUTS).zip(events.par_iter()).for_each(
        |(chunk, (alu, r))| {
            let slot: &mut MulWitgenInput<u64> = chunk.borrow_mut();
            slot.clk = alu.clk;
            slot.pc = alu.pc;
            slot.a = alu.a;
            slot.b = alu.b;
            slot.c = alu.c;
            slot.opcode = alu.opcode as u64;
            slot.adapter = RTypeReaderWitgenInput::from_record(r);
        },
    );
    inputs
}

fn record_mul_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let (mut rec, input) = record_witgen_inputs::<MulWitgenInput<WireId>>();
    let mut cols_w = MulCols::<WireId, SupervisorMode>::default();
    MulCols::<WireId, SupervisorMode>::witgen(&mut rec, &mut cols_w, &input);
    let program = rec.finish();
    let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
    // Register allocation bounds the per-thread wire array by max-live slots, not raw
    // wires, so the wide Mul gadget (531 wires) fits the kernel (100 slots) via the
    // slot-indexed witgen path (generate_columns_slots_into / accumulate_lookups_slots).
    let (_, max_slots) = program.allocate_slots(&col_wires);
    assert!(
        max_slots as usize <= super::WITGEN_MAX_WIRES,
        "Mul gadget needs {max_slots} slots > kernel capacity {}",
        super::WITGEN_MAX_WIRES
    );
    (program, col_wires)
}

/// The chip's cached [`WitgenChip`](super::WitgenChip) descriptor: recorded +
/// lowered ONCE per process (the program is shard-independent), not per shard.
fn mul_witgen_chip() -> &'static super::WitgenChip {
    static CHIP: std::sync::OnceLock<super::WitgenChip> = std::sync::OnceLock::new();
    CHIP.get_or_init(|| {
        let (program, col_wires) = record_mul_program();
        super::WitgenChip::new(program, col_wires)
    })
}

impl CudaTracegenAir<F> for MulChip<SupervisorMode> {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let chip = mul_witgen_chip();
        let n_cols = chip.n_cols();
        debug_assert_eq!(n_cols, NUM_MUL_COLS_SUPERVISOR);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.mul_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        let inputs = pack_mul_inputs(&events[..n_events]);

        // Wide gadget: register-allocated slot kernel (531 wires -> 100 slots). Padding
        // rows are all-zero (is_mul..is_mulw = 0 → padding row).
        let trace = Tensor::<F, TaskScope>::zeros_in([n_cols, height], scope.clone());
        super::generate_columns_slots_into(
            chip,
            super::WitgenBatch { inputs: &inputs, n_events, height },
            trace,
            scope,
        )
        .await
    }

    /// Fused device path — the one the PROVER actually calls for Mul (since
    /// `supports_device_dependencies` is true): columns + byte/range lookups in one
    /// register-allocated pass. `inputs` is pre-packed pre-permit by
    /// `pack_device_lookup_inputs` (the Mul arm in mod.rs). Missing this override was the
    /// iter-067 hang — the enum dispatch hit the trait-default `unimplemented!()`.
    async fn generate_trace_device_with_lookups(
        &self,
        input: &Self::Record,
        inputs: Vec<u64>,
        hist: crate::LookupHist,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let chip = mul_witgen_chip();
        debug_assert_eq!(chip.n_cols(), NUM_MUL_COLS_SUPERVISOR);
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let n_events =
            if height == 0 { 0 } else { inputs.len() / chip.program.num_inputs as usize };
        super::generate_trace_and_lookups_slots(
            chip,
            super::WitgenBatch { inputs: &inputs, n_events, height },
            hist,
            scope,
        )
        .await
    }

    fn supports_device_dependencies(&self) -> bool {
        true
    }

    async fn generate_device_dependencies(
        &self,
        input: &Self::Record,
        range_dev: &mut DeviceBuffer<u32>,
        byte_dev: &mut DeviceBuffer<u32>,
        scope: &TaskScope,
    ) -> Result<(), CopyError> {
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.mul_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        if n_events == 0 {
            return Ok(());
        }

        let inputs = pack_mul_inputs(&events[..n_events]);
        super::accumulate_lookups_slots(
            mul_witgen_chip(),
            &inputs,
            n_events,
            range_dev,
            byte_dev,
            scope,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use slop_tensor::Tensor;
    use sp1_core_executor::events::{AluEvent, MemoryReadRecord, MemoryRecordEnum};
    use sp1_core_executor::{ExecutionRecord, Opcode, RTypeRecord};
    use sp1_core_machine::alu::mul::MulChip;
    use sp1_core_machine::SupervisorMode;
    use sp1_gpu_cudart::TaskScope;
    use sp1_hypercube::air::MachineAir;

    use crate::{CudaTracegenAir, F};

    fn read(rng: &mut StdRng) -> MemoryRecordEnum {
        let prev_timestamp = rng.gen::<u32>() as u64;
        let timestamp = prev_timestamp + 1 + (rng.gen::<u32>() as u64);
        MemoryRecordEnum::Read(MemoryReadRecord {
            value: rng.gen::<u32>() as u64,
            timestamp,
            prev_timestamp,
            prev_page_prot_record: None,
        })
    }

    /// Device-vs-CPU trace equality for `Mul` over all 5 opcodes (MUL/MULH/MULHU/
    /// MULHSU/MULW) with random 64-bit operands — exercises the byte convolution,
    /// signed sign-extension, and the MULW msb path.
    #[tokio::test]
    async fn test_mul_generate_trace_device() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let mut rng = StdRng::seed_from_u64(0x6017);
            let ops = [Opcode::MUL, Opcode::MULH, Opcode::MULHU, Opcode::MULHSU, Opcode::MULW];
            let mul_events = (0..1500)
                .map(|i| {
                    let opcode = ops[i % 5];
                    let b = rng.gen::<u64>();
                    let c = rng.gen::<u64>();
                    let (bi, ci) = (b as i64 as i128, c as i64 as i128);
                    let (bu, cu) = (b as u128, c as u128);
                    let a = match opcode {
                        Opcode::MUL => b.wrapping_mul(c),
                        Opcode::MULH => ((bi * ci) >> 64) as u64,
                        Opcode::MULHU => ((bu * cu) >> 64) as u64,
                        Opcode::MULHSU => ((bi * (cu as i128)) >> 64) as u64,
                        _ => ((b as i32).wrapping_mul(c as i32) as i64) as u64,
                    };
                    let alu = AluEvent::new(
                        (i as u64) * 8 + 8,
                        (i as u64) * 4 + 4,
                        opcode,
                        a,
                        b,
                        c,
                        false,
                    );
                    let record = RTypeRecord {
                        op_a: rng.gen_range(1..32),
                        a: read(&mut rng),
                        op_b: rng.gen_range(1..32),
                        b: read(&mut rng),
                        op_c: rng.gen_range(1..32),
                        c: read(&mut rng),
                        is_untrusted: false,
                    };
                    (alu, record)
                })
                .collect::<Vec<_>>();

            let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
                mul_events: mul_events.clone(),
                ..Default::default()
            });

            let chip = MulChip::<SupervisorMode>::default();

            let trace =
                Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
            let gpu_trace = chip
                .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
                .await
                .expect("device tracegen should succeed")
                .to_host()
                .expect("copy trace to host")
                .into_guts();

            crate::tests::test_traces_eq(&trace, &gpu_trace, &mul_events);
        })
        .await
        .unwrap();
    }

    /// Register allocation on the (widest) Mul op-DAG: assert it (1) shrinks the
    /// per-thread footprint far below the 256-wire cap that gates Mul off device, and
    /// (2) produces bit-identical columns to the SSA interpreter — the CPU model the
    /// tiered register-allocated kernel will port. Uses real packed inputs.
    #[test]
    fn mul_regalloc_shrinks_and_matches() {
        use sp1_core_machine::air::{
            columns_as_wires, interpret_c_columns, interpret_c_slots_columns,
            interpret_c_slots_streaming_columns, interpret_slots_columns, record_witgen_inputs,
            WireId,
        };
        use sp1_core_machine::alu::mul::{MulCols, MulWitgenInput, NUM_MUL_WITGEN_INPUTS};

        // Build the Mul program inline (`record_mul_program` asserts <=256; Mul is 531).
        let (mut rec, input) = record_witgen_inputs::<MulWitgenInput<WireId>>();
        let mut cols_w = MulCols::<WireId, SupervisorMode>::default();
        MulCols::<WireId, SupervisorMode>::witgen(&mut rec, &mut cols_w, &input);
        let program = rec.finish();
        let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();

        let (slot, max_slots) = program.allocate_slots(&col_wires);
        assert!(
            max_slots <= 128,
            "Mul reg-alloc: max_slots={max_slots} (num_wires={}) should fit a 128-tier",
            program.num_wires()
        );

        // Real events → packed 18/row inputs; compare SSA vs slot interpreter per row.
        let mut rng = StdRng::seed_from_u64(0x6017);
        let ops = [Opcode::MUL, Opcode::MULH, Opcode::MULHU, Opcode::MULHSU, Opcode::MULW];
        let events = (0..64)
            .map(|i| {
                let opcode = ops[i % 5];
                let b = rng.gen::<u64>();
                let c = rng.gen::<u64>();
                let (bi, ci) = (b as i64 as i128, c as i64 as i128);
                let (bu, cu) = (b as u128, c as u128);
                let a = match opcode {
                    Opcode::MUL => b.wrapping_mul(c),
                    Opcode::MULH => ((bi * ci) >> 64) as u64,
                    Opcode::MULHU => ((bu * cu) >> 64) as u64,
                    Opcode::MULHSU => ((bi * (cu as i128)) >> 64) as u64,
                    _ => ((b as i32).wrapping_mul(c as i32) as i64) as u64,
                };
                let alu =
                    AluEvent::new((i as u64) * 8 + 8, (i as u64) * 4 + 4, opcode, a, b, c, false);
                let record = RTypeRecord {
                    op_a: rng.gen_range(1..32),
                    a: read(&mut rng),
                    op_b: rng.gen_range(1..32),
                    b: read(&mut rng),
                    op_c: rng.gen_range(1..32),
                    c: read(&mut rng),
                    is_untrusted: false,
                };
                (alu, record)
            })
            .collect::<Vec<_>>();
        let inputs = super::pack_mul_inputs(&events);
        let ops_c = program.to_c();
        // Slot-resolved flat form (the exact layout the register-allocated kernel
        // ports) + its remapped inputs/columns.
        let ops_slots = program.to_c_slots(&slot);
        let input_slots = &slot[..NUM_MUL_WITGEN_INPUTS];
        let col_slots: Vec<u32> = col_wires.iter().map(|&w| slot[w as usize]).collect();
        let ni = NUM_MUL_WITGEN_INPUTS;
        for row in 0..events.len() {
            let row_in = &inputs[row * ni..(row + 1) * ni];
            let ssa: Vec<F> = interpret_c_columns(&ops_c, ni as u32, row_in, &col_wires);
            let alloc: Vec<F> =
                interpret_slots_columns(&program, row_in, &col_wires, &slot, max_slots);
            // The flat slot form (WitOpCSlot, out/a/b pre-resolved) must also match
            // the SSA reference — this is what de-risks the CUDA `nat[op.out]` edit.
            let flat: Vec<F> = interpret_c_slots_columns(
                &ops_slots,
                ni as u32,
                row_in,
                input_slots,
                &col_slots,
                max_slots,
            );
            assert_eq!(ssa, alloc, "reg-alloc column mismatch at row {row}");
            assert_eq!(ssa, flat, "slot-flat (WitOpCSlot) column mismatch at row {row}");
        }

        // STREAMING (store-through) lowering: columns written at production, no
        // readout pinning — the smem-kernel model. Must match SSA bit-for-bit,
        // and the transient footprint should collapse far below the pinned one.
        let lowering = program.lower_streaming(&col_wires);
        for row in 0..events.len() {
            let row_in = &inputs[row * ni..(row + 1) * ni];
            let ssa: Vec<F> = interpret_c_columns(&ops_c, ni as u32, row_in, &col_wires);
            let streamed: Vec<F> =
                interpret_c_slots_streaming_columns(&lowering, ni as u32, row_in, col_wires.len());
            assert_eq!(ssa, streamed, "streaming column mismatch at row {row}");
        }
        assert!(lowering.max_slots < max_slots, "streaming should shrink the footprint");
        eprintln!(
            "Mul streaming: pinned max_slots={max_slots} -> streaming max_slots={} \
             (epilogue {} entries, input_cols {})",
            lowering.max_slots,
            lowering.epilogue.len(),
            lowering.input_cols.len()
        );
        eprintln!(
            "Mul reg-alloc OK: num_wires={} -> max_slots={max_slots} ({:.1}x)",
            program.num_wires(),
            program.num_wires() as f64 / max_slots as f64
        );
    }
}
