//! GPU validation of the generic witgen interpreter kernel: record
//! `AddrAddOperation::witgen` once, run the op-DAG on the device (one thread per
//! row), and assert the columns match the CPU `interpret_c_columns` reference.
//! Validates the CUDA kernel in isolation — no full e2e prove.

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use slop_algebra::AbstractField;
    use slop_alloc::Buffer;
    use sp1_core_machine::air::{columns_as_wires, RecordingWitnessBuilder, WireId};
    use sp1_core_machine::adapter::register::r_type::RTypeReader;
    use sp1_core_machine::adapter::state::CPUState;
    use sp1_core_machine::alu::add_sub::add::AddCols;
    use sp1_core_machine::SupervisorMode;
    use sp1_core_machine::memory::{RegisterAccessCols, RegisterAccessTimestamp};
    use sp1_core_machine::air::{
        interpret_c_columns as _interp, interpret_c_lookups, WitProgram, BYTE_HIST_ROWS,
        RANGE_HIST_ROWS,
    };
    use sp1_core_machine::bytes::columns::NUM_BYTE_MULT_COLS;
    use sp1_core_machine::operations::{AddOperation, AddrAddOperation, AddressOperation};
    use sp1_gpu_cudart::{args, DeviceBuffer, TaskScope, WitgenInterpKernel};

    use crate::F;

    /// Run a recorded gadget on the GPU interpreter over `n_rows` random 2-input
    /// rows and assert the columns match the CPU `interpret_c_columns` reference.
    async fn check_gadget(scope: TaskScope, program: WitProgram, col_wires: Vec<u32>) {
        let ops_c = program.to_c();
        let n_cols = col_wires.len();
        let num_inputs = program.num_inputs as usize;

        let n_rows = 1usize << 12;
        let mut rng = StdRng::seed_from_u64(7);
        let mut inputs: Vec<u64> = Vec::with_capacity(n_rows * num_inputs);
        for _ in 0..n_rows * num_inputs {
            // Mask to 30 bits (< the KoalaBear order ~2^31): a gadget's only *direct*
            // `nat_to_field` is of an input wire (e.g. an op index/value); all derived
            // quantities are `bits()`-decomposed first. Keeping inputs < P avoids the
            // now-strict `from_canonical` (asserts n < P) in the CPU reference while
            // still spanning multiple 16-bit limbs and the 24-bit timestamp low part.
            inputs.push(rng.gen::<u64>() & ((1u64 << 30) - 1));
        }

        let mut ops_dev = Buffer::try_with_capacity_in(ops_c.len(), scope.clone()).unwrap();
        ops_dev.extend_from_host_slice(&ops_c).unwrap();
        let mut col_dev = Buffer::try_with_capacity_in(col_wires.len(), scope.clone()).unwrap();
        col_dev.extend_from_host_slice(&col_wires).unwrap();
        let mut in_dev = Buffer::try_with_capacity_in(inputs.len(), scope.clone()).unwrap();
        in_dev.extend_from_host_slice(&inputs).unwrap();
        let mut out_buf = Buffer::try_with_capacity_in(n_cols * n_rows, scope.clone()).unwrap();
        out_buf.extend_from_host_slice(&vec![F::zero(); n_cols * n_rows]).unwrap();
        let mut out = DeviceBuffer::from_raw(out_buf);

        unsafe {
            const BLOCK: usize = 64;
            let grid = n_rows.div_ceil(BLOCK);
            let args = args!(
                out.as_mut_ptr(),
                n_rows,
                ops_dev.as_ptr(),
                ops_c.len(),
                col_dev.as_ptr(),
                n_cols,
                program.num_inputs,
                in_dev.as_ptr(),
                n_rows
            );
            scope.launch_kernel(TaskScope::witgen_interp_kernel(), grid, BLOCK, &args, 0).unwrap();
        }
        scope.synchronize_blocking().unwrap();

        let got: Vec<F> = out.to_host().unwrap();
        for r in 0..n_rows {
            let cpu = _interp::<F>(
                &ops_c,
                program.num_inputs,
                &inputs[r * num_inputs..(r + 1) * num_inputs],
                &col_wires,
            );
            for c in 0..n_cols {
                assert_eq!(got[c * n_rows + r], cpu[c], "mismatch at row {r}, col {c}");
            }
        }
    }

    #[tokio::test]
    async fn witgen_interp_addr_add_columns() {
        sp1_gpu_cudart::spawn(move |scope: TaskScope| async move {
            // Record the gadget once (shape is row-independent), validate on GPU.
            let mut rec = RecordingWitnessBuilder::new(2);
            let mut cols_w = AddrAddOperation::<WireId>::default();
            AddrAddOperation::<WireId>::witgen(
                &mut rec,
                &mut cols_w,
                RecordingWitnessBuilder::input(0),
                RecordingWitnessBuilder::input(1),
            );
            let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
            check_gadget(scope, rec.finish(), col_wires).await;
        })
        .await
        .unwrap();
    }

    /// Exercises `field_add`, `field_inverse`, and gadget composition on the GPU
    /// (AddressOperation composes AddrAddOperation and inverts a field sum).
    #[tokio::test]
    async fn witgen_interp_address_columns() {
        sp1_gpu_cudart::spawn(move |scope: TaskScope| async move {
            let mut rec = RecordingWitnessBuilder::new(2);
            let mut cols_w = AddressOperation::<WireId>::default();
            AddressOperation::<WireId>::witgen(
                &mut rec,
                &mut cols_w,
                RecordingWitnessBuilder::input(0),
                RecordingWitnessBuilder::input(1),
            );
            let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
            check_gadget(scope, rec.finish(), col_wires).await;
        })
        .await
        .unwrap();
    }

    /// A `Word` gadget (4 u16-limb columns) used by the RISC-V `Add` chip — a step
    /// toward porting a whole chip's witgen.
    #[tokio::test]
    async fn witgen_interp_add_word_columns() {
        sp1_gpu_cudart::spawn(move |scope: TaskScope| async move {
            let mut rec = RecordingWitnessBuilder::new(2);
            let mut cols_w = AddOperation::<WireId>::default();
            AddOperation::<WireId>::witgen(
                &mut rec,
                &mut cols_w,
                RecordingWitnessBuilder::input(0),
                RecordingWitnessBuilder::input(1),
            );
            let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
            check_gadget(scope, rec.finish(), col_wires).await;
        })
        .await
        .unwrap();
    }

    /// CPUState (clk/pc decomposition) — exercises `wrapping_sub` + `u8_range_check`
    /// (the new ops) on the device. A core piece of every RISC-V instruction chip.
    #[tokio::test]
    async fn witgen_interp_cpu_state_columns() {
        sp1_gpu_cudart::spawn(move |scope: TaskScope| async move {
            let mut rec = RecordingWitnessBuilder::new(2);
            let mut cols_w = CPUState::<WireId>::default();
            CPUState::<WireId>::witgen(
                &mut rec,
                &mut cols_w,
                RecordingWitnessBuilder::input(0),
                RecordingWitnessBuilder::input(1),
            );
            let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
            check_gadget(scope, rec.finish(), col_wires).await;
        })
        .await
        .unwrap();
    }

    /// RegisterAccessTimestamp — exercises `eq` + `select` (the new ops) plus
    /// `sub` on the device. The memory-access timing piece of every register read.
    #[tokio::test]
    async fn witgen_interp_reg_timestamp_columns() {
        sp1_gpu_cudart::spawn(move |scope: TaskScope| async move {
            let mut rec = RecordingWitnessBuilder::new(2);
            let mut cols_w = RegisterAccessTimestamp::<WireId>::default();
            RegisterAccessTimestamp::<WireId>::witgen(
                &mut rec,
                &mut cols_w,
                RecordingWitnessBuilder::input(0),
                RecordingWitnessBuilder::input(1),
            );
            let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
            check_gadget(scope, rec.finish(), col_wires).await;
        })
        .await
        .unwrap();
    }

    /// RegisterAccessCols (prev value Word + timestamp) — a full register read's
    /// columns, composing RegisterAccessTimestamp. 3 inputs (value, prev_ts, cur_ts).
    #[tokio::test]
    async fn witgen_interp_reg_access_columns() {
        sp1_gpu_cudart::spawn(move |scope: TaskScope| async move {
            let mut rec = RecordingWitnessBuilder::new(3);
            let mut cols_w = RegisterAccessCols::<WireId>::default();
            RegisterAccessCols::<WireId>::witgen(
                &mut rec,
                &mut cols_w,
                RecordingWitnessBuilder::input(0),
                RecordingWitnessBuilder::input(1),
                RecordingWitnessBuilder::input(2),
            );
            let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
            check_gadget(scope, rec.finish(), col_wires).await;
        })
        .await
        .unwrap();
    }

    /// RTypeReader — the full R-type register-read adapter: op_a/b/c indices, the
    /// op_a==0 flag (`eq`), and three composed RegisterAccessCols reads. 12 inputs.
    /// The largest composed gadget so far — a whole instruction adapter.
    #[tokio::test]
    async fn witgen_interp_rtype_reader_columns() {
        sp1_gpu_cudart::spawn(move |scope: TaskScope| async move {
            let mut rec = RecordingWitnessBuilder::new(12);
            let mut cols_w = RTypeReader::<WireId>::default();
            RTypeReader::<WireId>::witgen(
                &mut rec,
                &mut cols_w,
                RecordingWitnessBuilder::input(0),
                RecordingWitnessBuilder::input(1),
                RecordingWitnessBuilder::input(2),
                RecordingWitnessBuilder::input(3),
                RecordingWitnessBuilder::input(4),
                RecordingWitnessBuilder::input(5),
                RecordingWitnessBuilder::input(6),
                RecordingWitnessBuilder::input(7),
                RecordingWitnessBuilder::input(8),
                RecordingWitnessBuilder::input(9),
                RecordingWitnessBuilder::input(10),
                RecordingWitnessBuilder::input(11),
            );
            let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
            check_gadget(scope, rec.finish(), col_wires).await;
        })
        .await
        .unwrap();
    }

    /// The whole trusted (Supervisor) `Add` chip's witgen columns on the device:
    /// CPUState + RTypeReader + AddOperation + is_real, composed. 16 inputs (the
    /// AluEvent/RTypeRecord fields). The first end-to-end RISC-V chip on the GPU
    /// witgen interpreter.
    #[tokio::test]
    async fn witgen_interp_add_chip_columns() {
        sp1_gpu_cudart::spawn(move |scope: TaskScope| async move {
            let mut rec = RecordingWitnessBuilder::new(16);
            let mut cols_w = AddCols::<WireId, SupervisorMode>::default();
            AddCols::<WireId, SupervisorMode>::witgen(
                &mut rec,
                &mut cols_w,
                RecordingWitnessBuilder::input(0),
                RecordingWitnessBuilder::input(1),
                RecordingWitnessBuilder::input(2),
                RecordingWitnessBuilder::input(3),
                RecordingWitnessBuilder::input(4),
                RecordingWitnessBuilder::input(5),
                RecordingWitnessBuilder::input(6),
                RecordingWitnessBuilder::input(7),
                RecordingWitnessBuilder::input(8),
                RecordingWitnessBuilder::input(9),
                RecordingWitnessBuilder::input(10),
                RecordingWitnessBuilder::input(11),
                RecordingWitnessBuilder::input(12),
                RecordingWitnessBuilder::input(13),
                RecordingWitnessBuilder::input(14),
                RecordingWitnessBuilder::input(15),
            );
            let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
            check_gadget(scope, rec.finish(), col_wires).await;
        })
        .await
        .unwrap();
    }

    /// Validate the device byte-lookup kernel: run the trusted `Add` chip's op-DAG
    /// through `witgen_lookup_kernel` over random rows, accumulating into two device
    /// histograms, and assert they equal the CPU `interpret_c_lookups` reference
    /// (which iter-015 already proved equals the host `generate_dependencies` map).
    /// One thread per row, global `atomicAdd`; the GPU dual of the columns test.
    #[tokio::test]
    async fn witgen_lookup_add_chip_matches_cpu() {
        sp1_gpu_cudart::spawn(move |scope: TaskScope| async move {
            // Record the Add chip's op-DAG once (16 inputs).
            let mut rec = RecordingWitnessBuilder::new(16);
            let mut cols_w = AddCols::<WireId, SupervisorMode>::default();
            let wire = |i: u32| RecordingWitnessBuilder::input(i);
            AddCols::<WireId, SupervisorMode>::witgen(
                &mut rec,
                &mut cols_w,
                wire(0),
                wire(1),
                wire(2),
                wire(3),
                wire(4),
                wire(5),
                wire(6),
                wire(7),
                wire(8),
                wire(9),
                wire(10),
                wire(11),
                wire(12),
                wire(13),
                wire(14),
                wire(15),
            );
            let program = rec.finish();
            let ops_c = program.to_c();
            let num_inputs = program.num_inputs as usize;

            // Random rows. Lookups are integer-only, so any inputs are valid for both
            // backends; the table indices are bounded regardless (range checks mask to
            // u16, byte checks to u8). Mask to 40 bits to mimic realistic field values.
            let n_rows = 1usize << 12;
            let mut rng = StdRng::seed_from_u64(0xB17E);
            let inputs: Vec<u64> =
                (0..n_rows * num_inputs).map(|_| rng.gen::<u64>() & ((1u64 << 40) - 1)).collect();

            // CPU reference histograms.
            let mut cpu_range = vec![0u32; RANGE_HIST_ROWS];
            let mut cpu_byte = vec![0u32; BYTE_HIST_ROWS * NUM_BYTE_MULT_COLS];
            interpret_c_lookups(
                &ops_c,
                program.num_inputs,
                &inputs,
                n_rows,
                &mut cpu_range,
                &mut cpu_byte,
            );

            // Device buffers: op-DAG, inputs, and two zeroed histograms.
            let mut ops_dev = Buffer::try_with_capacity_in(ops_c.len(), scope.clone()).unwrap();
            ops_dev.extend_from_host_slice(&ops_c).unwrap();
            let mut in_dev = Buffer::try_with_capacity_in(inputs.len(), scope.clone()).unwrap();
            in_dev.extend_from_host_slice(&inputs).unwrap();

            let range_len = RANGE_HIST_ROWS;
            let byte_len = BYTE_HIST_ROWS * NUM_BYTE_MULT_COLS;
            let mut range_buf = Buffer::try_with_capacity_in(range_len, scope.clone()).unwrap();
            range_buf.extend_from_host_slice(&vec![0u32; range_len]).unwrap();
            let mut byte_buf = Buffer::try_with_capacity_in(byte_len, scope.clone()).unwrap();
            byte_buf.extend_from_host_slice(&vec![0u32; byte_len]).unwrap();
            let mut range_dev = DeviceBuffer::from_raw(range_buf);
            let mut byte_dev = DeviceBuffer::from_raw(byte_buf);

            unsafe {
                const BLOCK: usize = 64;
                let grid = n_rows.div_ceil(BLOCK);
                let args = args!(
                    ops_dev.as_ptr(),
                    ops_c.len(),
                    program.num_inputs,
                    in_dev.as_ptr(),
                    n_rows,
                    range_dev.as_mut_ptr(),
                    byte_dev.as_mut_ptr()
                );
                scope
                    .launch_kernel(TaskScope::witgen_lookup_kernel(), grid, BLOCK, &args, 0)
                    .unwrap();
            }
            scope.synchronize_blocking().unwrap();

            let gpu_range: Vec<u32> = range_dev.to_host().unwrap();
            let gpu_byte: Vec<u32> = byte_dev.to_host().unwrap();

            assert!(cpu_range.iter().any(|&m| m > 0), "test produced no range lookups");
            assert!(cpu_byte.iter().any(|&m| m > 0), "test produced no byte lookups");
            assert_eq!(gpu_range, cpu_range, "range histogram: GPU != CPU model");
            assert_eq!(gpu_byte, cpu_byte, "byte histogram: GPU != CPU model");
        })
        .await
        .unwrap();
    }
}
