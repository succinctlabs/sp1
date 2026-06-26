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
    use sp1_core_machine::adapter::state::CPUState;
    use sp1_core_machine::memory::{RegisterAccessCols, RegisterAccessTimestamp};
    use sp1_core_machine::air::{interpret_c_columns as _interp, WitProgram};
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
            inputs.push(rng.gen::<u64>() & ((1u64 << 40) - 1));
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
}
