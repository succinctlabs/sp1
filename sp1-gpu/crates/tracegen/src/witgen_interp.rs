//! GPU validation of the generic witgen interpreter kernel: record
//! `AddrAddOperation::witgen` once, run the op-DAG on the device (one thread per
//! row), and assert the columns match the CPU `interpret_c_columns` reference.
//! Validates the CUDA kernel in isolation — no full e2e prove.

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use slop_algebra::AbstractField;
    use slop_alloc::Buffer;
    use sp1_core_machine::air::{
        columns_as_wires, interpret_c_columns, RecordingWitnessBuilder, WireId,
    };
    use sp1_core_machine::operations::AddrAddOperation;
    use sp1_gpu_cudart::{args, DeviceBuffer, TaskScope, WitgenInterpKernel};

    use crate::F;

    #[tokio::test]
    async fn witgen_interp_addr_add_columns() {
        sp1_gpu_cudart::spawn(move |scope: TaskScope| async move {
            // Record the gadget once (shape is row-independent).
            let mut rec = RecordingWitnessBuilder::new(2);
            let mut cols_w = AddrAddOperation::<WireId>::default();
            AddrAddOperation::<WireId>::witgen(
                &mut rec,
                &mut cols_w,
                RecordingWitnessBuilder::input(0),
                RecordingWitnessBuilder::input(1),
            );
            let program = rec.finish();
            let ops_c = program.to_c();
            let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
            let n_cols = col_wires.len();
            let num_inputs = program.num_inputs;

            // Random per-row inputs with a + b < 2^48 (the gadget's valid range).
            let n_rows = 1usize << 12;
            let mut rng = StdRng::seed_from_u64(7);
            let mut inputs: Vec<u64> = Vec::with_capacity(n_rows * 2);
            for _ in 0..n_rows {
                inputs.push(rng.gen::<u64>() & ((1u64 << 40) - 1));
                inputs.push(rng.gen::<u64>() & ((1u64 << 40) - 1));
            }

            // Upload op-DAG, column-wire map, inputs; allocate a flat output buffer.
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
                // T* trace, uintptr height, WitOpC* ops, uintptr n_ops,
                // u32* col_wires, uintptr n_cols, u32 num_inputs, u64* inputs, uintptr n_rows
                let args = args!(
                    out.as_mut_ptr(),
                    n_rows,
                    ops_dev.as_ptr(),
                    ops_c.len(),
                    col_dev.as_ptr(),
                    n_cols,
                    num_inputs,
                    in_dev.as_ptr(),
                    n_rows
                );
                scope
                    .launch_kernel(TaskScope::witgen_interp_kernel(), grid, BLOCK, &args, 0)
                    .unwrap();
            }
            scope.synchronize_blocking().unwrap();

            // Compare every row's columns against the CPU reference (column-major).
            let got: Vec<F> = out.to_host().unwrap();
            for r in 0..n_rows {
                let cpu =
                    interpret_c_columns::<F>(&ops_c, num_inputs, &inputs[r * 2..r * 2 + 2], &col_wires);
                for c in 0..n_cols {
                    assert_eq!(got[c * n_rows + r], cpu[c], "mismatch at row {r}, col {c}");
                }
            }
        })
        .await
        .unwrap();
    }
}
