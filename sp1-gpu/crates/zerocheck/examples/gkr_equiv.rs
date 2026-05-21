#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::vec_init_then_push,
    clippy::useless_vec,
    clippy::manual_div_ceil,
    clippy::doc_lazy_continuation
)]
//! Equivalence test for GKR-correction chunks via ColumnTile.
//!
//! Uses `synthesize_gkr_chunk` to construct a column-tile bytecode whose
//! coefficients are `COEFF_KIND_RUNTIME` ext_t values supplied at launch
//! (the per-proof batching powers). Verifies the GPU kernel matches the
//! host oracle bitwise.

use rand::{rngs::StdRng, Rng, SeedableRng};
use slop_algebra::{AbstractExtensionField, AbstractField};
use sp1_gpu_air::ir::{synthesize_gkr_chunk, ColumnTileBytecode, COEFF_KIND_RUNTIME};
use sp1_gpu_air::{EF, F};
use sp1_gpu_cudart::sys::kernels::zerocheck_column_tile_kb_kernel;
use sp1_gpu_cudart::{args, run_sync_in_place, DeviceBuffer};

const N_PARTIAL_PER_BLOCK: usize = 3;

fn main() {
    // Synthesize a GKR-correction chunk: 5 main + 2 preprocessed columns.
    // Total 7 terms, all COEFF_KIND_RUNTIME, all alpha_idx=0.
    let main_width: u32 = 5;
    let prep_width: u32 = 2;
    let bc = synthesize_gkr_chunk(main_width, prep_width);
    println!(
        "synthesized GKR chunk: main={} prep={} → {} terms, {} leaves",
        main_width,
        prep_width,
        bc.terms.len(),
        bc.leaves.len()
    );
    // Sanity: every term should be COEFF_KIND_RUNTIME.
    for t in &bc.terms {
        assert_eq!(t.coeff_kind, COEFF_KIND_RUNTIME);
    }
    // Main first, then prep — matches v1's ordering.
    for (i, t) in bc.terms.iter().enumerate() {
        let leaf = bc.leaves[t.leaf_idx as usize];
        let kind = if leaf.source == 4 { "main" } else { "prep" };
        println!(
            "  term {}: {}#{}  runtime_coeff[{}]  alpha_idx={}",
            i, kind, leaf.col, t.coeff_idx, t.alpha_idx
        );
    }

    let scenarios: &[(&str, usize, u32, u64)] =
        &[("single block, small row tile", 8, 3, 0xA1), ("multi block, aligned tail", 64, 6, 0xC1)];

    let mut all_ok = true;
    for &(label, n_rows, rest_point_dim, seed) in scenarios {
        let mut rng = StdRng::seed_from_u64(seed);
        let n_cols_total = (main_width + prep_width) as usize;
        let height = 2 * n_rows;

        let trace: Vec<F> = (0..n_cols_total * height).map(|_| rand_f(&mut rng)).collect();
        let runtime_coeffs: Vec<EF> = (0..n_cols_total).map(|_| rand_ef(&mut rng)).collect();
        let powers_of_alpha: Vec<EF> = vec![rand_ef(&mut rng); 1];
        let partial_lagrange: Vec<EF> =
            (0..(1u32 << rest_point_dim)).map(|_| rand_ef(&mut rng)).collect();
        let powers_of_lambda: Vec<EF> = vec![rand_ef(&mut rng); 4];
        let chip_idx: u32 = 3;

        let host = host_oracle(
            &bc,
            &trace,
            height,
            &runtime_coeffs,
            &powers_of_alpha,
            &partial_lagrange,
            &powers_of_lambda,
            chip_idx,
            rest_point_dim,
            main_width,
            n_rows,
        );
        let gpu = run_gpu(
            &bc,
            &trace,
            height,
            &runtime_coeffs,
            &powers_of_alpha,
            &partial_lagrange,
            &powers_of_lambda,
            chip_idx,
            rest_point_dim,
            main_width,
            n_rows,
        );

        let ok = (0..N_PARTIAL_PER_BLOCK).all(|e| host[e] == gpu[e]);
        println!("[{}] n_rows={} : {}", label, n_rows, if ok { "match" } else { "MISMATCH" });
        if !ok {
            for e in 0..N_PARTIAL_PER_BLOCK {
                println!("  e{}: host={:?}  gpu={:?}", e, host[e], gpu[e]);
            }
            all_ok = false;
        }
    }
    if all_ok {
        println!("\nv2 GKR via ColumnTile (runtime coefficients) matches host oracle bitwise");
    } else {
        std::process::exit(1);
    }
}

fn rand_f(rng: &mut StdRng) -> F {
    F::from_wrapped_u32(rng.gen())
}

fn rand_ef(rng: &mut StdRng) -> EF {
    EF::from_base_slice(&[rand_f(rng), rand_f(rng), rand_f(rng), rand_f(rng)])
}

/// CPU port of the kernel logic for a runtime-coefficient chunk. Trace layout:
/// columns 0..main_width are "main" (source byte 4), preprocessed_ptr offsets
/// main_width * height ahead. Both share the same `trace` buffer.
fn host_oracle(
    bc: &ColumnTileBytecode,
    trace: &[F],
    height: usize,
    runtime_coeffs: &[EF],
    powers_of_alpha: &[EF],
    partial_lagrange: &[EF],
    powers_of_lambda: &[EF],
    chip_idx: u32,
    rest_point_dim: u32,
    main_width: u32,
    n_rows: usize,
) -> [EF; 3] {
    let mut sum = [EF::zero(); 3];
    let eval_pts: [F; 3] =
        [F::from_canonical_u32(0), F::from_canonical_u32(2), F::from_canonical_u32(4)];
    let main_ptr: usize = 0;
    let preprocessed_ptr: usize = (main_width as usize) * height;
    let domain = 1u32 << rest_point_dim;
    let lambda = powers_of_lambda[chip_idx as usize];
    for row in 0..n_rows {
        let weight =
            if (row as u32) < domain { partial_lagrange[row] * lambda } else { EF::zero() };
        for t in &bc.terms {
            let leaf = bc.leaves[t.leaf_idx as usize];
            let base = if leaf.source == 4 { main_ptr } else { preprocessed_ptr };
            let off = base + (leaf.col as usize) * height + (row << 1);
            let z = trace[off];
            let o = trace[off + 1];
            let diff = o - z;

            let coeff = runtime_coeffs[t.coeff_idx as usize];
            let alpha = powers_of_alpha[t.alpha_idx as usize];

            for e in 0..3 {
                let v = z + eval_pts[e] * diff;
                let contribution = alpha * (coeff * EF::from_base(v));
                sum[e] += contribution * weight;
            }
        }
    }
    sum
}

fn run_gpu(
    bc: &ColumnTileBytecode,
    trace: &[F],
    height: usize,
    runtime_coeffs: &[EF],
    powers_of_alpha: &[EF],
    partial_lagrange: &[EF],
    powers_of_lambda: &[EF],
    chip_idx: u32,
    rest_point_dim: u32,
    main_width: u32,
    n_rows: usize,
) -> [EF; 3] {
    const BLOCK_SIZE: u32 = 64;
    let total = (bc.terms.len() as u32) * (n_rows as u32);
    let grid_x = (total + BLOCK_SIZE - 1) / BLOCK_SIZE;
    let n_warps = BLOCK_SIZE / 32;
    let shmem_bytes = (n_warps as usize) * std::mem::size_of::<EF>();

    let result = run_sync_in_place(|scope| {
        let d_terms = DeviceBuffer::from_host_slice(&bc.terms, &scope).unwrap();
        let d_leaves = DeviceBuffer::from_host_slice(&bc.leaves, &scope).unwrap();
        // GKR chunk has no const-pool or public-pool entries; pass 1-elem dummies.
        let d_consts: DeviceBuffer<F> =
            DeviceBuffer::from_host_slice(&[F::zero()], &scope).unwrap();
        let d_publics: DeviceBuffer<u32> = DeviceBuffer::from_host_slice(&[0u32], &scope).unwrap();
        let d_runtime = DeviceBuffer::from_host_slice(runtime_coeffs, &scope).unwrap();
        let d_trace = DeviceBuffer::from_host_slice(trace, &scope).unwrap();
        let d_public_values = DeviceBuffer::from_host_slice(&vec![F::zero(); 4], &scope).unwrap();
        let d_powers = DeviceBuffer::from_host_slice(powers_of_alpha, &scope).unwrap();
        let d_partial_lagrange = DeviceBuffer::from_host_slice(partial_lagrange, &scope).unwrap();
        let d_powers_of_lambda = DeviceBuffer::from_host_slice(powers_of_lambda, &scope).unwrap();
        let mut d_partials: DeviceBuffer<EF> =
            DeviceBuffer::with_capacity_in(grid_x as usize * 3, scope.clone());
        unsafe {
            d_partials.assume_init();
        }

        let n_terms: u32 = bc.terms.len() as u32;
        let preprocessed_ptr: u64 = (main_width as u64) * (height as u64);
        let main_ptr: u64 = 0;
        let height_u: u32 = height as u32;
        let row_start: u32 = 0;
        let row_count: u32 = n_rows as u32;

        unsafe {
            let a = args!(
                d_terms.as_ptr(),
                n_terms,
                d_leaves.as_ptr(),
                d_consts.as_ptr(),
                d_publics.as_ptr(),
                d_runtime.as_ptr(),
                d_trace.as_ptr(),
                preprocessed_ptr,
                main_ptr,
                height_u,
                d_public_values.as_ptr(),
                d_powers.as_ptr(),
                d_partial_lagrange.as_ptr(),
                d_powers_of_lambda.as_ptr(),
                chip_idx,
                rest_point_dim,
                row_start,
                row_count,
                d_partials.as_mut_ptr()
            );
            scope
                .launch_kernel(
                    zerocheck_column_tile_kb_kernel(),
                    (grid_x, 1, 1),
                    (BLOCK_SIZE, 1, 1),
                    &a,
                    shmem_bytes,
                )
                .unwrap();
        }

        d_partials.to_host().unwrap().to_vec()
    })
    .unwrap();

    let mut out = [EF::zero(); 3];
    for (i, &p) in result.iter().enumerate() {
        out[i % 3] += p;
    }
    out
}
