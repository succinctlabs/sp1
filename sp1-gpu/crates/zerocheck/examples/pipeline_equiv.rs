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
//! End-to-end pipeline equivalence test.
//!
//! Drives one round's worth of v2 zerocheck for a synthetic chip:
//!   1. Build a `ConstraintDag` with constraints of both shapes (General +
//!      LinearWeightedSum), plus an injected GKR-correction chunk.
//!   2. Run the full pipeline: analyze → chunk → lowerings → bytecode.
//!   3. Launch the right kernel per chunk (Sequential or ColumnTile).
//!   4. Sum all partials across all chunks per eval point.
//!   5. Compute the same quantity host-side as ground truth.
//! Verify bitwise match.

use rand::{rngs::StdRng, Rng, SeedableRng};
use slop_algebra::{AbstractExtensionField, AbstractField};
use sp1_gpu_air::ir::{
    analyze_constraints, chunk_dag, enumerate_lowerings, lower_column_tile, lower_sequential,
    synthesize_gkr_chunk, ChunkBudget, ChunkBytecode, ColumnTileBytecode, ConstraintDag,
    ConstraintField, ConstraintRef, DagNode, Lowering, TraceSource, COEFF_KIND_CONST,
    COEFF_KIND_PUBLIC, COEFF_KIND_RUNTIME,
};
use sp1_gpu_air::{EF, F};
use sp1_gpu_cudart::sys::kernels::{
    zerocheck_column_tile_kb_kernel, zerocheck_sequential_kb_kernel,
};
use sp1_gpu_cudart::{args, run_sync_in_place, DeviceBuffer, TaskScope};

// Same DAG as v2_kernel_equiv: mix of LinearWeightedSum and General constraints.
fn build_chip_dag() -> ConstraintDag {
    let mut nodes = vec![];
    nodes.push(DagNode::InputLeaf { source: TraceSource::MainLocal, col: 0 }); // 0
    nodes.push(DagNode::InputLeaf { source: TraceSource::MainLocal, col: 1 }); // 1
    nodes.push(DagNode::InputLeaf { source: TraceSource::MainLocal, col: 2 }); // 2
    nodes.push(DagNode::InputLeaf { source: TraceSource::MainLocal, col: 3 }); // 3
    nodes.push(DagNode::InputLeaf { source: TraceSource::MainLocal, col: 4 }); // 4
    nodes.push(DagNode::ConstF { value: F::from_canonical_u32(5) }); // 5
    nodes.push(DagNode::ConstF { value: F::from_canonical_u32(7) }); // 6
    nodes.push(DagNode::AddF { a: 0, b: 1 }); // 7
    nodes.push(DagNode::MulF { a: 0, b: 2 }); // 8
    nodes.push(DagNode::SubF { a: 8, b: 5 }); // 9
    nodes.push(DagNode::AddF { a: 7, b: 2 }); // 10
    nodes.push(DagNode::MulF { a: 7, b: 3 }); // 11
    nodes.push(DagNode::NegF { a: 11 }); // 12
    nodes.push(DagNode::MulF { a: 4, b: 6 }); // 13
    nodes.push(DagNode::SubF { a: 13, b: 7 }); // 14

    let constraints = vec![
        ConstraintRef { root: 7, alpha_index: 0, field: ConstraintField::Base },
        ConstraintRef { root: 9, alpha_index: 1, field: ConstraintField::Base },
        ConstraintRef { root: 10, alpha_index: 2, field: ConstraintField::Base },
        ConstraintRef { root: 12, alpha_index: 3, field: ConstraintField::Base },
        ConstraintRef { root: 14, alpha_index: 4, field: ConstraintField::Base },
    ];
    ConstraintDag { nodes, constraints, preprocessed_width: 0, main_width: 5 }
}

const MAIN_WIDTH: u32 = 5;
const PREP_WIDTH: u32 = 0;
// NOTE: `synthesize_gkr_chunk` now emits `alpha_idx = 0` and flags the chunk
// `is_gkr_carrier`; the real launcher (`launch_chunk_into`) points
// `powers_of_alpha` at the `1` slot for such chunks. This standalone example
// still models the older "reserved slot" convention — its GKR equivalence
// check is stale and needs reworking to mirror the launcher.
const GKR_ALPHA_IDX: u32 = 5; // beyond the constraint alphas
const N_ALPHAS: usize = 6;

enum CompiledChunk {
    Sequential(ChunkBytecode),
    ColumnTile(ColumnTileBytecode),
}

fn main() {
    let dag = build_chip_dag();
    let infos = analyze_constraints(&dag);
    let chunks = chunk_dag(&infos, &ChunkBudget::recommended());

    // Compile every chunk to its appropriate bytecode.
    let mut compiled: Vec<CompiledChunk> = Vec::new();
    for chunk in &chunks {
        let lowerings = enumerate_lowerings(chunk, &infos, &dag);
        // Prefer ColumnTile when it applies; otherwise Sequential.
        let column_tile = lowerings.iter().find_map(|l| match l {
            Lowering::ColumnTile(p) => Some(p),
            _ => None,
        });
        if let Some(plan) = column_tile {
            if let Some(bc) = lower_column_tile(chunk, &infos, &dag, plan) {
                compiled.push(CompiledChunk::ColumnTile(bc));
                continue;
            }
        }
        let plan = lowerings
            .iter()
            .find_map(|l| match l {
                Lowering::Sequential(p) => Some(p),
                _ => None,
            })
            .unwrap();
        let bc = lower_sequential(chunk, &infos, &dag, plan);
        compiled.push(CompiledChunk::Sequential(bc));
    }
    // Append the synthesized GKR chunk.
    let gkr_bc = synthesize_gkr_chunk(MAIN_WIDTH, PREP_WIDTH);
    compiled.push(CompiledChunk::ColumnTile(gkr_bc));

    println!("compiled {} chunks:", compiled.len());
    for (i, c) in compiled.iter().enumerate() {
        match c {
            CompiledChunk::Sequential(bc) => println!(
                "  [{}] Sequential: {} instrs, {} asserts, max_reg={}",
                i,
                bc.instrs.len(),
                bc.asserts.len(),
                bc.max_reg
            ),
            CompiledChunk::ColumnTile(bc) => println!(
                "  [{}] ColumnTile: {} terms ({} consts/publics, {} runtime)",
                i,
                bc.terms.len(),
                bc.terms.iter().filter(|t| t.coeff_kind != COEFF_KIND_RUNTIME).count(),
                bc.terms.iter().filter(|t| t.coeff_kind == COEFF_KIND_RUNTIME).count(),
            ),
        }
    }

    let scenarios: &[(&str, usize, u32, u64)] =
        &[("medium chip, n_rows=32", 32, 5, 0xE0), ("larger chip, n_rows=128", 128, 7, 0xE1)];

    let mut all_ok = true;
    for &(label, n_rows, rest_point_dim, seed) in scenarios {
        let mut rng = StdRng::seed_from_u64(seed);
        let height = 2 * n_rows;
        let trace: Vec<F> = (0..(MAIN_WIDTH as usize) * height).map(|_| rand_f(&mut rng)).collect();
        let powers_of_alpha: Vec<EF> = (0..N_ALPHAS).map(|_| rand_ef(&mut rng)).collect();
        // Reserve a slot at GKR_ALPHA_IDX = 5, set it to one() so GKR is
        // additive (matches v1 semantics).
        let mut powers_of_alpha = powers_of_alpha;
        powers_of_alpha[GKR_ALPHA_IDX as usize] = EF::one();
        let partial_lagrange: Vec<EF> =
            (0..(1u32 << rest_point_dim)).map(|_| rand_ef(&mut rng)).collect();
        let powers_of_lambda: Vec<EF> = vec![rand_ef(&mut rng); 4];
        let runtime_coeffs: Vec<EF> =
            (0..(MAIN_WIDTH + PREP_WIDTH) as usize).map(|_| rand_ef(&mut rng)).collect();
        let public_values: Vec<F> = vec![F::zero(); 16];
        let chip_idx: u32 = 2;

        let host = full_host_oracle(
            &dag,
            &trace,
            height,
            &powers_of_alpha,
            &public_values,
            &partial_lagrange,
            &powers_of_lambda,
            chip_idx,
            rest_point_dim,
            n_rows,
            &runtime_coeffs,
            MAIN_WIDTH,
        );
        let gpu = full_pipeline_gpu(
            &compiled,
            &trace,
            height,
            &powers_of_alpha,
            &public_values,
            &partial_lagrange,
            &powers_of_lambda,
            chip_idx,
            rest_point_dim,
            n_rows,
            &runtime_coeffs,
            MAIN_WIDTH,
        );

        let ok = (0..3).all(|e| host[e] == gpu[e]);
        println!("[{}] dim={} : {}", label, rest_point_dim, if ok { "match" } else { "MISMATCH" });
        if !ok {
            for e in 0..3 {
                println!("  e{}: host={:?}  gpu={:?}", e, host[e], gpu[e]);
            }
            all_ok = false;
        }
    }

    if all_ok {
        println!("\nv2 full pipeline matches host oracle bitwise across all scenarios");
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

/// Full host oracle: evaluates the entire DAG plus the synthesized GKR
/// correction, weighted by eq · λ, summed across rows. The kernel pipeline
/// should produce the same value.
fn full_host_oracle(
    dag: &ConstraintDag,
    trace: &[F],
    height: usize,
    powers_of_alpha: &[EF],
    _public_values: &[F],
    partial_lagrange: &[EF],
    powers_of_lambda: &[EF],
    chip_idx: u32,
    rest_point_dim: u32,
    n_rows: usize,
    runtime_coeffs: &[EF],
    main_width: u32,
) -> [EF; 3] {
    let mut sum = [EF::zero(); 3];
    let eval_pts: [F; 3] =
        [F::from_canonical_u32(0), F::from_canonical_u32(2), F::from_canonical_u32(4)];
    let domain = 1u32 << rest_point_dim;
    let lambda = powers_of_lambda[chip_idx as usize];
    let gkr_alpha = powers_of_alpha[GKR_ALPHA_IDX as usize];

    for row in 0..n_rows {
        // Evaluate the DAG at this row for each eval point.
        let mut vals: Vec<[F; 3]> = vec![[F::zero(); 3]; dag.nodes.len()];
        for (i, node) in dag.nodes.iter().enumerate() {
            match *node {
                DagNode::InputLeaf { source, col } => {
                    assert!(matches!(source, TraceSource::MainLocal));
                    let off = (col as usize) * height + (row << 1);
                    let z = trace[off];
                    let o = trace[off + 1];
                    let diff = o - z;
                    vals[i][0] = z + eval_pts[0] * diff;
                    vals[i][1] = z + eval_pts[1] * diff;
                    vals[i][2] = z + eval_pts[2] * diff;
                }
                DagNode::ConstF { value } => vals[i] = [value, value, value],
                DagNode::AddF { a, b } => {
                    for e in 0..3 {
                        vals[i][e] = vals[a as usize][e] + vals[b as usize][e];
                    }
                }
                DagNode::SubF { a, b } => {
                    for e in 0..3 {
                        vals[i][e] = vals[a as usize][e] - vals[b as usize][e];
                    }
                }
                DagNode::MulF { a, b } => {
                    for e in 0..3 {
                        vals[i][e] = vals[a as usize][e] * vals[b as usize][e];
                    }
                }
                DagNode::NegF { a } => {
                    for e in 0..3 {
                        vals[i][e] = -vals[a as usize][e];
                    }
                }
                _ => panic!("oracle: unhandled node {:?}", node),
            }
        }

        // Per-row weighted constraint sum.
        let weight =
            if (row as u32) < domain { partial_lagrange[row] * lambda } else { EF::zero() };

        // Constraint contributions.
        let mut row_acc = [EF::zero(); 3];
        for c in &dag.constraints {
            let alpha = powers_of_alpha[c.alpha_index as usize];
            for e in 0..3 {
                row_acc[e] += alpha * EF::from_base(vals[c.root as usize][e]);
            }
        }

        // GKR contribution: Σ_i runtime_coeffs[i] · col_i(row, eval) · α_gkr.
        // Same column ordering as `synthesize_gkr_chunk`: main first, then prep.
        for col in 0..main_width {
            let off = (col as usize) * height + (row << 1);
            let z = trace[off];
            let o = trace[off + 1];
            let diff = o - z;
            let coeff = runtime_coeffs[col as usize];
            for e in 0..3 {
                let v = z + eval_pts[e] * diff;
                row_acc[e] += gkr_alpha * (coeff * EF::from_base(v));
            }
        }
        // (No preprocessed columns in this test.)

        for e in 0..3 {
            sum[e] += row_acc[e] * weight;
        }
    }
    sum
}

fn full_pipeline_gpu(
    compiled: &[CompiledChunk],
    trace: &[F],
    height: usize,
    powers_of_alpha: &[EF],
    public_values: &[F],
    partial_lagrange: &[EF],
    powers_of_lambda: &[EF],
    chip_idx: u32,
    rest_point_dim: u32,
    n_rows: usize,
    runtime_coeffs: &[EF],
    _main_width: u32,
) -> [EF; 3] {
    run_sync_in_place(|scope| {
        // Upload all the per-round buffers once.
        let d_trace = DeviceBuffer::from_host_slice(trace, &scope).unwrap();
        let d_public_values = DeviceBuffer::from_host_slice(public_values, &scope).unwrap();
        let d_powers = DeviceBuffer::from_host_slice(powers_of_alpha, &scope).unwrap();
        let d_partial_lagrange = DeviceBuffer::from_host_slice(partial_lagrange, &scope).unwrap();
        let d_powers_of_lambda = DeviceBuffer::from_host_slice(powers_of_lambda, &scope).unwrap();
        let d_runtime_coeffs = DeviceBuffer::from_host_slice(runtime_coeffs, &scope).unwrap();

        let mut total = [EF::zero(); 3];
        for chunk in compiled {
            let partials = match chunk {
                CompiledChunk::Sequential(bc) => launch_sequential(
                    &scope,
                    bc,
                    &d_trace,
                    &d_public_values,
                    &d_powers,
                    &d_partial_lagrange,
                    &d_powers_of_lambda,
                    chip_idx,
                    rest_point_dim,
                    height,
                    n_rows,
                ),
                CompiledChunk::ColumnTile(bc) => launch_column_tile(
                    &scope,
                    bc,
                    &d_trace,
                    &d_public_values,
                    &d_powers,
                    &d_partial_lagrange,
                    &d_powers_of_lambda,
                    &d_runtime_coeffs,
                    chip_idx,
                    rest_point_dim,
                    height,
                    n_rows,
                ),
            };
            for (i, &p) in partials.iter().enumerate() {
                total[i % 3] += p;
            }
        }
        total
    })
    .unwrap()
}

fn launch_sequential(
    scope: &TaskScope,
    bc: &ChunkBytecode,
    d_trace: &DeviceBuffer<F>,
    d_public_values: &DeviceBuffer<F>,
    d_powers: &DeviceBuffer<EF>,
    d_partial_lagrange: &DeviceBuffer<EF>,
    d_powers_of_lambda: &DeviceBuffer<EF>,
    chip_idx: u32,
    rest_point_dim: u32,
    height: usize,
    n_rows: usize,
) -> Vec<EF> {
    let d_instrs = DeviceBuffer::from_host_slice(&bc.instrs, scope).unwrap();
    let d_leaves = DeviceBuffer::from_host_slice(&bc.leaves, scope).unwrap();
    let d_consts = DeviceBuffer::from_host_slice(&bc.consts, scope).unwrap();
    let d_publics = DeviceBuffer::from_host_slice(&bc.publics, scope).unwrap();
    let assert_regs: Vec<u16> = bc.asserts.iter().map(|&(r, _)| r).collect();
    let assert_alphas: Vec<u32> = bc.asserts.iter().map(|&(_, a)| a).collect();
    let d_assert_regs = DeviceBuffer::from_host_slice(&assert_regs, scope).unwrap();
    let d_assert_alphas = DeviceBuffer::from_host_slice(&assert_alphas, scope).unwrap();

    let block_size: u32 = 32;
    let n_blocks: u32 = (n_rows as u32).div_ceil(block_size);
    let shmem_bytes = (block_size as usize / 32) * std::mem::size_of::<EF>();
    let mut d_partials: DeviceBuffer<EF> =
        DeviceBuffer::with_capacity_in(n_blocks as usize * 3, scope.clone());
    unsafe {
        d_partials.assume_init();
    }

    let n_instrs: u32 = bc.instrs.len() as u32;
    let n_asserts: u32 = bc.asserts.len() as u32;
    let preprocessed_ptr: u64 = 0;
    let main_ptr: u64 = 0;
    let height_u: u32 = height as u32;
    let row_start: u32 = 0;
    let row_count: u32 = n_rows as u32;

    unsafe {
        let a = args!(
            d_instrs.as_ptr(),
            n_instrs,
            d_leaves.as_ptr(),
            d_consts.as_ptr(),
            d_publics.as_ptr(),
            d_assert_regs.as_ptr(),
            d_assert_alphas.as_ptr(),
            n_asserts,
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
                zerocheck_sequential_kb_kernel(),
                (n_blocks, 1, 1),
                (block_size, 1, 1),
                &a,
                shmem_bytes,
            )
            .unwrap();
    }
    d_partials.to_host().unwrap().to_vec()
}

fn launch_column_tile(
    scope: &TaskScope,
    bc: &ColumnTileBytecode,
    d_trace: &DeviceBuffer<F>,
    d_public_values: &DeviceBuffer<F>,
    d_powers: &DeviceBuffer<EF>,
    d_partial_lagrange: &DeviceBuffer<EF>,
    d_powers_of_lambda: &DeviceBuffer<EF>,
    d_runtime_coeffs: &DeviceBuffer<EF>,
    chip_idx: u32,
    rest_point_dim: u32,
    height: usize,
    n_rows: usize,
) -> Vec<EF> {
    let d_terms = DeviceBuffer::from_host_slice(&bc.terms, scope).unwrap();
    let d_leaves = DeviceBuffer::from_host_slice(&bc.leaves, scope).unwrap();
    // Empty const/public pools can't be zero-length (gives null ptr); pad with 1.
    let consts = if bc.consts.is_empty() { vec![F::zero()] } else { bc.consts.clone() };
    let publics = if bc.publics.is_empty() { vec![0u32] } else { bc.publics.clone() };
    let d_consts = DeviceBuffer::from_host_slice(&consts, scope).unwrap();
    let d_publics = DeviceBuffer::from_host_slice(&publics, scope).unwrap();

    const BLOCK_SIZE: u32 = 64;
    let total = (bc.terms.len() as u32) * (n_rows as u32);
    let grid_x = total.div_ceil(BLOCK_SIZE);
    let n_warps = BLOCK_SIZE / 32;
    let shmem_bytes = (n_warps as usize) * std::mem::size_of::<EF>();
    let mut d_partials: DeviceBuffer<EF> =
        DeviceBuffer::with_capacity_in(grid_x as usize * 3, scope.clone());
    unsafe {
        d_partials.assume_init();
    }

    let n_terms: u32 = bc.terms.len() as u32;
    let preprocessed_ptr: u64 = 0;
    let main_ptr: u64 = 0;
    let height_u: u32 = height as u32;
    let row_start: u32 = 0;
    let row_count: u32 = n_rows as u32;

    // Sanity check: kinds present.
    let _has_const = bc.terms.iter().any(|t| t.coeff_kind == COEFF_KIND_CONST);
    let _has_pub = bc.terms.iter().any(|t| t.coeff_kind == COEFF_KIND_PUBLIC);

    unsafe {
        let a = args!(
            d_terms.as_ptr(),
            n_terms,
            d_leaves.as_ptr(),
            d_consts.as_ptr(),
            d_publics.as_ptr(),
            d_runtime_coeffs.as_ptr(),
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
}
