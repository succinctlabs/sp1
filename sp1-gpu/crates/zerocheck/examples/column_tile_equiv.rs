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
//! Equivalence test for the v2 ColumnTile kernel.
//!
//! Constructs a synthetic `LinearWeightedSum` DAG (every constraint is a
//! linear combination of column leaves with constant or public coefficients),
//! lowers it via `lower_column_tile`, runs both a CPU oracle and the GPU
//! kernel, and verifies the 3 per-eval-point partial sums match bitwise.

use rand::{rngs::StdRng, Rng, SeedableRng};
use slop_algebra::{AbstractExtensionField, AbstractField};
use sp1_gpu_air::ir::{
    analyze_constraints, chunk_dag, enumerate_lowerings, lower_column_tile, ChunkBudget,
    ColumnTileBytecode, ConstraintDag, ConstraintField, ConstraintRef, ConstraintShape, DagNode,
    Lowering, TraceSource, COEFF_KIND_CONST,
};
use sp1_gpu_air::{EF, F};
use sp1_gpu_cudart::sys::kernels::zerocheck_column_tile_kb_kernel;
use sp1_gpu_cudart::{args, run_sync_in_place, DeviceBuffer};

// LinearWeightedSum DAG with constants AND publics as coefficients:
//   c0: 3*l0 + 5*l1 + 7*l2          (constant coeffs)
//   c1: 11*l3 + 13*l4               (constant coeffs)
//   c2: pv0 * l0 + pv1 * l1         (public coeffs)
fn build_linear_dag() -> ConstraintDag {
    let mut nodes = vec![];
    // 0..5: column leaves
    for c in 0..5 {
        nodes.push(DagNode::InputLeaf { source: TraceSource::MainLocal, col: c });
    }
    // 5..10: constants (3, 5, 7, 11, 13)
    for k in [3u32, 5, 7, 11, 13] {
        nodes.push(DagNode::ConstF { value: F::from_canonical_u32(k) });
    }
    // 10..12: public values 0, 1
    nodes.push(DagNode::PublicValue { idx: 0 });
    nodes.push(DagNode::PublicValue { idx: 1 });

    // c0: 3*l0 + 5*l1 + 7*l2
    let m0 = nodes.len() as u32;
    nodes.push(DagNode::MulF { a: 5, b: 0 }); // 3 * l0
    let m1 = nodes.len() as u32;
    nodes.push(DagNode::MulF { a: 6, b: 1 }); // 5 * l1
    let s0 = nodes.len() as u32;
    nodes.push(DagNode::AddF { a: m0, b: m1 });
    let m2 = nodes.len() as u32;
    nodes.push(DagNode::MulF { a: 7, b: 2 }); // 7 * l2
    let c0_root = nodes.len() as u32;
    nodes.push(DagNode::AddF { a: s0, b: m2 });

    // c1: 11*l3 + 13*l4
    let m3 = nodes.len() as u32;
    nodes.push(DagNode::MulF { a: 8, b: 3 }); // 11 * l3
    let m4 = nodes.len() as u32;
    nodes.push(DagNode::MulF { a: 9, b: 4 }); // 13 * l4
    let c1_root = nodes.len() as u32;
    nodes.push(DagNode::AddF { a: m3, b: m4 });

    // c2: pv0 * l0 + pv1 * l1
    let m5 = nodes.len() as u32;
    nodes.push(DagNode::MulF { a: 10, b: 0 });
    let m6 = nodes.len() as u32;
    nodes.push(DagNode::MulF { a: 11, b: 1 });
    let c2_root = nodes.len() as u32;
    nodes.push(DagNode::AddF { a: m5, b: m6 });

    let constraints = vec![
        ConstraintRef { root: c0_root, alpha_index: 0, field: ConstraintField::Base },
        ConstraintRef { root: c1_root, alpha_index: 1, field: ConstraintField::Base },
        ConstraintRef { root: c2_root, alpha_index: 2, field: ConstraintField::Base },
    ];

    ConstraintDag { nodes, constraints, preprocessed_width: 0, main_width: 5 }
}

const N_COLS: usize = 5;
const N_PARTIAL_PER_BLOCK: usize = 3;

fn main() {
    let dag = build_linear_dag();
    let infos = analyze_constraints(&dag);

    // Sanity: every constraint should be LinearWeightedSum.
    for (i, info) in infos.iter().enumerate() {
        assert!(
            matches!(info.shape, ConstraintShape::LinearWeightedSum),
            "constraint {} not detected as LinearWeightedSum",
            i
        );
    }

    let chunks = chunk_dag(&infos, &ChunkBudget::recommended());
    assert_eq!(chunks.len(), 1, "should chunk into one linear chunk");
    let chunk = &chunks[0];
    assert!(matches!(chunk.shape, ConstraintShape::LinearWeightedSum));

    let lowerings = enumerate_lowerings(chunk, &infos, &dag);
    let plan = lowerings
        .iter()
        .find_map(|l| match l {
            Lowering::ColumnTile(p) => Some(p),
            _ => None,
        })
        .expect("ColumnTile plan should exist for a LinearWeightedSum chunk");
    let bc =
        lower_column_tile(chunk, &infos, &dag, plan).expect("lower_column_tile should succeed");

    println!(
        "column-tile bytecode: {} terms, {} leaves, {} consts, {} publics",
        bc.terms.len(),
        bc.leaves.len(),
        bc.consts.len(),
        bc.publics.len()
    );
    for (i, t) in bc.terms.iter().enumerate() {
        let kind = if t.coeff_kind == COEFF_KIND_CONST { "const" } else { "public" };
        println!(
            "  term {}: leaf_idx={} {}#{} alpha_idx={}",
            i, t.leaf_idx, kind, t.coeff_idx, t.alpha_idx
        );
    }

    // Run multiple scenarios to exercise grid bounds. n_rows == 2^rest_point_dim.
    let scenarios: &[(&str, usize, u32, u64)] =
        &[("single block, full row tile", 8, 3, 0xAA), ("multi block, aligned tail", 32, 5, 0xCC)];

    let mut all_ok = true;
    for &(label, n_rows, rest_point_dim, seed) in scenarios {
        let mut rng = StdRng::seed_from_u64(seed);
        let height = 2 * n_rows;
        let trace: Vec<F> = (0..N_COLS * height).map(|_| rand_f(&mut rng)).collect();
        let powers_of_alpha: Vec<EF> =
            (0..dag.constraints.len()).map(|_| rand_ef(&mut rng)).collect();
        let public_values: Vec<F> = (0..16).map(|_| rand_f(&mut rng)).collect();
        let partial_lagrange: Vec<EF> =
            (0..(1u32 << rest_point_dim)).map(|_| rand_ef(&mut rng)).collect();
        let powers_of_lambda: Vec<EF> = vec![rand_ef(&mut rng); 4];
        let chip_idx: u32 = 2;

        let host = host_oracle(
            &bc,
            &trace,
            height,
            &powers_of_alpha,
            &public_values,
            &partial_lagrange,
            &powers_of_lambda,
            chip_idx,
            rest_point_dim,
            n_rows,
        );
        let gpu = run_gpu(
            &bc,
            &trace,
            height,
            &powers_of_alpha,
            &public_values,
            &partial_lagrange,
            &powers_of_lambda,
            chip_idx,
            rest_point_dim,
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
        println!("\nv2 ColumnTile kernel matches host oracle bitwise across all scenarios");
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

fn host_oracle(
    bc: &ColumnTileBytecode,
    trace: &[F],
    height: usize,
    powers_of_alpha: &[EF],
    public_values: &[F],
    partial_lagrange: &[EF],
    powers_of_lambda: &[EF],
    chip_idx: u32,
    rest_point_dim: u32,
    n_rows: usize,
) -> [EF; 3] {
    let mut sum = [EF::zero(); 3];
    let eval_pts: [F; 3] =
        [F::from_canonical_u32(0), F::from_canonical_u32(2), F::from_canonical_u32(4)];
    let domain = 1u32 << rest_point_dim;
    let lambda = powers_of_lambda[chip_idx as usize];
    for row in 0..n_rows {
        // Each term in a column-tile chunk contributes one weighted value per
        // (row, eval). The kernel multiplies each term's contribution by
        // eq[row] · λ; the host mirrors that exactly per-term.
        let weight =
            if (row as u32) < domain { partial_lagrange[row] * lambda } else { EF::zero() };
        for t in &bc.terms {
            let leaf = bc.leaves[t.leaf_idx as usize];
            let off = (leaf.col as usize) * height + (row << 1);
            let z = trace[off];
            let o = trace[off + 1];
            let coeff = if t.coeff_kind == COEFF_KIND_CONST {
                bc.consts[t.coeff_idx as usize]
            } else {
                public_values[bc.publics[t.coeff_idx as usize] as usize]
            };
            let alpha = powers_of_alpha[t.alpha_idx as usize];
            for e in 0..3 {
                let v = z + eval_pts[e] * (o - z);
                let contribution = alpha * EF::from_base(coeff * v);
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
    powers_of_alpha: &[EF],
    public_values: &[F],
    partial_lagrange: &[EF],
    powers_of_lambda: &[EF],
    chip_idx: u32,
    rest_point_dim: u32,
    n_rows: usize,
) -> [EF; 3] {
    // 1D block; each thread = one (term, row) pair, computing all 3 eval points.
    const BLOCK_SIZE: u32 = 64;
    let total = (bc.terms.len() as u32) * (n_rows as u32);
    let grid_x = (total + BLOCK_SIZE - 1) / BLOCK_SIZE;
    let n_warps = BLOCK_SIZE / 32;
    let shmem_bytes = (n_warps as usize) * std::mem::size_of::<EF>();

    let result = run_sync_in_place(|scope| {
        let d_terms = DeviceBuffer::from_host_slice(&bc.terms, &scope).unwrap();
        let d_leaves = DeviceBuffer::from_host_slice(&bc.leaves, &scope).unwrap();
        let d_consts = DeviceBuffer::from_host_slice(&bc.consts, &scope).unwrap();
        let d_publics = DeviceBuffer::from_host_slice(&bc.publics, &scope).unwrap();
        // No COEFF_KIND_RUNTIME terms in this test; pass a 1-element dummy so
        // the kernel pointer is non-null.
        let d_runtime: DeviceBuffer<EF> =
            DeviceBuffer::from_host_slice(&[EF::zero()], &scope).unwrap();
        let d_trace = DeviceBuffer::from_host_slice(trace, &scope).unwrap();
        let d_public_values = DeviceBuffer::from_host_slice(public_values, &scope).unwrap();
        let d_powers = DeviceBuffer::from_host_slice(powers_of_alpha, &scope).unwrap();
        let d_partial_lagrange = DeviceBuffer::from_host_slice(partial_lagrange, &scope).unwrap();
        let d_powers_of_lambda = DeviceBuffer::from_host_slice(powers_of_lambda, &scope).unwrap();
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
