//! GPU batch sparse merkle tree update.

use std::time::{Duration, Instant};

use sp1_gpu_cudart::{
    args,
    sys::merkle_tree::{
        copy_digest8_merkle_tree_kernel, count_histogram_merkle_tree_kernel,
        prev_compress_merkle_tree_kernel, prev_leader_flags_merkle_tree_kernel,
        scan_reset_merkle_tree_kernel, scan_u32_merkle_tree_kernel,
    },
    DeviceBuffer, TaskScope,
};
use sp1_primitives::SP1Field;

use slop_merkle_tree::batch_update::{
    ancestor_levels, default_hashes, make_compressor, BatchMerkleProof, Digest, Tag, Update,
};

use sp1_gpu_cudart::sys::merkle_tree::{
    cur_compress_merkle_tree_kernel, emit_rows_merkle_tree_kernel,
};

const DIGEST_WIDTH: usize = 8;
const BLOCK: usize = 256;
/// The chained scan processes `2 * blockDim` elements per block; `scan.cuh` fixes
/// `SECTION_SIZE = 512`, so the scan must launch with `blockDim = 256`.
const SCAN_BLOCK: usize = 256;
const SCAN_SECTION: usize = 512;
const HIST_BINS: usize = 32;

/// Prev sparse tree resident on the device. Leaves (level `height`) live in their own
/// buffers; internal levels `0..height` are packed into one pool, level `h` at digest
/// offset `offset[h]`. `count[h]` is the number of nodes at height `h`.
pub struct GpuPrevTree {
    pub leaf_idx: DeviceBuffer<u32>,
    pub leaf_val: DeviceBuffer<SP1Field>,
    pub pool_idx: DeviceBuffer<u32>,
    pub pool_val: DeviceBuffer<SP1Field>,
    pub count: Vec<usize>,
    pub offset: Vec<usize>,
    pub defaults_dev: DeviceBuffer<SP1Field>,
    pub height: usize,
}

impl GpuPrevTree {
    /// Const pointer to the sorted index array at height `h`.
    pub fn idx_ptr(&self, h: usize) -> *const u32 {
        if h == self.height {
            self.leaf_idx.as_ptr()
        } else {
            unsafe { self.pool_idx.as_ptr().add(self.offset[h]) }
        }
    }
    /// Const pointer to the digest array at height `h`.
    pub fn val_ptr(&self, h: usize) -> *const SP1Field {
        if h == self.height {
            self.leaf_val.as_ptr()
        } else {
            unsafe { self.pool_val.as_ptr().add(self.offset[h] * DIGEST_WIDTH) }
        }
    }
}

/// Timings for the prev build.
#[derive(Clone, Copy, Debug, Default)]
pub struct PrevBuildTimings {
    pub host_prep: Duration,
    pub h2d: Duration,
    pub count_pass: Duration,
    pub compute: Duration,
}

/// Build the prev sparse tree entirely on the GPU.
pub fn gpu_build_prev(
    scope: &TaskScope,
    default_leaf: Digest,
    leaf_idx: &[u32],
    leaf_val: &[SP1Field],
    height: usize,
) -> (GpuPrevTree, Digest, PrevBuildTimings) {
    assert!(height >= 1, "height must be >= 1");
    assert_eq!(leaf_val.len(), leaf_idx.len() * DIGEST_WIDTH, "leaf_val must be 8 per leaf");
    let h = height;
    let n = leaf_idx.len();

    // --- Host prep: just the default-subtree digests. No structure, no marshalling. ---
    let t_prep = Instant::now();
    let c = make_compressor();
    let defaults = default_hashes(&c, default_leaf, h);
    let defaults_flat: Vec<SP1Field> = defaults.iter().flat_map(|d| d.iter().copied()).collect();
    let host_prep = t_prep.elapsed();

    // --- H2D: leaves (level H), defaults, histogram + scan scratch. ---
    let t_h2d = Instant::now();
    let defaults_dev = DeviceBuffer::from_host_slice(&defaults_flat, scope).unwrap();
    let leaf_idx_dev = if n > 0 {
        DeviceBuffer::from_host_slice(leaf_idx, scope).unwrap()
    } else {
        DeviceBuffer::with_capacity_in(1, scope.clone())
    };
    let leaf_val_dev = if n > 0 {
        DeviceBuffer::from_host_slice(leaf_val, scope).unwrap()
    } else {
        DeviceBuffer::with_capacity_in(1, scope.clone())
    };
    let mut hist_dev = DeviceBuffer::from_host_slice(&[0u32; HIST_BINS], scope).unwrap();

    let cap = n.max(1);
    let max_blocks = n.div_ceil(SCAN_SECTION).max(1);
    let mut flags = DeviceBuffer::<u32>::with_capacity_in(cap, scope.clone());
    let mut incl = DeviceBuffer::<u32>::with_capacity_in(cap, scope.clone());
    let mut scan_values = DeviceBuffer::<u32>::with_capacity_in(max_blocks + 1, scope.clone());
    let mut block_counter = DeviceBuffer::<u32>::with_capacity_in(1, scope.clone());
    let mut block_flags = DeviceBuffer::<u32>::with_capacity_in(max_blocks + 1, scope.clone());
    unsafe {
        flags.set_len(cap);
        incl.set_len(cap);
        scan_values.set_len(max_blocks + 1);
        block_counter.set_len(1);
        block_flags.set_len(max_blocks + 1);
    }
    scope.synchronize_blocking().unwrap();
    let h2d = t_h2d.elapsed();

    // --- Stage A: histogram over leaf pairs -> per-level counts (one readback). ---
    let t_count = Instant::now();
    let hist = {
        if n > 0 {
            let arr = leaf_idx_dev.as_ptr();
            let nn = n as u32;
            let out = hist_dev.as_mut_ptr();
            let grid = n.div_ceil(BLOCK);
            let kern = unsafe { count_histogram_merkle_tree_kernel() };
            let a = args!(arr, nn, out);
            unsafe { scope.launch_kernel(kern, grid, BLOCK, &a, 0).unwrap() };
        }
        hist_dev.to_host().unwrap()
    };
    let count_pass = t_count.elapsed();

    // count[h] = 1 + Σ_{b ≥ H-h} hist[b]  (count[H] = n); 0 everywhere if no leaves.
    let mut count = vec![0usize; h + 1];
    if n > 0 {
        count[h] = n;
        for lvl in 0..h {
            let s: usize = hist[(h - lvl)..HIST_BINS].iter().map(|&x| x as usize).sum();
            count[lvl] = 1 + s;
        }
    }

    // Pool layout for internal levels: h = H-1 (offset 0), H-2, ..., 0.
    let mut offset = vec![0usize; h]; // offset[h] only meaningful for h < height
    let mut total_internal = 0usize;
    if h >= 1 {
        for lvl in (0..h).rev() {
            offset[lvl] = total_internal;
            total_internal += count[lvl];
        }
    }
    let mut pool_idx = DeviceBuffer::<u32>::with_capacity_in(total_internal.max(1), scope.clone());
    let mut pool_val = DeviceBuffer::<SP1Field>::with_capacity_in(
        (total_internal * DIGEST_WIDTH).max(1),
        scope.clone(),
    );
    unsafe {
        pool_idx.set_len(total_internal);
        pool_val.set_len(total_internal * DIGEST_WIDTH);
    }

    // --- Stage B: build level by level, no per-level sync. ---
    let pool_idx_base = pool_idx.as_mut_ptr();
    let pool_val_base = pool_val.as_mut_ptr();
    let leaf_idx_p = leaf_idx_dev.as_ptr();
    let leaf_val_p = leaf_val_dev.as_ptr();

    let t_comp = Instant::now();
    for lvl in (0..h).rev() {
        let n_ch = count[lvl + 1];
        if n_ch == 0 {
            continue;
        }
        // child arrays at level lvl+1
        let (cidx, cval) = if lvl + 1 == h {
            (leaf_idx_p, leaf_val_p)
        } else {
            (unsafe { pool_idx_base.add(offset[lvl + 1]) } as *const u32, unsafe {
                pool_val_base.add(offset[lvl + 1] * DIGEST_WIDTH)
            }
                as *const SP1Field)
        };
        let flags_ptr = flags.as_mut_ptr();
        let incl_ptr = incl.as_mut_ptr();

        // 1. leader flags
        {
            let nn = n_ch as u32;
            let grid = n_ch.div_ceil(BLOCK);
            let kern = unsafe { prev_leader_flags_merkle_tree_kernel() };
            let a = args!(cidx, nn, flags_ptr);
            unsafe { scope.launch_kernel(kern, grid, BLOCK, &a, 0).unwrap() };
        }
        // 2. reset scratch + inclusive scan
        let num_blocks = n_ch.div_ceil(SCAN_SECTION);
        {
            let sv = scan_values.as_mut_ptr();
            let bc = block_counter.as_mut_ptr();
            let bf = block_flags.as_mut_ptr();
            let nb = num_blocks as u32;
            let grid = (num_blocks + 1).div_ceil(BLOCK);
            let kern = unsafe { scan_reset_merkle_tree_kernel() };
            let a = args!(sv, bc, bf, nb);
            unsafe { scope.launch_kernel(kern, grid, BLOCK, &a, 0).unwrap() };
        }
        {
            let din = flags.as_ptr();
            let nsz = n_ch;
            let sv = scan_values.as_mut_ptr();
            let bc = block_counter.as_mut_ptr();
            let bf = block_flags.as_mut_ptr();
            let kern = unsafe { scan_u32_merkle_tree_kernel() };
            let a = args!(incl_ptr, din, nsz, sv, bc, bf);
            unsafe { scope.launch_kernel(kern, num_blocks, SCAN_BLOCK, &a, 0).unwrap() };
        }
        // 3. segmented compress into pool[offset[lvl]]
        {
            let nn = n_ch as u32;
            let default_child = unsafe { defaults_dev.as_ptr().add((lvl + 1) * DIGEST_WIDTH) };
            let flags_c = flags.as_ptr();
            let incl_c = incl.as_ptr();
            let pidx = unsafe { pool_idx_base.add(offset[lvl]) };
            let pval = unsafe { pool_val_base.add(offset[lvl] * DIGEST_WIDTH) };
            let grid = n_ch.div_ceil(BLOCK);
            let kern = unsafe { prev_compress_merkle_tree_kernel() };
            let a = args!(cidx, cval, nn, incl_c, flags_c, default_child, pidx, pval);
            unsafe { scope.launch_kernel(kern, grid, BLOCK, &a, 0).unwrap() };
        }
    }
    scope.synchronize_blocking().unwrap();
    let compute = t_comp.elapsed();

    // Root: the single level-0 node, or default[0] for an empty tree.
    let prev_root = if count[0] >= 1 {
        let mut root_dev = DeviceBuffer::<SP1Field>::with_capacity_in(DIGEST_WIDTH, scope.clone());
        unsafe { root_dev.set_len(DIGEST_WIDTH) };
        let src = unsafe { pool_val_base.add(offset[0] * DIGEST_WIDTH) } as *const SP1Field;
        let dst = root_dev.as_mut_ptr();
        let kern = unsafe { copy_digest8_merkle_tree_kernel() };
        let a = args!(src, dst);
        unsafe { scope.launch_kernel(kern, 1usize, DIGEST_WIDTH, &a, 0).unwrap() };
        let v = root_dev.to_host().unwrap();
        core::array::from_fn(|k| v[k])
    } else {
        defaults[0]
    };

    let tree = GpuPrevTree {
        leaf_idx: leaf_idx_dev,
        leaf_val: leaf_val_dev,
        pool_idx,
        pool_val,
        count,
        offset,
        defaults_dev,
        height: h,
    };
    (tree, prev_root, PrevBuildTimings { host_prep, h2d, count_pass, compute })
}

/// Timings for the full pipeline.
#[derive(Clone, Copy, Debug, Default)]
pub struct GpuTimings {
    pub prev: PrevBuildTimings,
    pub active_host: Duration,
    pub stage_c_h2d: Duration,
    pub cur_build: Duration,
    pub emit: Duration,
    pub d2h: Duration,
}

/// Map a column of GPU tag codes (Vec<u8>) into `Vec<Tag>`.
#[inline]
fn tags_from_codes(codes: Vec<u8>) -> Vec<Tag> {
    codes.into_iter().map(Tag::from_code).collect()
}

/// Full GPU batch update: GPU prev build + host active structure (search-free
/// dedup) + GPU current build + GPU tagged emit. Returns the batch Merkle proof in
/// column form ([`BatchMerkleProof`], byte-identical to the CPU reference) and timings.
pub fn gpu_batch_update(
    scope: &TaskScope,
    default_leaf: Digest,
    leaf_idx: &[u32],
    leaf_val: &[SP1Field],
    updates: &[Update],
    height: usize,
) -> (BatchMerkleProof, GpuTimings) {
    let h = height;
    let (tree, prev_root, prev_t) = gpu_build_prev(scope, default_leaf, leaf_idx, leaf_val, h);

    // --- Active structure on the host ---
    let t_active = Instant::now();
    let update_idxs: Vec<u64> = updates.iter().map(|u| u.idx).collect();
    let active = ancestor_levels(&update_idxs, h, true); // active[height] = update idxs
    let active_count: Vec<usize> = active.iter().map(|v| v.len()).collect();

    // Active pool layout: levels height, height-1, ..., 0.
    let mut act_offset = vec![0usize; h + 1];
    let mut cursor = 0usize;
    for lvl in (0..=h).rev() {
        act_offset[lvl] = cursor;
        cursor += active_count[lvl];
    }
    let total_act = cursor;

    // Concatenated active indices in pool order, and emit row offsets.
    let mut act_idx_host = Vec::with_capacity(total_act);
    for lvl in (0..=h).rev() {
        act_idx_host.extend(active[lvl].iter().map(|&i| i as u32));
    }
    // prefix_internal[h] = number of active internal nodes in levels < h (levels 0..H-1).
    let mut prefix_internal = vec![0usize; h];
    let mut acc = 0usize;
    for lvl in 0..h {
        prefix_internal[lvl] = acc;
        acc += active_count[lvl];
    }
    let n_rows = 2 * acc;
    let active_host = t_active.elapsed();

    // --- Stage C H2D: active indices + new leaf values; allocate cur pool + outputs. ---
    let t_c_h2d = Instant::now();
    let act_idx_dev = if total_act > 0 {
        DeviceBuffer::from_host_slice(&act_idx_host, scope).unwrap()
    } else {
        DeviceBuffer::with_capacity_in(1, scope.clone())
    };
    let mut cur_pool = DeviceBuffer::<SP1Field>::with_capacity_in(
        (total_act * DIGEST_WIDTH).max(1),
        scope.clone(),
    );
    // level-H current values = new leaves (parallel to update order = active[height]).
    let new_leaves_flat: Vec<SP1Field> = updates.iter().flat_map(|u| u.new_leaf).collect();
    if !new_leaves_flat.is_empty() {
        unsafe { cur_pool.extend_from_host_slice(&new_leaves_flat).unwrap() };
    }
    unsafe { cur_pool.set_len(total_act * DIGEST_WIDTH) };

    // Output trace buffers.
    let mut out_tlr = DeviceBuffer::<SP1Field>::with_capacity_in(
        (n_rows * 3 * DIGEST_WIDTH).max(1),
        scope.clone(),
    );
    let mut out_height = DeviceBuffer::<u32>::with_capacity_in(n_rows.max(1), scope.clone());
    let mut out_idx = DeviceBuffer::<u32>::with_capacity_in(n_rows.max(1), scope.clone());
    let mut out_tag1 = DeviceBuffer::<u8>::with_capacity_in(n_rows.max(1), scope.clone());
    let mut out_tag2 = DeviceBuffer::<u8>::with_capacity_in(n_rows.max(1), scope.clone());
    let mut out_tag3 = DeviceBuffer::<u8>::with_capacity_in(n_rows.max(1), scope.clone());
    let mut out_mult = DeviceBuffer::<i8>::with_capacity_in(n_rows.max(1), scope.clone());
    unsafe {
        out_tlr.set_len(n_rows * 3 * DIGEST_WIDTH);
        out_height.set_len(n_rows);
        out_idx.set_len(n_rows);
        out_tag1.set_len(n_rows);
        out_tag2.set_len(n_rows);
        out_tag3.set_len(n_rows);
        out_mult.set_len(n_rows);
    }
    scope.synchronize_blocking().unwrap();
    let stage_c_h2d = t_c_h2d.elapsed();

    let act_idx_base = act_idx_dev.as_ptr();
    let cur_base = cur_pool.as_mut_ptr();
    let defaults_base = tree.defaults_dev.as_ptr();

    // --- Stage C compute: current values, bottom-up over active nodes. ---
    let t_cur = Instant::now();
    for lvl in (0..h).rev() {
        let n_a = active_count[lvl];
        if n_a == 0 {
            continue;
        }
        let node_idx = unsafe { act_idx_base.add(act_offset[lvl]) };
        let n_ac = active_count[lvl + 1] as u32;
        let act_child_idx = unsafe { act_idx_base.add(act_offset[lvl + 1]) };
        let act_child_val =
            unsafe { cur_base.add(act_offset[lvl + 1] * DIGEST_WIDTH) } as *const SP1Field;
        let prev_child_idx = tree.idx_ptr(lvl + 1);
        let n_pc = tree.count[lvl + 1] as u32;
        let prev_child_val = tree.val_ptr(lvl + 1);
        let default_child = unsafe { defaults_base.add((lvl + 1) * DIGEST_WIDTH) };
        let out_val = unsafe { cur_base.add(act_offset[lvl] * DIGEST_WIDTH) };
        let n_a32 = n_a as u32;
        let grid = n_a.div_ceil(BLOCK);
        let kern = unsafe { cur_compress_merkle_tree_kernel() };
        let a = args!(
            node_idx,
            n_a32,
            act_child_idx,
            n_ac,
            act_child_val,
            prev_child_idx,
            n_pc,
            prev_child_val,
            default_child,
            out_val
        );
        unsafe { scope.launch_kernel(kern, grid, BLOCK, &a, 0).unwrap() };
    }
    scope.synchronize_blocking().unwrap();
    let cur_build = t_cur.elapsed();

    // --- Stage C emit: two rows per active internal node. ---
    let t_emit = Instant::now();
    let h32 = h as u32;
    let tlr_base = out_tlr.as_mut_ptr();
    let oh = out_height.as_mut_ptr();
    let oi = out_idx.as_mut_ptr();
    let ot1 = out_tag1.as_mut_ptr();
    let ot2 = out_tag2.as_mut_ptr();
    let ot3 = out_tag3.as_mut_ptr();
    let om = out_mult.as_mut_ptr();
    for lvl in 0..h {
        let n_a = active_count[lvl];
        if n_a == 0 {
            continue;
        }
        let node_idx = unsafe { act_idx_base.add(act_offset[lvl]) };
        let n_a32 = n_a as u32;
        let lvl32 = lvl as u32;
        let prev_self_idx = tree.idx_ptr(lvl);
        let n_ps = tree.count[lvl] as u32;
        let prev_self_val = tree.val_ptr(lvl);
        let default_self = unsafe { defaults_base.add(lvl * DIGEST_WIDTH) };
        let cur_self_val =
            unsafe { cur_base.add(act_offset[lvl] * DIGEST_WIDTH) } as *const SP1Field;
        let act_child_idx = unsafe { act_idx_base.add(act_offset[lvl + 1]) };
        let n_ac = active_count[lvl + 1] as u32;
        let act_child_val =
            unsafe { cur_base.add(act_offset[lvl + 1] * DIGEST_WIDTH) } as *const SP1Field;
        let prev_child_idx = tree.idx_ptr(lvl + 1);
        let n_pc = tree.count[lvl + 1] as u32;
        let prev_child_val = tree.val_ptr(lvl + 1);
        let default_child = unsafe { defaults_base.add((lvl + 1) * DIGEST_WIDTH) };
        let row_base = (2 * prefix_internal[lvl]) as u32;
        let grid = n_a.div_ceil(BLOCK);
        let kern = unsafe { emit_rows_merkle_tree_kernel() };
        let a = args!(
            node_idx,
            n_a32,
            lvl32,
            h32,
            prev_self_idx,
            n_ps,
            prev_self_val,
            default_self,
            cur_self_val,
            act_child_idx,
            n_ac,
            act_child_val,
            prev_child_idx,
            n_pc,
            prev_child_val,
            default_child,
            row_base,
            tlr_base,
            oh,
            oi,
            ot1,
            ot2,
            ot3,
            om
        );
        unsafe { scope.launch_kernel(kern, grid, BLOCK, &a, 0).unwrap() };
    }
    scope.synchronize_blocking().unwrap();
    let emit = t_emit.elapsed();

    // --- D2H: copy the trace back. ---
    let t_d2h = Instant::now();
    let tlr = out_tlr.to_host().unwrap();
    let hh = out_height.to_host().unwrap();
    let ii = out_idx.to_host().unwrap();
    let t1 = out_tag1.to_host().unwrap();
    let t2 = out_tag2.to_host().unwrap();
    let t3 = out_tag3.to_host().unwrap();
    let mm = out_mult.to_host().unwrap();
    let d2h = t_d2h.elapsed();

    // cur root = row 1's T (level-0 current row); prev root from the build.
    let cur_root =
        if n_rows >= 2 { core::array::from_fn(|k| tlr[3 * DIGEST_WIDTH + k]) } else { prev_root };

    let proof = BatchMerkleProof {
        prev_root,
        cur_root,
        n_rows,
        tlr,
        height: hh,
        idx: ii,
        tag1: tags_from_codes(t1),
        tag2: tags_from_codes(t2),
        tag3: tags_from_codes(t3),
        mult: mm,
    };
    let timings = GpuTimings { prev: prev_t, active_host, stage_c_h2d, cur_build, emit, d2h };
    (proof, timings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use slop_algebra::AbstractField;
    use slop_merkle_tree::batch_update::{
        batch_update, cancellation_residual, cpu_prev_levels, validate_row_constraints,
    };
    use sp1_gpu_cudart::run_sync_in_place;

    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self {
            Rng(seed)
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next_u64() % n
        }
    }
    const P: u32 = 0x7f00_0001;
    fn rand_digest(rng: &mut Rng) -> Digest {
        core::array::from_fn(|_| SP1Field::from_canonical_u32((rng.next_u64() as u32) % P))
    }

    /// Generate sorted leaves and the matching index/value arrays.
    fn gen_leaves(
        rng: &mut Rng,
        height: usize,
        n_leaves: usize,
        clustered: bool,
    ) -> (Vec<(u64, Digest)>, Vec<u32>, Vec<SP1Field>) {
        let span = 1u64 << height;
        let mut idxs: Vec<u64> = if clustered {
            let n = (n_leaves as u64).min(span);
            let base = if span > n { rng.below(span - n) } else { 0 };
            (base..base + n).collect()
        } else {
            let mut s = std::collections::BTreeSet::new();
            while (s.len() as u64) < (n_leaves as u64).min(span) {
                s.insert(rng.below(span));
            }
            s.into_iter().collect()
        };
        idxs.sort_unstable();
        let leaves: Vec<(u64, Digest)> = idxs.iter().map(|&i| (i, rand_digest(rng))).collect();
        let leaf_idx: Vec<u32> = leaves.iter().map(|l| l.0 as u32).collect();
        let leaf_val: Vec<SP1Field> = leaves.iter().flat_map(|l| l.1).collect();
        (leaves, leaf_idx, leaf_val)
    }

    /// Read a resident GPU level back as `(idx, digest)` pairs.
    fn read_level(tree: &GpuPrevTree, lvl: usize) -> Vec<(u64, Digest)> {
        let m = tree.count[lvl];
        if m == 0 {
            return Vec::new();
        }
        let (idx, val) = if lvl == tree.height {
            (tree.leaf_idx.to_host().unwrap(), tree.leaf_val.to_host().unwrap())
        } else {
            // Slice the pool for this level.
            let idx_all = tree.pool_idx.to_host().unwrap();
            let val_all = tree.pool_val.to_host().unwrap();
            let o = tree.offset[lvl];
            (idx_all[o..o + m].to_vec(), val_all[o * DIGEST_WIDTH..(o + m) * DIGEST_WIDTH].to_vec())
        };
        (0..m)
            .map(|p| {
                let d: Digest = core::array::from_fn(|k| val[p * DIGEST_WIDTH + k]);
                (idx[p] as u64, d)
            })
            .collect()
    }

    #[allow(clippy::needless_range_loop)]
    fn check_prev_build(seed: u64, height: usize, n_leaves: usize, clustered: bool) {
        run_sync_in_place(|scope| {
            let mut rng = Rng::new(seed);
            let dl = rand_digest(&mut rng);
            let (leaves, lidx, lval) = gen_leaves(&mut rng, height, n_leaves, clustered);

            let (tree, prev_root, _) = gpu_build_prev(&scope, dl, &lidx, &lval, height);
            let cpu = cpu_prev_levels(dl, &leaves, height);

            for lvl in 0..=height {
                let gpu_level = read_level(&tree, lvl);
                assert_eq!(gpu_level, cpu[lvl], "seed {seed} level {lvl}: nodes differ");
            }
            if !cpu[0].is_empty() {
                assert_eq!(prev_root, cpu[0][0].1, "seed {seed}: prev_root mismatch");
            }
        })
        .unwrap();
    }

    #[test]
    fn gpu_prev_build_matches_cpu_small() {
        for seed in 0..30u64 {
            let height = 3 + (seed % 10) as usize;
            let span = 1usize << height;
            let mut rng = Rng::new(seed ^ 0x99);
            let nmax = (span as u64).max(1);
            let n = rng.below(nmax).max(1) as usize;
            check_prev_build(seed, height, n, seed % 2 == 0);
        }
    }

    #[test]
    fn gpu_prev_build_matches_cpu_h29() {
        for seed in 0..4u64 {
            check_prev_build(seed ^ 0x55, 29, 100_000, seed % 2 == 0);
        }
    }

    /// Generate sorted leaves and a consistent update batch.
    #[allow(clippy::type_complexity)]
    fn gen_case_full(
        rng: &mut Rng,
        height: usize,
        n_leaves: usize,
        n_updates: usize,
        clustered: bool,
        dl: Digest,
    ) -> (Vec<(u64, Digest)>, Vec<u32>, Vec<SP1Field>, Vec<Update>) {
        let (leaves, lidx, lval) = gen_leaves(rng, height, n_leaves, clustered);
        let leaf_map: std::collections::BTreeMap<u64, Digest> = leaves.iter().copied().collect();
        let span = 1u64 << height;
        let (foot_lo, foot_hi) = if leaves.is_empty() {
            (0, span)
        } else {
            (leaves[0].0, leaves[leaves.len() - 1].0 + 1)
        };
        let mut upd = std::collections::BTreeSet::new();
        // Cap by the number of distinct indices the footprint can supply (else the loop
        // can never reach `target` and spins forever).
        let target = (n_updates as u64).min(foot_hi - foot_lo) as usize;
        while upd.len() < target {
            // ~80% modify an existing leaf, ~20% a new page within the footprint.
            let idx = if !leaves.is_empty() && !rng.next_u64().is_multiple_of(5) {
                leaves[(rng.below(leaves.len() as u64)) as usize].0
            } else {
                foot_lo + rng.below(foot_hi - foot_lo)
            };
            upd.insert(idx);
        }
        let updates: Vec<Update> = upd
            .into_iter()
            .map(|idx| {
                let prev_leaf = *leaf_map.get(&idx).unwrap_or(&dl);
                let new_leaf = if rng.next_u64().is_multiple_of(4) { dl } else { rand_digest(rng) };
                Update { idx, prev_leaf, new_leaf }
            })
            .collect();
        (leaves, lidx, lval, updates)
    }

    fn assert_full(seed: u64, height: usize, n_leaves: usize, n_updates: usize, clustered: bool) {
        run_sync_in_place(|scope| {
            let mut rng = Rng::new(seed);
            let dl = rand_digest(&mut rng);
            let (leaves, lidx, lval, updates) =
                gen_case_full(&mut rng, height, n_leaves, n_updates, clustered, dl);

            let cpu = batch_update(dl, &leaves, &updates, height);
            let (proof, _) = gpu_batch_update(&scope, dl, &lidx, &lval, &updates, height);
            let gpu = proof.to_batch_proof();

            assert_eq!(gpu.prev_root, cpu.prev_root, "seed {seed}: prev_root");
            assert_eq!(gpu.cur_root, cpu.cur_root, "seed {seed}: cur_root");
            assert_eq!(gpu.rows.len(), cpu.rows.len(), "seed {seed}: row count");
            for (i, (g, c)) in gpu.rows.iter().zip(cpu.rows.iter()).enumerate() {
                assert_eq!(g.height, c.height, "seed {seed} row {i} height");
                assert_eq!(g.idx, c.idx, "seed {seed} row {i} idx");
                assert_eq!(g.mult, c.mult, "seed {seed} row {i} mult");
                assert_eq!(
                    (g.tag1, g.tag2, g.tag3),
                    (c.tag1, c.tag2, c.tag3),
                    "seed {seed} row {i} tags"
                );
                assert_eq!(g.t, c.t, "seed {seed} row {i} T");
                assert_eq!(g.l, c.l, "seed {seed} row {i} L");
                assert_eq!(g.r, c.r, "seed {seed} row {i} R");
            }
            validate_row_constraints(&gpu, height);
            assert!(
                cancellation_residual(&gpu, &updates, height).is_empty(),
                "seed {seed}: GPU proof did not cancel"
            );
        })
        .unwrap();
    }

    #[test]
    fn gpu_matches_cpu_small() {
        for seed in 0..40u64 {
            let height = 3 + (seed % 9) as usize;
            let span = 1usize << height;
            let mut rng = Rng::new(seed ^ 0x77);
            let nl = rng.below((span as u64).max(1)) as usize;
            let nu = rng.below((span as u64).max(1)) as usize;
            assert_full(seed, height, nl, nu, seed % 2 == 0);
        }
    }

    #[test]
    fn gpu_matches_cpu_h29() {
        for seed in 0..4u64 {
            assert_full(seed ^ 0x3333, 29, 100_000, 5_000, seed % 2 == 0);
        }
    }

    #[test]
    #[allow(clippy::print_stdout)]
    fn bench_gpu_1m() {
        run_sync_in_place(|scope| {
            for clustered in [true, false] {
                let mut rng = Rng::new(0xCAFE);
                let dl = rand_digest(&mut rng);
                let (_, lidx, lval, updates) =
                    gen_case_full(&mut rng, 29, 1_000_000, 10_000, clustered, dl);
                for _ in 0..2 {
                    let _ = gpu_batch_update(&scope, dl, &lidx, &lval, &updates, 29);
                }
                let mut samples = Vec::new();
                for _ in 0..5 {
                    let (_, t) = gpu_batch_update(&scope, dl, &lidx, &lval, &updates, 29);
                    samples.push(t);
                }
                let med = |f: &dyn Fn(&GpuTimings) -> Duration| {
                    let mut v: Vec<Duration> = samples.iter().map(f).collect();
                    v.sort();
                    v[2]
                };
                let (proof, _) = gpu_batch_update(&scope, dl, &lidx, &lval, &updates, 29);
                let n_rows = proof.n_rows;
                let trace_mb = (n_rows * 3 * DIGEST_WIDTH * 4) as f64 / 1.0e6;
                let mut asm = Vec::new();
                for _ in 0..5 {
                    let ta = Instant::now();
                    let _ = proof.to_rows();
                    asm.push(ta.elapsed());
                }
                asm.sort();
                let assemble = asm[2];
                let dist = if clustered { "clustered" } else { "scattered" };
                println!("=== FULL, H=29, 1M leaves, 10k updates ({dist}) ===");
                println!("  n_rows: {n_rows}  (trace digests ~{trace_mb:.1} MB)");
                println!("  prev host_prep: {:?}", med(&|t| t.prev.host_prep));
                println!("  prev H2D      : {:?}", med(&|t| t.prev.h2d));
                println!("  prev count    : {:?}", med(&|t| t.prev.count_pass));
                println!("  prev build    : {:?}", med(&|t| t.prev.compute));
                println!("  active (host) : {:?}", med(&|t| t.active_host));
                println!("  stage C H2D   : {:?}", med(&|t| t.stage_c_h2d));
                println!("  cur build     : {:?}", med(&|t| t.cur_build));
                println!("  emit          : {:?}", med(&|t| t.emit));
                println!("  D2H           : {:?}", med(&|t| t.d2h));
                let pipeline = med(&|t| {
                    t.prev.host_prep
                        + t.prev.h2d
                        + t.prev.count_pass
                        + t.prev.compute
                        + t.active_host
                        + t.stage_c_h2d
                        + t.cur_build
                        + t.emit
                        + t.d2h
                });
                println!("  PIPELINE TOTAL: {pipeline:?}  (column output, no row repack)");
                println!("  + assemble(par): {assemble:?}  -> {:?}", pipeline + assemble);
            }
        })
        .unwrap();
    }

    #[test]
    #[allow(clippy::print_stdout)]
    fn bench_gpu_prev_build_1m() {
        run_sync_in_place(|scope| {
            for clustered in [true, false] {
                let mut rng = Rng::new(0xBEEF);
                let dl = rand_digest(&mut rng);
                let (_, lidx, lval) = gen_leaves(&mut rng, 29, 1_000_000, clustered);
                for _ in 0..2 {
                    let _ = gpu_build_prev(&scope, dl, &lidx, &lval, 29);
                }
                let mut prep = Vec::new();
                let mut h2d = Vec::new();
                let mut cnt = Vec::new();
                let mut comp = Vec::new();
                for _ in 0..5 {
                    let (_, _, t) = gpu_build_prev(&scope, dl, &lidx, &lval, 29);
                    prep.push(t.host_prep);
                    h2d.push(t.h2d);
                    cnt.push(t.count_pass);
                    comp.push(t.compute);
                }
                prep.sort();
                h2d.sort();
                cnt.sort();
                comp.sort();
                let dist = if clustered { "clustered" } else { "scattered" };
                println!("=== prev build, H=29, 1M leaves ({dist}) ===");
                println!("  host prep  (median): {:?}", prep[2]);
                println!("  H2D        (median): {:?}", h2d[2]);
                println!("  count pass (median): {:?}", cnt[2]);
                println!("  build      (median): {:?}", comp[2]);
            }
        })
        .unwrap();
    }
}
