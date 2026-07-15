use serde::{Deserialize, Serialize};
use slop_algebra::PrimeField32;
use slop_challenger::IopCtx;
use slop_koala_bear::{KoalaBear, KoalaBearDegree4Duplex};
use slop_symmetric::PseudoCompressionFunction;

/// An 8-element KoalaBear Poseidon2 digest (a Merkle node value / leaf hash).
pub type Digest = <KoalaBearDegree4Duplex as IopCtx>::Digest;

/// The compression function for the merkle tree.
pub type Compressor = <KoalaBearDegree4Duplex as IopCtx>::Compressor;

/// Construct the compressor (the KoalaBear-16 Poseidon2 truncated permutation).
#[inline]
pub fn make_compressor() -> Compressor {
    KoalaBearDegree4Duplex::default_hasher_and_compressor().1
}

/// The compression function.
#[inline]
pub(crate) fn sigma(c: &Compressor, l: Digest, r: Digest) -> Digest {
    c.compress([l, r])
}

/// A single leaf update: the leaf at `idx` goes from `prev_leaf` to `new_leaf`.
/// `prev_leaf` must equal the prev tree's current leaf at `idx`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Update {
    pub idx: u64,
    pub prev_leaf: Digest,
    pub new_leaf: Digest,
}

/// Tags for the batch merkle proof AIR.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tag {
    InitRoot,
    InitInternal,
    InitLeave,
    FinalRoot,
    FinalInternal,
    FinalLeave,
    Shared,
}

impl Tag {
    /// The compact `u8` code for this tag (matches the GPU emit kernel's tag codes).
    #[inline]
    pub fn to_code(self) -> u8 {
        match self {
            Tag::InitRoot => 0,
            Tag::InitInternal => 1,
            Tag::InitLeave => 2,
            Tag::FinalRoot => 3,
            Tag::FinalInternal => 4,
            Tag::FinalLeave => 5,
            Tag::Shared => 6,
        }
    }

    /// Inverse of [`Tag::to_code`].
    #[inline]
    pub fn from_code(code: u8) -> Self {
        match code {
            0 => Tag::InitRoot,
            1 => Tag::InitInternal,
            2 => Tag::InitLeave,
            3 => Tag::FinalRoot,
            4 => Tag::FinalInternal,
            5 => Tag::FinalLeave,
            6 => Tag::Shared,
            _ => panic!("invalid tag code {code}"),
        }
    }
}

/// A single row of the batch merkle proof AIR.
#[derive(Clone, Debug)]
pub struct Row {
    pub height: usize,
    pub idx: u64,
    pub tag1: Tag,
    pub t: Digest,
    pub tag2: Tag,
    pub l: Digest,
    pub tag3: Tag,
    pub r: Digest,
    pub mult: i64,
}

/// The batch merkle proof as the AIR trace.
#[derive(Clone, Debug)]
pub struct BatchProof {
    pub prev_root: Digest,
    pub cur_root: Digest,
    pub rows: Vec<Row>,
}

/// The batch merkle proof in the GPU friendly form.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BatchMerkleProof {
    pub prev_root: Digest,
    pub cur_root: Digest,
    pub n_rows: usize,
    pub tlr: Vec<KoalaBear>,
    pub height: Vec<u32>,
    pub idx: Vec<u32>,
    pub tag1: Vec<Tag>,
    pub tag2: Vec<Tag>,
    pub tag3: Vec<Tag>,
    pub mult: Vec<i8>,
}

impl BatchMerkleProof {
    /// Number of proof rows.
    #[inline]
    pub fn n_rows(&self) -> usize {
        self.n_rows
    }

    /// The `j`-th digest in the flat `tlr` column (`j = 3i + {0,1,2}` for row `i`).
    #[inline]
    fn digest_at(&self, j: usize) -> Digest {
        core::array::from_fn(|k| self.tlr[8 * j + k])
    }

    /// Reconstruct row `i` as a [`Row`].
    pub fn row(&self, i: usize) -> Row {
        Row {
            height: self.height[i] as usize,
            idx: self.idx[i] as u64,
            tag1: self.tag1[i],
            t: self.digest_at(3 * i),
            tag2: self.tag2[i],
            l: self.digest_at(3 * i + 1),
            tag3: self.tag3[i],
            r: self.digest_at(3 * i + 2),
            mult: self.mult[i] as i64,
        }
    }

    /// Materialize all rows.
    pub fn to_rows(&self) -> Vec<Row> {
        (0..self.n_rows).map(|i| self.row(i)).collect()
    }

    /// Materialize the row-vector [`BatchProof`] form.
    pub fn to_batch_proof(&self) -> BatchProof {
        BatchProof { prev_root: self.prev_root, cur_root: self.cur_root, rows: self.to_rows() }
    }

    /// The sub-proof holding rows `[start, end)`; both roots are preserved.
    pub fn sub_proof(&self, start: usize, end: usize) -> BatchMerkleProof {
        BatchMerkleProof {
            prev_root: self.prev_root,
            cur_root: self.cur_root,
            n_rows: end - start,
            tlr: self.tlr[24 * start..24 * end].to_vec(),
            height: self.height[start..end].to_vec(),
            idx: self.idx[start..end].to_vec(),
            tag1: self.tag1[start..end].to_vec(),
            tag2: self.tag2[start..end].to_vec(),
            tag3: self.tag3[start..end].to_vec(),
            mult: self.mult[start..end].to_vec(),
        }
    }

    /// Split into sub-proofs of at most `max_rows` rows each.
    pub fn split(&self, max_rows: usize) -> Vec<BatchMerkleProof> {
        if max_rows == 0 || self.n_rows <= max_rows {
            return vec![self.clone()];
        }
        let mut out = Vec::with_capacity(self.n_rows.div_ceil(max_rows));
        let mut start = 0;
        while start < self.n_rows {
            let end = (start + max_rows).min(self.n_rows);
            out.push(self.sub_proof(start, end));
            start = end;
        }
        out
    }
}

impl BatchProof {
    /// Pack the row-vector proof into the column [`BatchMerkleProof`] form.
    pub fn to_merkle_proof(&self) -> BatchMerkleProof {
        let n_rows = self.rows.len();
        let mut tlr = Vec::with_capacity(24 * n_rows);
        let mut height = Vec::with_capacity(n_rows);
        let mut idx = Vec::with_capacity(n_rows);
        let mut tag1 = Vec::with_capacity(n_rows);
        let mut tag2 = Vec::with_capacity(n_rows);
        let mut tag3 = Vec::with_capacity(n_rows);
        let mut mult = Vec::with_capacity(n_rows);
        for row in &self.rows {
            tlr.extend_from_slice(&row.t);
            tlr.extend_from_slice(&row.l);
            tlr.extend_from_slice(&row.r);
            height.push(row.height as u32);
            idx.push(row.idx as u32);
            tag1.push(row.tag1);
            tag2.push(row.tag2);
            tag3.push(row.tag3);
            mult.push(row.mult as i8);
        }
        BatchMerkleProof {
            prev_root: self.prev_root,
            cur_root: self.cur_root,
            n_rows,
            tlr,
            height,
            idx,
            tag1,
            tag2,
            tag3,
            mult,
        }
    }
}

/// Expected number of rows in the batch proof, derived independently from the updated
/// leaf indices alone — a cross-check on the emitted trace.
pub(crate) fn expected_proof_len(update_idxs: &[u64], height: usize) -> usize {
    use std::collections::HashSet;
    if update_idxs.is_empty() {
        // Just the root: one prev row + one current row.
        return 2;
    }
    let mut active_internal = 0usize;
    for k in 1..=(height as u32) {
        let distinct: HashSet<u64> = update_idxs.iter().map(|&i| i >> k).collect();
        active_internal += distinct.len();
    }
    2 * active_internal
}

/// `default[h]` for `h in 0..=height`: the value of a fully-default subtree of that height.
pub fn default_hashes(c: &Compressor, default_leaf: Digest, height: usize) -> Vec<Digest> {
    let mut defaults = vec![default_leaf; height + 1];
    for h in (0..height).rev() {
        defaults[h] = sigma(c, defaults[h + 1], defaults[h + 1]);
    }
    defaults
}

/// Position of `idx` in a sorted, distinct index slice, or `None`.
#[inline]
pub(crate) fn pos_of(sorted: &[u64], idx: u64) -> Option<usize> {
    sorted.binary_search(&idx).ok()
}

/// Sparse per-level node values. `levels[h]` is sorted by index and holds only the
/// non-default nodes at height `h`. `levels[height]` is the leaf level.
struct SparseLevels {
    levels: Vec<Vec<(u64, Digest)>>,
}

impl SparseLevels {
    /// Build the full sparse tree bottom-up from `leaves` (sorted, distinct by index).
    fn build(c: &Compressor, defaults: &[Digest], leaves: &[(u64, Digest)], height: usize) -> Self {
        let mut levels: Vec<Vec<(u64, Digest)>> = vec![Vec::new(); height + 1];
        levels[height] = leaves.to_vec();

        for h in (0..height).rev() {
            let children = &levels[h + 1];
            let default_child = defaults[h + 1];
            let mut parents: Vec<(u64, Digest)> = Vec::with_capacity(children.len());

            let mut i = 0;
            while i < children.len() {
                let (cidx, cval) = children[i];
                let parent = cidx >> 1;
                // Default the missing sibling; fill in whichever child(ren) are present.
                let (mut lval, mut rval) = (default_child, default_child);
                if cidx & 1 == 0 {
                    lval = cval;
                } else {
                    rval = cval;
                }
                // The only other child sharing this parent (if present) is the sibling,
                // and because the level is sorted+distinct it is the very next entry.
                if i + 1 < children.len() && (children[i + 1].0 >> 1) == parent {
                    rval = children[i + 1].1;
                    i += 1;
                }
                parents.push((parent, sigma(c, lval, rval)));
                i += 1;
            }
            levels[h] = parents;
        }

        Self { levels }
    }

    /// Value at node `(h, idx)`: the stored value if present, else the default for `h`.
    #[inline]
    fn value(&self, defaults: &[Digest], h: usize, idx: u64) -> Digest {
        match self.levels[h].binary_search_by_key(&idx, |&(i, _)| i) {
            Ok(p) => self.levels[h][p].1,
            Err(_) => defaults[h],
        }
    }

    /// The root value (`default[0]` if the tree is fully default).
    #[inline]
    fn root(&self, defaults: &[Digest]) -> Digest {
        self.value(defaults, 0, 0)
    }
}

/// Build the prev sparse tree on the CPU and return its per-level non-default nodes
/// (`levels[h]` sorted by index; `levels[height]` is the leaves).
pub fn cpu_prev_levels(
    default_leaf: Digest,
    leaves: &[(u64, Digest)],
    height: usize,
) -> Vec<Vec<(u64, Digest)>> {
    let c = make_compressor();
    let defaults = default_hashes(&c, default_leaf, height);
    SparseLevels::build(&c, &defaults, leaves, height).levels
}

/// Merkle root of a sparse tree with non-default `leaves` (sorted, distinct); the `prev_root` of a
/// [`batch_update`] over the same leaves, without emitting a trace.
pub fn compute_root(default_leaf: Digest, leaves: &[(u64, Digest)], height: usize) -> Digest {
    let c = make_compressor();
    let defaults = default_hashes(&c, default_leaf, height);
    SparseLevels::build(&c, &defaults, leaves, height).root(&defaults)
}

/// `tag1` for an emitted internal node: root vs internal, prev (`init`) vs current.
#[inline]
pub(crate) fn node_tag(init: bool, h: usize) -> Tag {
    match (init, h == 0) {
        (true, true) => Tag::InitRoot,
        (true, false) => Tag::InitInternal,
        (false, true) => Tag::FinalRoot,
        (false, false) => Tag::FinalInternal,
    }
}

/// Tag for a child at `child_level`: `SHARED` if it has no updated leaf below it,
/// else leaf/internal depending on whether it sits on the leaf level (`== height`).
#[inline]
pub(crate) fn child_tag(is_active: bool, init: bool, child_level: usize, height: usize) -> Tag {
    if !is_active {
        return Tag::Shared;
    }
    match (init, child_level == height) {
        (true, true) => Tag::InitLeave,
        (true, false) => Tag::InitInternal,
        (false, true) => Tag::FinalLeave,
        (false, false) => Tag::FinalInternal,
    }
}

/// Per-level node indices reachable from `base_idxs` (a sorted, distinct set of leaf
/// indices at level `height`): `levels[h]` is the sorted, distinct set of ancestors at
/// height `h`. With `force_root`, the root (level 0) is always included even when
/// `base_idxs` is empty — used for the active subtree. Without it, an empty base
/// yields all-empty levels — used for the sparse prev tree.
pub fn ancestor_levels(base_idxs: &[u64], height: usize, force_root: bool) -> Vec<Vec<u64>> {
    let mut levels: Vec<Vec<u64>> = vec![Vec::new(); height + 1];
    levels[height] = base_idxs.to_vec();

    for h in (0..height).rev() {
        let mut parents: Vec<u64> = Vec::with_capacity(levels[h + 1].len());
        let mut last: Option<u64> = None;
        for &c in &levels[h + 1] {
            let p = c >> 1;
            if last != Some(p) {
                parents.push(p);
                last = Some(p);
            }
        }
        levels[h] = parents;
    }

    if force_root && levels[0].is_empty() {
        levels[0].push(0);
    }
    levels
}

/// Run the batch update and produce the tagged batch proof.
///
/// `leaves` and `updates` must be sorted by index with distinct indices, all in
/// `[0, 2^height)`. Each `prev_leaf` must equal the prev tree's leaves.
pub fn batch_update(
    default_leaf: Digest,
    leaves: &[(u64, Digest)],
    updates: &[Update],
    height: usize,
) -> BatchProof {
    assert!(height >= 1, "height must be >= 1");
    debug_assert!(
        leaves.windows(2).all(|w| w[0].0 < w[1].0),
        "leaves must be sorted with distinct indices"
    );
    debug_assert!(
        updates.windows(2).all(|w| w[0].idx < w[1].idx),
        "updates must be sorted with distinct indices"
    );

    let c = make_compressor();
    let defaults = default_hashes(&c, default_leaf, height);

    // --- Prev tree (the σ-build; this is the dominant cost at scale) ---
    let prev = SparseLevels::build(&c, &defaults, leaves, height);
    let prev_root = prev.root(&defaults);

    // Witness check: each update's prev_leaf must match the prev tree's leaf.
    for u in updates {
        assert!(u.idx < (1u64 << height), "update idx out of range");
        let actual = prev.value(&defaults, height, u.idx);
        assert!(
            actual == u.prev_leaf,
            "update.prev_leaf does not match prev tree at idx {}",
            u.idx
        );
    }

    // --- Active subtree (structure depends only on the indices) ---
    let update_idxs: Vec<u64> = updates.iter().map(|u| u.idx).collect();
    let active = ancestor_levels(&update_idxs, height, true);

    // --- Current values along the active subtree (recompute only what changed) ---
    // `cur_val[h]` is parallel to `active[h]`.
    let mut cur_val: Vec<Vec<Digest>> = vec![Vec::new(); height + 1];
    cur_val[height] = updates.iter().map(|u| u.new_leaf).collect();

    // Current value of a child at `(child_level, idx)`: its recomputed value if active,
    // otherwise the (unchanged) prev value.
    let child_cur =
        |child_level: usize, idx: u64, active: &[Vec<u64>], cur_val: &[Vec<Digest>]| -> Digest {
            match pos_of(&active[child_level], idx) {
                Some(p) => cur_val[child_level][p],
                None => prev.value(&defaults, child_level, idx),
            }
        };

    for h in (0..height).rev() {
        let mut vals = Vec::with_capacity(active[h].len());
        for &i in &active[h] {
            let l = child_cur(h + 1, 2 * i, &active, &cur_val);
            let r = child_cur(h + 1, 2 * i + 1, &active, &cur_val);
            vals.push(sigma(&c, l, r));
        }
        cur_val[h] = vals;
    }
    // active[0] == [0] always, so its single value is the current root.
    let cur_root = cur_val[0][0];

    // --- Emit the tagged trace ---
    let mut rows: Vec<Row> = Vec::new();
    for h in 0..height {
        for (pos, &i) in active[h].iter().enumerate() {
            let prev_t = prev.value(&defaults, h, i);
            let cur_t = cur_val[h][pos];

            let l_idx = 2 * i;
            let r_idx = 2 * i + 1;
            let l_prev = prev.value(&defaults, h + 1, l_idx);
            let r_prev = prev.value(&defaults, h + 1, r_idx);
            let l_active = pos_of(&active[h + 1], l_idx);
            let r_active = pos_of(&active[h + 1], r_idx);
            let l_cur = l_active.map_or(l_prev, |p| cur_val[h + 1][p]);
            let r_cur = r_active.map_or(r_prev, |p| cur_val[h + 1][p]);

            // Prev-tree row (mult = +1).
            rows.push(Row {
                height: h,
                idx: i,
                tag1: node_tag(true, h),
                t: prev_t,
                tag2: child_tag(l_active.is_some(), true, h + 1, height),
                l: l_prev,
                tag3: child_tag(r_active.is_some(), true, h + 1, height),
                r: r_prev,
                mult: 1,
            });
            // Current-tree row (mult = -1).
            rows.push(Row {
                height: h,
                idx: i,
                tag1: node_tag(false, h),
                t: cur_t,
                tag2: child_tag(l_active.is_some(), false, h + 1, height),
                l: l_cur,
                tag3: child_tag(r_active.is_some(), false, h + 1, height),
                r: r_cur,
                mult: -1,
            });
        }
    }

    assert_eq!(
        rows.len(),
        expected_proof_len(&update_idxs, height),
        "emitted proof length does not match the expected length"
    );

    BatchProof { prev_root, cur_root, rows }
}

/// The interaction `(height, idx, tag, value)`.
type Term = (usize, u64, Tag, [u32; 8]);

/// Canonical hashable key for a digest.
#[inline]
fn digest_key(d: &Digest) -> [u32; 8] {
    core::array::from_fn(|i| d[i].as_canonical_u32())
}

/// Verify the batch proof works as intended.
pub fn cancellation_residual(
    proof: &BatchProof,
    updates: &[Update],
    height: usize,
) -> Vec<(Term, i64)> {
    use std::collections::HashMap;
    let mut coeffs: HashMap<Term, i64> = HashMap::new();
    let mut add = |h: usize, idx: u64, tag: Tag, d: &Digest, k: i64| {
        *coeffs.entry((h, idx, tag, digest_key(d))).or_insert(0) += k;
    };

    add(0, 0, Tag::InitRoot, &proof.prev_root, -1);
    add(0, 0, Tag::FinalRoot, &proof.cur_root, 1);

    for u in updates {
        add(height, u.idx, Tag::InitLeave, &u.prev_leaf, 1);
        add(height, u.idx, Tag::FinalLeave, &u.new_leaf, -1);
    }

    for row in &proof.rows {
        let m = row.mult;
        add(row.height, row.idx, row.tag1, &row.t, m);
        add(row.height + 1, 2 * row.idx, row.tag2, &row.l, -m);
        add(row.height + 1, 2 * row.idx + 1, row.tag3, &row.r, -m);
    }

    coeffs.into_iter().filter(|&(_, k)| k != 0).collect()
}

/// Assert every row of the proof satisfies the per-row trace constraints.
pub fn validate_row_constraints(proof: &BatchProof, height: usize) {
    let c = make_compressor();
    for (r, row) in proof.rows.iter().enumerate() {
        assert!(matches!(row.mult, -1..=1), "row {r}: mult {} not in {{-1, 0, 1}}", row.mult);
        assert!(row.height < height, "row {r}: height {} not < H = {height}", row.height);
        assert!(row.idx < (1u64 << row.height), "row {r}: idx {} not < 2^{}", row.idx, row.height);
        assert_eq!(sigma(&c, row.l, row.r), row.t, "row {r}: T != σ(L, R)");

        // mult == 0 contributes nothing, so its tags are unconstrained (skip the rules).
        if row.mult == 0 {
            continue;
        }
        let init = row.mult == 1;

        let expected_tag1 = match (init, row.height == 0) {
            (true, true) => Tag::InitRoot,
            (true, false) => Tag::InitInternal,
            (false, true) => Tag::FinalRoot,
            (false, false) => Tag::FinalInternal,
        };
        assert_eq!(row.tag1, expected_tag1, "row {r}: TAG1");

        let child_is_leaf = row.height + 1 == height;
        let allowed: [Tag; 2] = match (init, child_is_leaf) {
            (true, false) => [Tag::InitInternal, Tag::Shared],
            (true, true) => [Tag::InitLeave, Tag::Shared],
            (false, false) => [Tag::FinalInternal, Tag::Shared],
            (false, true) => [Tag::FinalLeave, Tag::Shared],
        };
        assert!(allowed.contains(&row.tag2), "row {r}: TAG2 {:?} not in {allowed:?}", row.tag2);
        assert!(allowed.contains(&row.tag3), "row {r}: TAG3 {:?} not in {allowed:?}", row.tag3);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, Rng as _, SeedableRng};
    use slop_algebra::AbstractField;
    use std::collections::BTreeMap;

    /// Seeded deterministic RNG so test cases stay reproducible across runs.
    struct Rng(StdRng);
    impl Rng {
        fn new(seed: u64) -> Self {
            Rng(StdRng::seed_from_u64(seed))
        }
        fn next_u64(&mut self) -> u64 {
            self.0.gen()
        }
        fn below(&mut self, n: u64) -> u64 {
            self.0.gen_range(0..n)
        }
    }

    const P: u32 = 0x7f00_0001; // KoalaBear prime.

    fn rand_field(rng: &mut Rng) -> KoalaBear {
        KoalaBear::from_canonical_u32((rng.next_u64() as u32) % P)
    }

    fn rand_digest(rng: &mut Rng) -> Digest {
        core::array::from_fn(|_| rand_field(rng))
    }

    /// Independent, dead-simple dense oracle: materialize all `2^height` leaves and
    /// fold the whole binary tree up. Only usable for small `height`.
    fn dense_root(
        c: &Compressor,
        default_leaf: Digest,
        leaf_map: &BTreeMap<u64, Digest>,
        height: usize,
    ) -> Digest {
        let mut level: Vec<Digest> =
            (0..(1u64 << height)).map(|i| *leaf_map.get(&i).unwrap_or(&default_leaf)).collect();
        for _ in 0..height {
            level = level.chunks(2).map(|p| sigma(c, p[0], p[1])).collect();
        }
        level[0]
    }

    /// Build a random sparse tree + consistent update batch.
    ///
    /// `clustered`: leaf indices form a contiguous block (realistic for memory pages);
    /// otherwise scattered uniformly. Some updates hit existing leaves, some hit
    /// previously-default slots; some `new_leaf`s equal the default (deletion).
    fn gen_case(
        rng: &mut Rng,
        height: usize,
        n_leaves: usize,
        n_updates: usize,
        clustered: bool,
        default_leaf: Digest,
    ) -> (Vec<(u64, Digest)>, Vec<Update>) {
        let span = 1u64 << height;

        // Leaf indices.
        let mut leaf_idxs: Vec<u64> = if clustered {
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
        leaf_idxs.sort_unstable();
        let leaves: Vec<(u64, Digest)> = leaf_idxs.iter().map(|&i| (i, rand_digest(rng))).collect();
        let leaf_map: BTreeMap<u64, Digest> = leaves.iter().copied().collect();

        // Update indices: mix of existing leaves and fresh (default) slots.
        let mut upd_idxs = std::collections::BTreeSet::new();
        let target = (n_updates as u64).min(span) as usize;
        while upd_idxs.len() < target {
            let from_existing = !leaves.is_empty() && rng.next_u64().is_multiple_of(2);
            let idx = if from_existing {
                leaves[(rng.below(leaves.len() as u64)) as usize].0
            } else {
                rng.below(span)
            };
            upd_idxs.insert(idx);
        }

        let updates: Vec<Update> = upd_idxs
            .into_iter()
            .map(|idx| {
                let prev_leaf = *leaf_map.get(&idx).unwrap_or(&default_leaf);
                // ~1 in 4 updates is a deletion (new_leaf == default).
                let new_leaf =
                    if rng.next_u64().is_multiple_of(4) { default_leaf } else { rand_digest(rng) };
                Update { idx, prev_leaf, new_leaf }
            })
            .collect();

        (leaves, updates)
    }

    /// Apply updates to the leaf set, producing the current leaf set (sorted, distinct).
    fn apply_updates(leaves: &[(u64, Digest)], updates: &[Update]) -> Vec<(u64, Digest)> {
        let mut map: BTreeMap<u64, Digest> = leaves.iter().copied().collect();
        for u in updates {
            map.insert(u.idx, u.new_leaf);
        }
        map.into_iter().collect()
    }

    fn assert_valid(proof: &BatchProof, updates: &[Update], height: usize) {
        validate_row_constraints(proof, height);
        let residual = cancellation_residual(proof, updates, height);
        assert!(
            residual.is_empty(),
            "interactions mistmatch: {} non-zero terms, e.g. {:?}",
            residual.len(),
            residual.iter().take(4).collect::<Vec<_>>()
        );
    }

    #[test]
    fn expected_proof_len_hand_computed() {
        let h = 4;
        // Two adjacent leaves share every ancestor: 4 internal nodes (levels 3..0) → 8 rows.
        assert_eq!(expected_proof_len(&[0, 1], h), 8);
        // Leaves 0 and 8 split immediately below the root: levels 3,2,1 have 2 nodes each,
        // level 0 has the shared root → 7 internal nodes → 14 rows.
        assert_eq!(expected_proof_len(&[0, 8], h), 14);
        // A single update touches one node per level → H internal nodes → 2H rows.
        assert_eq!(expected_proof_len(&[5], h), 2 * h);
        // No updates → just the root's two rows.
        assert_eq!(expected_proof_len(&[], h), 2);
    }

    #[test]
    fn defaults_are_consistent() {
        let c = make_compressor();
        let dl = [KoalaBear::from_canonical_u32(7); 8];
        let d = default_hashes(&c, dl, 5);
        assert_eq!(d[5], dl);
        for h in 0..5 {
            assert_eq!(d[h], sigma(&c, d[h + 1], d[h + 1]));
        }
    }

    #[test]
    fn empty_updates_roots_equal_and_cancels() {
        let mut rng = Rng::new(1);
        let height = 8;
        let dl = rand_digest(&mut rng);
        let (leaves, _) = gen_case(&mut rng, height, 40, 0, false, dl);
        let proof = batch_update(dl, &leaves, &[], height);
        assert_eq!(proof.prev_root, proof.cur_root, "no updates ⇒ root unchanged");
        assert_valid(&proof, &[], height);
    }

    #[test]
    fn compute_root_matches_batch_update_prev_root() {
        let mut rng = Rng::new(0xC0FFEE);
        let height = 12;
        let dl = rand_digest(&mut rng);
        let (leaves, _) = gen_case(&mut rng, height, 50, 0, false, dl);
        let proof = batch_update(dl, &leaves, &[], height);
        assert_eq!(compute_root(dl, &leaves, height), proof.prev_root);
    }

    #[test]
    fn compute_root_empty_is_default_root() {
        let c = make_compressor();
        let dl = [KoalaBear::from_canonical_u32(9); 8];
        let defaults = default_hashes(&c, dl, 10);
        assert_eq!(compute_root(dl, &[], 10), defaults[0]);
    }

    #[test]
    fn matches_dense_oracle_small() {
        let c = make_compressor();
        for seed in 0..200u64 {
            let mut rng = Rng::new(seed);
            let height = 3 + (seed % 8) as usize; // 3..=10
            let dl = rand_digest(&mut rng);
            let span = 1usize << height;
            let n_leaves = rng.below((span as u64).max(1)) as usize;
            let n_updates = rng.below((span as u64).max(1)) as usize;
            let clustered = seed % 2 == 0;
            let (leaves, updates) = gen_case(&mut rng, height, n_leaves, n_updates, clustered, dl);

            let proof = batch_update(dl, &leaves, &updates, height);

            // prev_root vs dense.
            let prev_map: BTreeMap<u64, Digest> = leaves.iter().copied().collect();
            assert_eq!(
                proof.prev_root,
                dense_root(&c, dl, &prev_map, height),
                "prev_root seed {seed}"
            );

            // cur_root vs dense over the updated leaf set.
            let cur_leaves = apply_updates(&leaves, &updates);
            let cur_map: BTreeMap<u64, Digest> = cur_leaves.iter().copied().collect();
            assert_eq!(
                proof.cur_root,
                dense_root(&c, dl, &cur_map, height),
                "cur_root seed {seed}"
            );

            // The proof is valid.
            assert_valid(&proof, &updates, height);
        }
    }

    #[test]
    fn cur_root_matches_full_rebuild_any_height() {
        // Validates the incremental current-value recompute against a full rebuild,
        // at heights where dense materialization is infeasible.
        let c = make_compressor();
        for seed in 0..40u64 {
            let mut rng = Rng::new(seed ^ 0xABCD);
            let height = 29;
            let dl = rand_digest(&mut rng);
            let clustered = seed % 2 == 0;
            let (leaves, updates) = gen_case(&mut rng, height, 2000, 200, clustered, dl);

            let proof = batch_update(dl, &leaves, &updates, height);

            let cur_leaves = apply_updates(&leaves, &updates);
            let defaults = default_hashes(&c, dl, height);
            let rebuilt = SparseLevels::build(&c, &defaults, &cur_leaves, height);
            assert_eq!(proof.cur_root, rebuilt.root(&defaults), "cur_root seed {seed}");

            assert_valid(&proof, &updates, height);
        }
    }

    #[test]
    fn realistic_scale_h29() {
        // The target shape: H=29, ~1M real leaves (clustered, as memory pages tend to
        // be), ~10k updates. Validates via cancellation + full-rebuild cross-check.
        let c = make_compressor();
        let mut rng = Rng::new(0xF1BB);
        let height = 29;
        let dl = rand_digest(&mut rng);
        let (leaves, updates) = gen_case(&mut rng, height, 1_000_000, 10_000, true, dl);

        let proof = batch_update(dl, &leaves, &updates, height);

        let cur_leaves = apply_updates(&leaves, &updates);
        let defaults = default_hashes(&c, dl, height);
        let rebuilt = SparseLevels::build(&c, &defaults, &cur_leaves, height);
        assert_eq!(proof.cur_root, rebuilt.root(&defaults));

        assert_valid(&proof, &updates, height);
    }

    #[test]
    #[ignore = "stress: H=29 with 1M scattered leaves; slow single-threaded"]
    fn stress_scattered_h29() {
        let mut rng = Rng::new(0x5CA7);
        let height = 29;
        let dl = rand_digest(&mut rng);
        let (leaves, updates) = gen_case(&mut rng, height, 1_000_000, 10_000, false, dl);
        let proof = batch_update(dl, &leaves, &updates, height);
        assert_valid(&proof, &updates, height);
    }
}
