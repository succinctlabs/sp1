use std::{collections::HashMap, marker::PhantomData, sync::Arc};

use slop_air::Air;
use slop_algebra::{extension::BinomialExtensionField, AbstractField, Field, PrimeField32};
use slop_matrix::{dense::RowMajorMatrix, Matrix};
use slop_multilinear::Mle;
use sp1_core_executor::{ExecutionRecord, MerkleProvingPayload, PageState};
use sp1_hypercube::{
    air::{InteractionScope, MachineAir},
    debug_constraints, Chip, DebugConstraintBuilder, DebugPublicValuesConstraintFolder,
    InteractionKind, MachineRecord,
};
use sp1_jit::MERKLE_PAGE_WORDS;
use sp1_primitives::{SP1Field, SP1GlobalContext};

use crate::merkle_prover::{build_merkle_proof_record, hash_page, zero_leaf, MerkleProvingInput};

type EF = BinomialExtensionField<SP1Field, 4>;

/// A bus message keyed by `(scope, kind, comma-joined values)` mapped to its net multiplicity.
pub(crate) type BusTotals = HashMap<(InteractionScope, InteractionKind, String), SP1Field>;

/// The full `[global ‖ main]` trace of a chip, matching the `{ global, main }` column layout.
pub(crate) fn full_trace<A: MachineAir<SP1Field, Record = ExecutionRecord>>(
    chip: &Chip<SP1Field, A>,
    record: &ExecutionRecord,
) -> RowMajorMatrix<SP1Field> {
    let mut out = ExecutionRecord::default();
    let rows = chip.num_rows(record).unwrap();
    let main = chip.generate_trace(record, &mut out);
    let Some(global) = chip.generate_global_trace(record, &mut out) else {
        return main;
    };
    let (gw, mw) = (global.width(), main.width());
    let mut values = Vec::with_capacity(rows * (gw + mw));
    for i in 0..rows {
        values.extend_from_slice(&global.values[i * gw..(i + 1) * gw]);
        if mw > 0 {
            values.extend_from_slice(&main.values[i * mw..(i + 1) * mw]);
        }
    }
    RowMajorMatrix::new(values, gw + mw)
}

/// Accumulate `chip`'s interactions of the given `kinds` over `trace`.
pub(crate) fn accumulate_interactions<A: MachineAir<SP1Field>>(
    chip: &Chip<SP1Field, A>,
    trace: &RowMajorMatrix<SP1Field>,
    kinds: &[InteractionKind],
    totals: &mut BusTotals,
) {
    let width = trace.width();
    let empty: [SP1Field; 0] = [];
    for row in trace.values.chunks(width) {
        for (sign, interactions) in
            [(SP1Field::one(), chip.sends()), (SP1Field::neg_one(), chip.receives())]
        {
            for it in interactions.iter().filter(|i| kinds.contains(&i.kind)) {
                let mult: SP1Field = it.multiplicity.apply(&empty, row);
                if mult.is_zero() {
                    continue;
                }
                let key = it
                    .values
                    .iter()
                    .map(|v| {
                        let value: SP1Field = v.apply(&empty, row);
                        value.to_string()
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                *totals.entry((it.scope, it.kind, key)).or_insert(SP1Field::zero()) += sign * mult;
            }
        }
    }
}

/// Assert every accumulated message nets to zero.
pub(crate) fn assert_bus_balanced(totals: &BusTotals) {
    assert!(!totals.is_empty(), "no interactions were accumulated (wrong kind filter?)");
    let unbalanced: Vec<_> =
        totals.iter().filter(|(_, net)| !net.is_zero()).map(|(k, net)| (k, *net)).collect();
    assert!(unbalanced.is_empty(), "bus not balanced; nonzero nets: {unbalanced:?}");
}

/// Print and count the messages whose sends/receives don't cancel (run with `-- --nocapture`).
#[allow(clippy::print_stdout)]
pub(crate) fn report_bus_mismatches(totals: &BusTotals) -> usize {
    let mut mismatches: Vec<_> = totals.iter().filter(|(_, net)| !net.is_zero()).collect();
    mismatches.sort_by(|a, b| a.0.cmp(b.0));
    for ((scope, kind, values), net) in &mismatches {
        println!("[{scope} {kind}] mult={net} values=({values})");
    }
    println!("--- {} mismatched message(s) ---", mismatches.len());
    mismatches.len()
}

/// Assert `chip`'s constraints hold on `trace`.
pub(crate) fn assert_constraints_satisfied<A>(
    chip: &Chip<SP1Field, A>,
    trace: &RowMajorMatrix<SP1Field>,
) where
    A: MachineAir<SP1Field> + for<'a> Air<DebugConstraintBuilder<'a, SP1Field, EF>>,
{
    let main: Mle<SP1Field> = Mle::from(trace.clone());
    let failures = debug_constraints::<SP1GlobalContext, A>(chip, None, &main, &[]);
    assert!(
        failures.is_empty(),
        "constraint failures (row, failing constraint indices): {:?}",
        failures.iter().map(|(row, idx, _)| (*row, idx.clone())).collect::<Vec<_>>()
    );
}

/// Deterministic non-zero page contents for page `p`, `phase` 0 = initial, 1 = final.
fn page_words(p: usize, phase: u64) -> [u64; MERKLE_PAGE_WORDS] {
    core::array::from_fn(|i| {
        ((p as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15)
            ^ (i as u64).wrapping_mul(0xc2b2_ae3d_27d4_eb4f))
        .wrapping_add(phase.wrapping_mul(0xd6e8_feb8_6659_fd93))
    })
}

/// A consistent record (real proof via [`build_merkle_proof_record`]) for `n_pages` touched pages,
/// with non-zero initial contents so `prev_leaves` and `pre_chunk_snapshot` are non-trivial.
pub(crate) fn merkle_record(n_pages: usize) -> ExecutionRecord {
    let mut page_ids = Vec::with_capacity(n_pages);
    let mut pages = Vec::with_capacity(n_pages);
    let mut prev_leaves = Vec::with_capacity(n_pages);
    let mut new_leaves = Vec::with_capacity(n_pages);
    let mut snapshot = Vec::with_capacity(n_pages);
    for p in 0..n_pages {
        let page_id = p as u32 + 1;
        let initial = page_words(p, 0);
        let final_values = page_words(p, 1);
        let prev = hash_page(&initial);
        page_ids.push(page_id);
        prev_leaves.push(prev);
        new_leaves.push(hash_page(&final_values));
        if prev != zero_leaf() {
            snapshot.push((page_id, prev));
        }
        pages.push(PageState {
            initial_contents: initial,
            last_clk: [0; MERKLE_PAGE_WORDS],
            final_values,
            shard_touched_bits: [0; MERKLE_PAGE_WORDS / 64],
        });
    }
    let input = MerkleProvingInput {
        chunk_idx: 0,
        pre_chunk_snapshot: Arc::new(snapshot),
        prev_leaves: Arc::new(prev_leaves),
        new_leaves: Arc::new(new_leaves),
        payload: MerkleProvingPayload { page_ids, pages },
    };
    let proof_record = build_merkle_proof_record(input);
    let mut record = ExecutionRecord::default();
    record.public_values.prev_merkle_root =
        proof_record.proof.prev_root.map(|x| x.as_canonical_u32());
    record.public_values.merkle_root = proof_record.proof.cur_root.map(|x| x.as_canonical_u32());
    record.public_values.is_first_merkle_shard = 1;
    record.merkle_proof_record = Some(proof_record);
    record
}

/// Accumulate the public-value interactions given `kinds` into `totals`.
pub(crate) fn accumulate_public_value_interactions(
    record: &ExecutionRecord,
    kinds: &[InteractionKind],
    totals: &mut BusTotals,
) {
    let public_values: Vec<SP1Field> = record.public_values.to_vec();
    let zero = SP1Field::zero();
    let mut folder = DebugPublicValuesConstraintFolder::<SP1Field> {
        perm_challenges: (&zero, &[]),
        alpha: zero,
        accumulator: zero,
        interactions: vec![],
        public_values: &public_values,
        _marker: PhantomData,
    };
    ExecutionRecord::eval_public_values(&mut folder);
    for (kind, scope, values, mult) in folder.interactions {
        if !kinds.contains(&kind) || mult.is_zero() {
            continue;
        }
        let key = values.iter().map(ToString::to_string).collect::<Vec<_>>().join(",");
        *totals.entry((scope, kind, key)).or_insert(SP1Field::zero()) += mult;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::merkle::{
        leaf_hash::LeafHashChip, leaf_hash_controller::LeafHashControlChip,
        tree_traversal::MerkleTreeTraversalChip,
    };

    /// The `LeafHash` and `MerkleTreeTraversal` buses fully cancel.
    #[test]
    fn merkle_pipeline_bus_balances() {
        let record = merkle_record(2000);

        let lh = Chip::new(LeafHashChip::new());
        let ctrl = Chip::new(LeafHashControlChip::new());
        let tt = Chip::new(MerkleTreeTraversalChip::new());

        let kinds = [InteractionKind::LeafHash, InteractionKind::MerkleTreeTraversal];
        let mut totals = BusTotals::new();
        accumulate_interactions(&lh, &full_trace(&lh, &record), &kinds, &mut totals);
        accumulate_interactions(&ctrl, &full_trace(&ctrl, &record), &kinds, &mut totals);
        accumulate_interactions(&tt, &full_trace(&tt, &record), &kinds, &mut totals);
        accumulate_public_value_interactions(&record, &kinds, &mut totals);

        assert_eq!(report_bus_mismatches(&totals), 0, "merkle pipeline bus should fully cancel");
    }
}
