use std::{collections::HashMap, marker::PhantomData, sync::Arc};

use slop_air::{Air, BaseAir};
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

/// The `(global, main)` traces of a chip, generated from `record`.
pub(crate) fn chip_traces<A: MachineAir<SP1Field, Record = ExecutionRecord>>(
    chip: &Chip<SP1Field, A>,
    record: &ExecutionRecord,
) -> (Option<RowMajorMatrix<SP1Field>>, Option<RowMajorMatrix<SP1Field>>) {
    let mut out = ExecutionRecord::default();
    let main = (chip.width() > 0).then(|| chip.generate_trace(record, &mut out));
    let global = chip.generate_global_trace(record, &mut out);
    (global, main)
}

/// Accumulate `chip`'s interactions of the given `kinds` over its `(global, main)` traces.
pub(crate) fn accumulate_interactions<A: MachineAir<SP1Field>>(
    chip: &Chip<SP1Field, A>,
    global: Option<&RowMajorMatrix<SP1Field>>,
    main: Option<&RowMajorMatrix<SP1Field>>,
    kinds: &[InteractionKind],
    totals: &mut BusTotals,
) {
    let height = main.map_or_else(
        || global.map_or(0, Matrix::height),
        |m| {
            if let Some(global) = global {
                assert_eq!(m.height(), global.height(), "global and main heights must match");
            }
            m.height()
        },
    );
    let empty: [SP1Field; 0] = [];
    for row in 0..height {
        let global_row =
            global.map_or(&[][..], |g| &g.values[row * g.width()..(row + 1) * g.width()]);
        let main_row = main.map_or(&[][..], |m| &m.values[row * m.width()..(row + 1) * m.width()]);
        for (sign, interactions) in
            [(SP1Field::one(), chip.sends()), (SP1Field::neg_one(), chip.receives())]
        {
            for it in interactions.iter().filter(|i| kinds.contains(&i.kind)) {
                let mult: SP1Field = it.multiplicity.apply(&empty, global_row, main_row);
                if mult.is_zero() {
                    continue;
                }
                let key = it
                    .values
                    .iter()
                    .map(|v| {
                        let value: SP1Field = v.apply(&empty, global_row, main_row);
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

/// Assert `chip`'s constraints hold on its `(global, main)` traces.
pub(crate) fn assert_constraints_satisfied<A>(
    chip: &Chip<SP1Field, A>,
    global: Option<&RowMajorMatrix<SP1Field>>,
    main: Option<&RowMajorMatrix<SP1Field>>,
) where
    A: MachineAir<SP1Field> + for<'a> Air<DebugConstraintBuilder<'a, SP1Field, EF>>,
{
    let global: Option<Mle<SP1Field>> = global.map(|g| Mle::from(g.clone()));
    let main: Option<Mle<SP1Field>> = main.map(|m| Mle::from(m.clone()));
    let failures =
        debug_constraints::<SP1GlobalContext, A>(chip, None, global.as_ref(), main.as_ref(), &[]);
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
    record.public_values.num_merkle_shard = 1;
    record.public_values.inv_num_shards = 1;
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
        leaf_hash::{LeafHashChip, BLOCKS_PER_HASH},
        leaf_hash_controller::LeafHashControlChip,
        tree_traversal::MerkleTreeTraversalChip,
    };
    use crate::merkle_prover::split_merkle_proof_record;
    use sp1_core_executor::{
        rv64im_costs, RiscvAirId, SP1CoreOpts, ShardingThreshold, BYTE_NUM_ROWS,
        MAXIMUM_CYCLE_AREA, MAXIMUM_PADDING_AREA, RANGE_NUM_ROWS,
    };

    /// `SP1CoreOpts` admitting ~`pages_per_shard` pages per merkle shard (`program_len == 0`);
    /// height threshold stays large so only area binds.
    fn split_opts(pages_per_shard: u64) -> SP1CoreOpts {
        let costs = rv64im_costs();
        let cost = |id: RiscvAirId| costs[&id] as u64;
        let base = BYTE_NUM_ROWS * cost(RiscvAirId::Byte)
            + RANGE_NUM_ROWS * cost(RiscvAirId::Range)
            + MAXIMUM_PADDING_AREA
            + MAXIMUM_CYCLE_AREA;
        let page_cost = cost(RiscvAirId::LeafHashControl)
            + 2 * BLOCKS_PER_HASH as u64 * cost(RiscvAirId::LeafHash);
        SP1CoreOpts {
            sharding_threshold: ShardingThreshold {
                element_threshold: base + pages_per_shard * page_cost,
                height_threshold: 1 << 22,
            },
            ..SP1CoreOpts::default()
        }
    }

    /// The `LeafHash` and `MerkleTreeTraversal` buses fully cancel.
    #[test]
    fn merkle_pipeline_bus_balances() {
        let record = merkle_record(2000);

        let lh = Chip::new(LeafHashChip::new());
        let ctrl = Chip::new(LeafHashControlChip::new());
        let tt = Chip::new(MerkleTreeTraversalChip::new());

        let kinds = [InteractionKind::LeafHash, InteractionKind::MerkleTreeTraversal];
        let mut totals = BusTotals::new();
        for_chip_traces(&lh, &record, &kinds, &mut totals);
        for_chip_traces(&ctrl, &record, &kinds, &mut totals);
        for_chip_traces(&tt, &record, &kinds, &mut totals);
        accumulate_public_value_interactions(&record, &kinds, &mut totals);

        assert_eq!(report_bus_mismatches(&totals), 0, "merkle pipeline bus should fully cancel");
    }

    /// A tight budget tiles the record into several shards exactly; a large budget keeps one.
    #[test]
    fn split_merkle_proof_record_tiles_the_record() {
        let record = merkle_record(12).merkle_proof_record.expect("merkle_record sets the record");
        let total_rows = record.proof.n_rows();

        // Large budget: the whole record stays a single shard.
        let whole = split_merkle_proof_record(
            record.clone(),
            0,
            &SP1CoreOpts {
                sharding_threshold: ShardingThreshold {
                    element_threshold: 1 << 30,
                    height_threshold: 1 << 22,
                },
                ..SP1CoreOpts::default()
            },
        );
        assert_eq!(whole.len(), 1, "a record that fits must stay one shard");
        assert_eq!(whole[0].payload.page_ids, record.payload.page_ids);
        assert_eq!(whole[0].proof.n_rows(), total_rows);

        // Tight budget: several shards. Reassembling them must reproduce the original exactly.
        let opts = split_opts(3);
        let pieces = split_merkle_proof_record(record.clone(), 0, &opts);
        assert!(pieces.len() > 1, "a tight budget must split the record");

        let (mut page_ids, mut prev_leaves, mut new_leaves) = (Vec::new(), Vec::new(), Vec::new());
        let (mut height, mut idx, mut mult) = (Vec::new(), Vec::new(), Vec::new());
        for piece in &pieces {
            // Page arrays stay parallel within each piece.
            assert_eq!(piece.payload.page_ids.len(), piece.payload.pages.len());
            assert_eq!(piece.prev_leaves.len(), piece.payload.pages.len());
            assert_eq!(piece.new_leaves.len(), piece.payload.pages.len());

            // Each piece fits the area and height budgets.
            let pages = piece.payload.pages.len() as u64;
            let rows = piece.proof.n_rows() as u64;
            let costs = rv64im_costs();
            let cost = |id: RiscvAirId| costs[&id] as u64;
            let base = BYTE_NUM_ROWS * cost(RiscvAirId::Byte)
                + RANGE_NUM_ROWS * cost(RiscvAirId::Range)
                + MAXIMUM_PADDING_AREA
                + MAXIMUM_CYCLE_AREA;
            let area = pages
                * (cost(RiscvAirId::LeafHashControl)
                    + 2 * BLOCKS_PER_HASH as u64 * cost(RiscvAirId::LeafHash))
                + rows * cost(RiscvAirId::MerkleTreeTraversal);
            assert!(base + area <= opts.sharding_threshold.element_threshold);
            assert!(2 * pages * BLOCKS_PER_HASH as u64 <= opts.sharding_threshold.height_threshold);
            assert!(rows <= opts.sharding_threshold.height_threshold);

            page_ids.extend_from_slice(&piece.payload.page_ids);
            prev_leaves.extend_from_slice(&piece.prev_leaves);
            new_leaves.extend_from_slice(&piece.new_leaves);
            height.extend_from_slice(&piece.proof.height);
            idx.extend_from_slice(&piece.proof.idx);
            mult.extend_from_slice(&piece.proof.mult);
        }
        assert_eq!(page_ids, record.payload.page_ids);
        assert_eq!(prev_leaves, record.prev_leaves);
        assert_eq!(new_leaves, record.new_leaves);
        assert_eq!(height, record.proof.height);
        assert_eq!(idx, record.proof.idx);
        assert_eq!(mult, record.proof.mult);
    }

    /// Merkle buses still cancel across a multi-shard split: shard 0 holds `is_first_merkle_shard`
    /// while (under this budget) the root rows land in a later, row-only shard.
    #[test]
    fn merkle_split_bus_balances() {
        let record = merkle_record(12).merkle_proof_record.expect("merkle_record sets the record");
        let prev_root = record.proof.prev_root.map(|x| x.as_canonical_u32());
        let cur_root = record.proof.cur_root.map(|x| x.as_canonical_u32());

        let pieces = split_merkle_proof_record(record, 0, &split_opts(3));
        assert!(pieces.len() > 1, "expected a multi-shard split");

        let lh = Chip::new(LeafHashChip::new());
        let ctrl = Chip::new(LeafHashControlChip::new());
        let tt = Chip::new(MerkleTreeTraversalChip::new());
        let kinds = [InteractionKind::LeafHash, InteractionKind::MerkleTreeTraversal];

        let num_shards = pieces.len() as u32;
        let mut totals = BusTotals::new();
        for (shard_index, piece) in pieces.into_iter().enumerate() {
            let mut shard = ExecutionRecord::default();
            shard.public_values.initial_timestamp = 1;
            shard.public_values.last_timestamp = 1;
            shard.public_values.prev_merkle_root = prev_root;
            shard.public_values.merkle_root = cur_root;
            shard.public_values.shard_index = shard_index as u32;
            shard.public_values.num_merkle_shard = num_shards;
            shard.finalize_public_values::<SP1Field>();
            shard.merkle_proof_record = Some(piece);

            for_chip_traces(&lh, &shard, &kinds, &mut totals);
            for_chip_traces(&ctrl, &shard, &kinds, &mut totals);
            for_chip_traces(&tt, &shard, &kinds, &mut totals);
            accumulate_public_value_interactions(&shard, &kinds, &mut totals);
        }
        assert_eq!(
            report_bus_mismatches(&totals),
            0,
            "merkle buses must cancel across the split shards"
        );
    }

    /// Generate a chip's traces and accumulate its interactions.
    fn for_chip_traces<A: MachineAir<SP1Field, Record = ExecutionRecord>>(
        chip: &Chip<SP1Field, A>,
        record: &ExecutionRecord,
        kinds: &[InteractionKind],
        totals: &mut BusTotals,
    ) {
        let (global, main) = chip_traces(chip, record);
        accumulate_interactions(chip, global.as_ref(), main.as_ref(), kinds, totals);
    }

    #[tokio::test]
    async fn test_merkle_cluster_prove_verify() {
        use crate::riscv::RiscvAir;
        use slop_basefold::FriConfig;
        use sp1_core_executor::{Instruction, Opcode, Program};
        use sp1_hypercube::{prover::simple_prover, MachineProof, ShardVerifier};

        // A standalone (non-execution) shard holding the merkle record.
        let machine = RiscvAir::<SP1Field>::machine();
        let program =
            Arc::new(Program::new(vec![Instruction::new(Opcode::ADD, 0, 0, 0, false, true)], 0, 0));
        let mut record = merkle_record(8);
        record.program = program.clone();
        record.public_values.update_initialized_state(0, false, None, None);
        machine.generate_dependencies(std::iter::once(&mut record), None);

        let verifier = ShardVerifier::from_basefold_parameters(
            FriConfig::default_fri_config(),
            21,
            22,
            machine,
        );
        let prover = simple_prover(verifier.clone());
        let (pk, vk) = prover.setup(program).await;
        let pk = unsafe { pk.into_inner() };
        let proof = prover.prove_shard(pk, record).await;

        assert!(proof.global_commitment.is_some());
        assert!(proof.global_cumulative_sum.is_some());

        let machine_verifier = sp1_hypercube::MachineVerifier::new(verifier);
        machine_verifier
            .verify(&vk, &MachineProof { shard_proofs: vec![proof] })
            .expect("merkle cluster proof should verify");
    }
}
