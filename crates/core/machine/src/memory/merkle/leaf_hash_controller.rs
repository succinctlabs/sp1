use core::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};

use slop_air::{Air, BaseAir, GlobalBuilder};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::{IndexedParallelIterator, ParallelIterator, ParallelSliceMut};
use slop_merkle_tree::batch_update::Tag;
use sp1_core_executor::{ExecutionRecord, Program};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::{InteractionScope, MachineAir};

use super::leaf_hash::{BLOCKS_PER_HASH, DIGEST_WIDTH};
use crate::{air::SP1CoreAirBuilder, utils::next_multiple_of_32};

/// The columns of the [`LeafHashControlChip`]. One row per touched page.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct LeafHashControlCols<T: Copy> {
    /// The page id.
    pub page_id: T,

    /// The prev leaf hash.
    pub prev_state: [T; DIGEST_WIDTH],

    /// The new leaf hash.
    pub new_state: [T; DIGEST_WIDTH],

    /// Whether this row is padding or not.
    pub is_real: T,
}

/// The number of columns in the [`LeafHashControlChip`].
pub const NUM_LEAF_HASH_CONTROL_COLS: usize = size_of::<LeafHashControlCols<u8>>();

/// The leaf-hash controller chip (see the module docs).
#[derive(Default)]
pub struct LeafHashControlChip;

impl LeafHashControlChip {
    /// Create a new [`LeafHashControlChip`].
    pub const fn new() -> Self {
        Self
    }
}

impl<F> BaseAir<F> for LeafHashControlChip {
    fn width(&self) -> usize {
        0
    }
}

impl<F: PrimeField32> MachineAir<F> for LeafHashControlChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "LeafHashControl"
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = input.merkle_proof_record.as_ref().map_or(0, |r| r.payload.pages.len());
        let size_log2 = input.fixed_log2_rows::<F, Self>(self);
        Some(next_multiple_of_32(nb_rows, size_log2))
    }

    fn global_width(&self) -> usize {
        NUM_LEAF_HASH_CONTROL_COLS
    }

    fn generate_trace_into(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _buffer: &mut [MaybeUninit<F>],
    ) {
    }

    fn generate_global_trace_into(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let width = <Self as MachineAir<F>>::global_width(self);
        let padded_nb_rows = <Self as MachineAir<F>>::num_rows(self, input).unwrap();
        let record = input.merkle_proof_record.as_ref();
        let num_pages = record.map_or(0, |r| r.payload.pages.len());

        unsafe {
            core::ptr::write_bytes(buffer.as_mut_ptr(), 0, padded_nb_rows * width);
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, padded_nb_rows * width) };

        values[..num_pages * width].par_chunks_mut(width).enumerate().for_each(|(p, row)| {
            let record = record.unwrap();
            let cols: &mut LeafHashControlCols<F> = row.borrow_mut();
            cols.page_id = F::from_canonical_u32(record.payload.page_ids[p]);
            cols.prev_state = core::array::from_fn(|i| {
                F::from_canonical_u32(record.prev_leaves[p][i].as_canonical_u32())
            });
            cols.new_state = core::array::from_fn(|i| {
                F::from_canonical_u32(record.new_leaves[p][i].as_canonical_u32())
            });
            cols.is_real = F::one();
        });
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            shard.merkle_proof_record.as_ref().is_some_and(|r| !r.payload.pages.is_empty())
        }
    }
}

impl<AB> Air<AB> for LeafHashControlChip
where
    AB: SP1CoreAirBuilder + GlobalBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let global = builder.global();
        let local = global.row_slice(0);
        let local: &LeafHashControlCols<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_real);

        // Send the leaf hash request for the initial contents.
        builder.send_leaf_hash(
            local.page_id,
            AB::Expr::one(),
            AB::Expr::zero(),
            core::array::from_fn::<_, DIGEST_WIDTH, _>(|_| AB::Expr::zero()),
            local.is_real,
            InteractionScope::Local,
        );
        builder.receive_leaf_hash(
            local.page_id,
            AB::Expr::one(),
            AB::Expr::from_canonical_usize(BLOCKS_PER_HASH),
            local.prev_state,
            local.is_real,
            InteractionScope::Local,
        );

        // Send the leaf hash request for the final values.
        builder.send_leaf_hash(
            local.page_id,
            AB::Expr::zero(),
            AB::Expr::zero(),
            core::array::from_fn::<_, DIGEST_WIDTH, _>(|_| AB::Expr::zero()),
            local.is_real,
            InteractionScope::Local,
        );
        builder.receive_leaf_hash(
            local.page_id,
            AB::Expr::zero(),
            AB::Expr::from_canonical_usize(BLOCKS_PER_HASH),
            local.new_state,
            local.is_real,
            InteractionScope::Local,
        );

        builder.receive_merkle_traversal(
            AB::Expr::from_canonical_u32(29),
            local.page_id,
            AB::Expr::from_canonical_u8(Tag::InitLeave as u8),
            local.prev_state,
            local.is_real,
            InteractionScope::Global,
        );

        builder.send_merkle_traversal(
            AB::Expr::from_canonical_u32(29),
            local.page_id,
            AB::Expr::from_canonical_u8(Tag::FinalLeave as u8),
            local.new_state,
            local.is_real,
            InteractionScope::Global,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        memory::merkle::{
            leaf_hash::LeafHashChip,
            test_util::{
                accumulate_interactions, assert_bus_balanced, assert_constraints_satisfied,
                chip_traces,
            },
        },
        merkle_prover::hash_page,
    };
    use sp1_core_executor::{ExecutionRecord, MerkleProofRecord, MerkleProvingPayload, PageState};
    use sp1_hypercube::{Chip, InteractionKind};
    use sp1_jit::MERKLE_PAGE_WORDS;
    use sp1_primitives::SP1Field;
    use std::collections::HashMap;

    fn test_record() -> (ExecutionRecord, [u64; MERKLE_PAGE_WORDS], [u64; MERKLE_PAGE_WORDS]) {
        let initial: [u64; MERKLE_PAGE_WORDS] =
            core::array::from_fn(|i| (i as u64).wrapping_mul(0x1234_5678_9abc_def1));
        let final_values: [u64; MERKLE_PAGE_WORDS] =
            core::array::from_fn(|i| (i as u64 + 1).wrapping_mul(0xdead_beef_0bad_f00d));

        let page = PageState {
            initial_contents: initial,
            last_clk: [0; MERKLE_PAGE_WORDS],
            final_values,
            shard_touched_bits: [0; MERKLE_PAGE_WORDS / 64],
        };
        let mut record = ExecutionRecord::default();
        record.merkle_proof_record = Some(MerkleProofRecord {
            payload: MerkleProvingPayload { page_ids: vec![7], pages: vec![page] },
            proof: Default::default(),
            prev_leaves: vec![hash_page(&initial)],
            new_leaves: vec![hash_page(&final_values)],
        });
        (record, initial, final_values)
    }

    #[test]
    fn leaf_hash_control_digests_match_hash_page() {
        let (record, initial, final_values) = test_record();

        let chip = Chip::new(LeafHashControlChip::new());
        let (global, _) = chip_traces(&chip, &record);
        let trace = global.expect("control chip is wholly global");

        let cols: &LeafHashControlCols<SP1Field> =
            trace.values[..NUM_LEAF_HASH_CONTROL_COLS].borrow();
        let prev_digest: [SP1Field; DIGEST_WIDTH] = core::array::from_fn(|i| cols.prev_state[i]);
        let new_digest: [SP1Field; DIGEST_WIDTH] = core::array::from_fn(|i| cols.new_state[i]);

        assert_eq!(prev_digest, hash_page(&initial));
        assert_eq!(new_digest, hash_page(&final_values));
        assert_eq!(cols.page_id, SP1Field::from_canonical_u32(7));
    }

    /// The `LeafHash` bus balances across the controller and the permute chip: every state the
    /// controller injects / reads is matched by the sponge rows, and vice-versa.
    #[test]
    fn leaf_hash_bus_balances() {
        let (record, _, _) = test_record();

        let lh = Chip::new(LeafHashChip::new());
        let ctrl = Chip::new(LeafHashControlChip::new());
        let (lh_global, lh_main) = chip_traces(&lh, &record);
        let (ctrl_global, ctrl_main) = chip_traces(&ctrl, &record);

        let mut totals = HashMap::new();
        accumulate_interactions(
            &lh,
            lh_global.as_ref(),
            lh_main.as_ref(),
            &[InteractionKind::LeafHash],
            &mut totals,
        );
        accumulate_interactions(
            &ctrl,
            ctrl_global.as_ref(),
            ctrl_main.as_ref(),
            &[InteractionKind::LeafHash],
            &mut totals,
        );
        assert_bus_balanced(&totals);
    }

    /// Both chips' AIR constraints are satisfied on their generated traces.
    #[test]
    fn leaf_hash_constraints_hold() {
        let (record, _, _) = test_record();

        let lh = Chip::new(LeafHashChip::new());
        let ctrl = Chip::new(LeafHashControlChip::new());
        let (lh_global, lh_main) = chip_traces(&lh, &record);
        let (ctrl_global, ctrl_main) = chip_traces(&ctrl, &record);

        assert_constraints_satisfied(&lh, lh_global.as_ref(), lh_main.as_ref());
        assert_constraints_satisfied(&ctrl, ctrl_global.as_ref(), ctrl_main.as_ref());
    }
}
