use core::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};

use hashbrown::HashMap;
use itertools::Itertools;
use slop_air::{Air, AirBuilder, BaseAir, GlobalBuilder, PairBuilder};
use slop_algebra::{AbstractField, Field, PrimeField32};
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::*;
use slop_merkle_tree::batch_update::Row;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode, ExecutionRecord, Program,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{InteractionScope, MachineAir},
    operations::poseidon2::{
        air::{eval_external_round, eval_internal_rounds},
        permutation::Poseidon2Cols,
        trace::populate_perm_deg3,
        Poseidon2Operation, NUM_EXTERNAL_ROUNDS, WIDTH,
    },
};

use crate::{
    air::{SP1CoreAirBuilder, SP1Operation},
    operations::{IsZeroOperation, IsZeroOperationInput},
    utils::next_multiple_of_32,
};

/// The width of a merkle node digest, in KoalaBear field elements.
pub const DIGEST_WIDTH: usize = 8;

/// The global columns of the [`MerkleTreeTraversalChip`].
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct MerkleTreeTraversalGlobalCols<T: Copy> {
    /// The height of the parent node `T`.
    pub height: T,

    /// The index of the parent node `T` within its level.
    pub idx: T,

    /// The tag of the parent node.
    pub tag1: T,

    /// The tag of the left child.
    pub tag2: T,

    /// The tag of the right child.
    pub tag3: T,

    /// The parent node value.
    pub t: [T; DIGEST_WIDTH],

    /// The left child value.
    pub l: [T; DIGEST_WIDTH],

    /// The right child value.
    pub r: [T; DIGEST_WIDTH],

    /// The multiplicity of this row.
    pub mult: T,

    /// Whether this row is padding or not.
    pub is_real: T,
}

/// The main columns of the [`MerkleTreeTraversalChip`].
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct MerkleTreeTraversalMainCols<T: Copy> {
    /// The Poseidon2 permutation.
    pub poseidon2: Poseidon2Operation<T>,

    /// The low 16 bits of the index.
    pub idx_low_16: T,

    /// The high-limb bit budget for `idx < 2^height` (`= max(height - 16, 0)`).
    pub k_hi: T,

    /// Indicator that `height == 0`.
    pub is_height_zero: IsZeroOperation<T>,

    /// Indicator that `height == H - 1` (the children are leaves).
    pub is_child_leaf: IsZeroOperation<T>,
}

/// The number of global columns in the [`MerkleTreeTraversalChip`].
pub const NUM_MERKLE_TREE_TRAVERSAL_GLOBAL_COLS: usize =
    size_of::<MerkleTreeTraversalGlobalCols<u8>>();

/// The number of main columns in the [`MerkleTreeTraversalChip`].
pub const NUM_MERKLE_TREE_TRAVERSAL_MAIN_COLS: usize = size_of::<MerkleTreeTraversalMainCols<u8>>();

/// The batch merkle-tree update chip (see the module docs).
#[derive(Default)]
pub struct MerkleTreeTraversalChip;

impl MerkleTreeTraversalChip {
    /// Create a new [`MerkleTreeTraversalChip`].
    pub const fn new() -> Self {
        Self
    }
}

impl<F> BaseAir<F> for MerkleTreeTraversalChip {
    fn width(&self) -> usize {
        NUM_MERKLE_TREE_TRAVERSAL_MAIN_COLS
    }
}

/// Convert a signed multiplicity into a field element.
#[inline]
fn mult_to_field<F: PrimeField32>(mult: i64) -> F {
    match mult {
        0 => F::zero(),
        1 => F::one(),
        -1 => F::neg_one(),
        other => panic!("multiplicity out of range: {other}"),
    }
}

/// Convert a KoalaBear digest into the chip's field `F`.
#[inline]
fn digest_to_field<F: PrimeField32>(
    digest: &[impl PrimeField32; DIGEST_WIDTH],
) -> [F; DIGEST_WIDTH] {
    core::array::from_fn(|i| F::from_canonical_u32(digest[i].as_canonical_u32()))
}

impl MerkleTreeTraversalChip {
    /// Populate a single global row from a [`Row`] of the batch merkle proof.
    fn populate_global_row<F: PrimeField32>(
        cols: &mut MerkleTreeTraversalGlobalCols<F>,
        row: &Row,
    ) {
        cols.height = F::from_canonical_usize(row.height);
        cols.idx = F::from_canonical_u64(row.idx);
        cols.tag1 = F::from_canonical_u8(row.tag1.to_code());
        cols.tag2 = F::from_canonical_u8(row.tag2.to_code());
        cols.tag3 = F::from_canonical_u8(row.tag3.to_code());
        cols.t = digest_to_field(&row.t);
        cols.l = digest_to_field(&row.l);
        cols.r = digest_to_field(&row.r);
        cols.mult = mult_to_field(row.mult);
        cols.is_real = F::one();
    }

    /// Populate a single main row from a [`Row`] of the batch merkle proof.
    fn populate_main_row<F: PrimeField32>(cols: &mut MerkleTreeTraversalMainCols<F>, row: &Row) {
        let mut perm_input = [F::zero(); WIDTH];
        perm_input[..DIGEST_WIDTH].copy_from_slice(&digest_to_field(&row.l));
        perm_input[DIGEST_WIDTH..].copy_from_slice(&digest_to_field(&row.r));
        cols.poseidon2 = populate_perm_deg3(perm_input, None);
        cols.idx_low_16 = F::from_canonical_u64(row.idx & 0xFFFF);
        cols.k_hi = F::from_canonical_usize(row.height.saturating_sub(16));
        cols.is_height_zero.populate(row.height as u64);
        cols.is_child_leaf.populate_from_field_element(
            F::from_canonical_usize(row.height) - F::from_canonical_u32(28),
        );
    }
}

impl<F: PrimeField32> MachineAir<F> for MerkleTreeTraversalChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "MerkleTreeTraversal"
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = input.merkle_proof_record.as_ref().map_or(0, |r| r.proof.n_rows());
        let size_log2 = input.fixed_log2_rows::<F, Self>(self);
        Some(next_multiple_of_32(nb_rows, size_log2))
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let proof = input.merkle_proof_record.as_ref().map(|r| &r.proof);
        let n_rows = proof.map_or(0, |p| p.n_rows());
        if n_rows == 0 {
            return;
        }
        let proof = proof.unwrap();
        let chunk_size = std::cmp::max(n_rows / num_cpus::get(), 1);
        let blu_batches = (0..n_rows)
            .into_par_iter()
            .chunks(chunk_size)
            .map(|idxs| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                for i in idxs {
                    let row = proof.row(i);
                    let k_hi = row.height.saturating_sub(16);
                    let k_lo = row.height - k_hi;
                    // `height < H = 29`.
                    blu.add_byte_lookup_event(ByteLookupEvent {
                        opcode: ByteOpcode::LTU,
                        a: 1,
                        b: row.height as u8,
                        c: 29,
                    });
                    // `idx < 2^height` via the two 16-bit-boundary limbs.
                    blu.add_bit_range_check((row.idx & 0xFFFF) as u16, k_lo as u8);
                    blu.add_bit_range_check((row.idx >> 16) as u16, k_hi as u8);
                }
                blu
            })
            .collect::<Vec<_>>();
        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
    }

    fn global_width(&self) -> usize {
        NUM_MERKLE_TREE_TRAVERSAL_GLOBAL_COLS
    }

    fn generate_global_trace_into(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let width = <Self as MachineAir<F>>::global_width(self);
        let padded_nb_rows = <Self as MachineAir<F>>::num_rows(self, input).unwrap();
        let proof = input.merkle_proof_record.as_ref().map(|r| &r.proof);
        let n_rows = proof.map_or(0, |p| p.n_rows());

        unsafe {
            let padding_start = n_rows * width;
            let padding_size = (padded_nb_rows - n_rows) * width;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }
        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, padded_nb_rows * width) };

        values.par_chunks_exact_mut(width).enumerate().for_each(|(idx, row)| {
            let cols: &mut MerkleTreeTraversalGlobalCols<F> = row.borrow_mut();
            if idx < n_rows {
                let row = proof.unwrap().row(idx);
                Self::populate_global_row(cols, &row);
            }
        });
    }

    fn generate_trace_into(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let width = <Self as BaseAir<F>>::width(self);
        let padded_nb_rows = <Self as MachineAir<F>>::num_rows(self, input).unwrap();
        let proof = input.merkle_proof_record.as_ref().map(|r| &r.proof);
        let n_rows = proof.map_or(0, |p| p.n_rows());

        unsafe {
            let padding_start = n_rows * width;
            let padding_size = (padded_nb_rows - n_rows) * width;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        // A consistent dummy permutation for padding rows.
        let dummy_poseidon2 = populate_perm_deg3::<F>([F::zero(); WIDTH], None);

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, padded_nb_rows * width) };

        values.par_chunks_exact_mut(width).enumerate().for_each(|(idx, row)| {
            let cols: &mut MerkleTreeTraversalMainCols<F> = row.borrow_mut();
            if idx < n_rows {
                let row = proof.unwrap().row(idx);
                Self::populate_main_row(cols, &row);
            } else {
                cols.poseidon2 = dummy_poseidon2;
            }
        });
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            shard.merkle_proof_record.as_ref().is_some_and(|r| r.proof.n_rows() > 0)
        }
    }
}

impl<AB> Air<AB> for MerkleTreeTraversalChip
where
    AB: SP1CoreAirBuilder + PairBuilder + GlobalBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let global_trace = builder.global();
        let global = global_trace.row_slice(0);
        let global: &MerkleTreeTraversalGlobalCols<AB::Var> = (*global).borrow();
        let main_trace = builder.main();
        let main = main_trace.row_slice(0);
        let main: &MerkleTreeTraversalMainCols<AB::Var> = (*main).borrow();

        // `is_real` is boolean.
        builder.assert_bool(global.is_real);

        // Assert that `mult in {-1, 0, 1}`.
        let mult: AB::Expr = global.mult.into();
        builder.assert_zero(
            mult.clone() * (mult.clone() - AB::Expr::one()) * (mult.clone() + AB::Expr::one()),
        );

        // `is_real == 0` enforces `mult == 0`.
        builder.when_not(global.is_real).assert_zero(global.mult);

        // `is_real == 1` enforces `mult == +-1`.
        builder.when(global.is_real).assert_zero(global.mult * global.mult - AB::Expr::one());

        // Check the input is the two child nodes.
        let perm_input = &main.poseidon2.permutation.external_rounds_state()[0];
        for i in 0..DIGEST_WIDTH {
            builder.when(global.is_real).assert_eq(perm_input[i], global.l[i]);
            builder.when(global.is_real).assert_eq(perm_input[DIGEST_WIDTH + i], global.r[i]);
        }

        // The permutation round transitions.
        for r in 0..NUM_EXTERNAL_ROUNDS {
            eval_external_round(builder, &main.poseidon2.permutation, r);
        }
        eval_internal_rounds(builder, &main.poseidon2.permutation);

        // The permutation outputs are the parent value `T`.
        let perm_output = main.poseidon2.permutation.perm_output();
        for i in 0..DIGEST_WIDTH {
            builder.when(global.is_real).assert_eq(perm_output[i], global.t[i]);
        }

        // Receive the merkle traversal interaction for the parent node.
        builder.receive_merkle_traversal(
            global.height,
            global.idx,
            global.tag1,
            global.t,
            global.mult,
            InteractionScope::Global,
        );

        // Send the merkle traversal interaction for the left child node.
        builder.send_merkle_traversal(
            global.height + AB::Expr::one(),
            global.idx * AB::Expr::two(),
            global.tag2,
            global.l,
            global.mult,
            InteractionScope::Global,
        );

        // Send the merkle traversal interaction for the right child node.
        builder.send_merkle_traversal(
            global.height + AB::Expr::one(),
            global.idx * AB::Expr::two() + AB::Expr::one(),
            global.tag3,
            global.r,
            global.mult,
            InteractionScope::Global,
        );

        // Run `IsZeroOperation`: `is_height_zero = (height == 0)`.
        IsZeroOperation::<AB::F>::eval(
            builder,
            IsZeroOperationInput::new(
                global.height.into(),
                main.is_height_zero,
                global.is_real.into(),
            ),
        );
        // Run `IsZeroOperation`: `is_child_leaf = (height == 28)`.
        IsZeroOperation::<AB::F>::eval(
            builder,
            IsZeroOperationInput::new(
                global.height.into() - AB::Expr::from_canonical_u32(28),
                main.is_child_leaf,
                global.is_real.into(),
            ),
        );
        let z = main.is_height_zero.result;
        let w = main.is_child_leaf.result;

        // If `z == 1` and `mult == 1`, then `tag1 == InitRoot == 0`
        // If `z == 0` and `mult == 1`, then `tag1 == InitInternal == 1`.
        // If `z == 1` and `mult == -1`, then `tag1 == FinalRoot == 3`.
        // If `z == 0` and `mult == -1`, then `tag1 == FinalInternal == 4`.
        // In all cases, `tag1 == (1 - z) + 3 * (1 - mult) / 2`.
        builder.when(global.is_real).assert_eq(
            global.tag1.into() * AB::Expr::two(),
            AB::Expr::from_canonical_u32(5)
                - global.mult.into() * AB::Expr::from_canonical_u32(3)
                - z.into() * AB::Expr::two(),
        );

        // If `w == 1` and `mult == 1`, then `tag2, tag3 == InitLeave or Shared == 2 or 6`.
        // If `w == 0` and `mult == 1`, then `tag2, tag3 == InitInternal or Shared == 1 or 6`.
        // If `w == 1` and `mult == -1`, then `tag2, tag3 == FinalLeave or Shared == 5 or 6`.
        // If `w == 0` and `mult == -1`, then `tag2, tag3 == FinalInternal or Shared == 4 or 6`.
        // In all cases, `tag2, tag3 == (1 + w + 3 / 2 * (1 - mult)) or 6`.
        let target = AB::Expr::from_canonical_u32(5)
            - global.mult.into() * AB::Expr::from_canonical_u32(3)
            + w.into() * AB::Expr::two();
        for tag in [global.tag2, global.tag3] {
            builder.when(global.is_real).assert_zero(
                (tag.into() * AB::Expr::two() - target.clone())
                    * (tag.into() - AB::Expr::from_canonical_u32(6)),
            );
        }

        // Check that `0 <= height < H = 29`.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::LTU as u32),
            AB::Expr::one(),
            global.height,
            AB::Expr::from_canonical_u32(29),
            global.is_real,
        );

        // Now we check that `0 <= idx < 2^height`.
        // First, set `idx_low_16` as the low 16 bits, and `idx_high` as the high bits.
        let idx_high = (global.idx.into() - main.idx_low_16.into())
            * AB::F::from_canonical_u32(1 << 16).inverse();

        // We enforce `k_hi = max(height - 16, 0)`.
        // First, check that `k_hi == 0` or `k_hi == height - 16`.
        builder.assert_zero(
            main.k_hi.into()
                * (main.k_hi.into() - (global.height.into() - AB::Expr::from_canonical_u32(16))),
        );

        // Range check that `0 <= idx_low_16 < 2^(height - k_hi)`.
        // This enforces `0 <= height - k_hi <= 16`, so `height >= 16` means `k_hi = height - 16`.
        // The later range check also enforces `0 <= k_hi <= 16`. Therefore, we have
        // `0 <= height < 16` => `k_hi == 0`, `idx_low_16 < 2^height`, `idx_high == 0`.
        // `16 <= height < 29` =>`k_hi == height - 16`, `idx_low_16 < 2^16`, `idx_high < 2^k_hi`.
        // Which shows `0 <= idx < 2^height` accordingly.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            main.idx_low_16,
            global.height.into() - main.k_hi.into(),
            AB::Expr::zero(),
            global.is_real,
        );
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            idx_high.clone(),
            main.k_hi,
            AB::Expr::zero(),
            global.is_real,
        );
    }
}
