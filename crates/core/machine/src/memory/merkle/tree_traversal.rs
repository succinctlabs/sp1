use core::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};

use slop_air::{Air, AirBuilder, BaseAir, PairBuilder};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::{IndexedParallelIterator, ParallelIterator, ParallelSliceMut};
use slop_merkle_tree::batch_update::Row;
use sp1_core_executor::{ExecutionRecord, Program};
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

use crate::{air::SP1CoreAirBuilder, utils::next_multiple_of_32};

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
}

/// The columns of the [`MerkleTreeTraversalChip`].
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct MerkleTreeTraversalCols<T: Copy> {
    /// The global part of the chip.
    pub global: MerkleTreeTraversalGlobalCols<T>,

    /// The main part of the chip.
    pub main: MerkleTreeTraversalMainCols<T>,
}

/// The number of columns in the [`MerkleTreeTraversalChip`].
pub const NUM_MERKLE_TREE_TRAVERSAL_COLS: usize = size_of::<MerkleTreeTraversalCols<u8>>();

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
        NUM_MERKLE_TREE_TRAVERSAL_COLS
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

    // TODO(rkm): add accordingly once the AIRs are done
    // fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
    //     let proof = input.merkle_proof_record.as_ref().map(|r| &r.proof);
    //     let n_rows = proof.map_or(0, |p| p.n_rows());
    //     if n_rows == 0 {
    //         return;
    //     }
    // }

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

    fn main_width(&self) -> usize {
        NUM_MERKLE_TREE_TRAVERSAL_MAIN_COLS
    }

    fn generate_trace_into(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let width = <Self as MachineAir<F>>::main_width(self);
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
    AB: SP1CoreAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MerkleTreeTraversalCols<AB::Var> = (*local).borrow();

        // `is_real` is boolean.
        builder.assert_bool(local.global.is_real);

        // Assert that `mult in {-1, 0, 1}`.
        let mult: AB::Expr = local.global.mult.into();
        builder.assert_zero(
            mult.clone() * (mult.clone() - AB::Expr::one()) * (mult.clone() + AB::Expr::one()),
        );

        // `is_real == 0` enforces `mult == 0`.
        builder.when_not(local.global.is_real).assert_zero(local.global.mult);

        // `is_real == 1` enforces `mult == +-1`.
        builder
            .when(local.global.is_real)
            .assert_zero(local.global.mult * local.global.mult - AB::Expr::one());

        // Check the input is the two child nodes.
        let perm_input = &local.main.poseidon2.permutation.external_rounds_state()[0];
        for i in 0..DIGEST_WIDTH {
            builder.when(local.global.is_real).assert_eq(perm_input[i], local.global.l[i]);
            builder
                .when(local.global.is_real)
                .assert_eq(perm_input[DIGEST_WIDTH + i], local.global.r[i]);
        }

        // The permutation round transitions.
        for r in 0..NUM_EXTERNAL_ROUNDS {
            eval_external_round(builder, &local.main.poseidon2.permutation, r);
        }
        eval_internal_rounds(builder, &local.main.poseidon2.permutation);

        // The permutation outputs are the parent value `T`.
        let perm_output = local.main.poseidon2.permutation.perm_output();
        for i in 0..DIGEST_WIDTH {
            builder.when(local.global.is_real).assert_eq(perm_output[i], local.global.t[i]);
        }

        builder.receive_merkle_traversal(
            local.global.height,
            local.global.idx,
            local.global.tag1,
            local.global.t,
            local.global.mult,
            InteractionScope::Global,
        );

        builder.send_merkle_traversal(
            local.global.height + AB::Expr::one(),
            local.global.idx * AB::Expr::two(),
            local.global.tag2,
            local.global.l,
            local.global.mult,
            InteractionScope::Global,
        );

        builder.send_merkle_traversal(
            local.global.height + AB::Expr::one(),
            local.global.idx * AB::Expr::two() + AB::Expr::one(),
            local.global.tag3,
            local.global.r,
            local.global.mult,
            InteractionScope::Global,
        );

        // TODO: constrain `0 <= idx < 2^height` and `height < H`.
        // TODO: constrain the tag-validity table relating (tag1, tag2, tag3) to
        // (mult, height) — i.e. which tags each row is allowed to carry / cancel against.
    }
}
