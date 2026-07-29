use core::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};

use hashbrown::HashMap;
use itertools::Itertools;
use slop_air::{Air, AirBuilder, BaseAir, GlobalBuilder, PairBuilder};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::*;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode, ExecutionRecord, Program,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{AirInteraction, InteractionScope, MachineAir},
    operations::poseidon2::{
        air::{eval_external_round, eval_internal_rounds},
        permutation::Poseidon2Cols,
        trace::populate_perm_deg3,
        Poseidon2Operation, NUM_EXTERNAL_ROUNDS, WIDTH,
    },
    InteractionKind, Word,
};
use sp1_jit::MERKLE_PAGE_WORDS;

use crate::{
    air::{SP1CoreAirBuilder, SP1Operation},
    operations::{IsZeroOperation, IsZeroOperationInput},
    utils::next_multiple_of_32,
};

/// The sponge rate.
pub const RATE: usize = 8;

/// The digest width (`OUT` of the sponge), in field elements.
pub const DIGEST_WIDTH: usize = 8;

/// Number of `u64` words packed into one `RATE`-sized block.
pub const WORDS_PER_BLOCK: usize = 3;

/// Number of permutations (rows) per page hash: `ceil(256 / 3) = 86`.
pub const BLOCKS_PER_HASH: usize = MERKLE_PAGE_WORDS.div_ceil(WORDS_PER_BLOCK);

/// The global columns of the [`LeafHashChip`].
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct LeafHashGlobalCols<T: Copy> {
    /// The page id.
    pub page_id: T,

    /// The page id's bits[0..5].
    pub page_id_0_5: T,

    /// The page id's bits[5..21].
    pub page_id_5_21: T,

    /// The page_ id's bits[21..29]
    pub page_id_21_29: T,

    /// If this hash is for the initial state or final state.
    pub is_init: T,

    /// The offset within the page.
    pub offset: T,

    /// The increment per address.
    pub step: T,

    /// The block index within the page hash.
    pub block: T,

    /// If the block index is less than 10.
    pub block_lt_10: T,

    /// If the block index is less than 11.
    pub block_lt_11: T,

    /// If this block is for the final permutation.
    pub is_last_block: T,

    /// The signed multiplicity of the memory interaction.
    pub memory_multiplicity: [T; 3],

    /// The value of the first word.
    pub value_1: Word<T>,

    /// The timestamp for the first word, as `[high, low]`.
    pub timestamp_1: [T; 2],

    /// The value of the second word.
    pub value_2: Word<T>,

    /// The timestamp for the second word, as `[high, low]`.
    pub timestamp_2: [T; 2],

    /// The byte form value of the third word.
    pub value_3: [T; 8],

    /// The timestamp for the third word, as `[high, low]`.
    pub timestamp_3: [T; 2],

    /// Indicator that `page_id == 0` (a register page), driving the reality/stride pattern.
    pub is_page_id_zero: IsZeroOperation<T>,

    /// Whether this row is padding or not.
    pub is_real: T,
}

/// The main columns of the [`LeafHashChip`].
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct LeafHashMainCols<T: Copy> {
    /// The Poseidon2 permutation for this block.
    pub poseidon2: Poseidon2Operation<T>,

    /// The 8 element capacity.
    pub state_in: [T; DIGEST_WIDTH],

    /// Indicator that `block == BLOCKS_PER_HASH - 1` (the final permutation of the page hash).
    pub is_last_block_check: IsZeroOperation<T>,
}

/// The number of global columns in the [`LeafHashChip`].
pub const NUM_LEAF_HASH_GLOBAL_COLS: usize = size_of::<LeafHashGlobalCols<u8>>();

/// The number of main columns in the [`LeafHashChip`].
pub const NUM_LEAF_HASH_MAIN_COLS: usize = size_of::<LeafHashMainCols<u8>>();

/// The leaf-hash chip (see the module docs).
#[derive(Default)]
pub struct LeafHashChip;

impl LeafHashChip {
    /// Create a new [`LeafHashChip`].
    pub const fn new() -> Self {
        Self
    }
}

impl<F> BaseAir<F> for LeafHashChip {
    fn width(&self) -> usize {
        NUM_LEAF_HASH_MAIN_COLS
    }
}

/// Bit-pack one block of 3 `u64` into `RATE` field elements.
#[inline]
fn pack_block<F: PrimeField32>(e1: u64, e2: u64, e3: u64) -> [F; RATE] {
    core::array::from_fn(|j| {
        let lane = if j < 4 { (e1 >> (16 * j)) & 0xFFFF } else { (e2 >> (16 * (j - 4))) & 0xFFFF };
        let byte = (e3 >> (8 * j)) & 0xFF;
        F::from_canonical_u32(((lane as u32) << 8) | byte as u32)
    })
}

impl LeafHashChip {
    /// The `[u64; 256]` pages to hash.
    pub(crate) fn pages_to_hash(input: &ExecutionRecord) -> Vec<&[u64; MERKLE_PAGE_WORDS]> {
        input
            .merkle_proof_record
            .as_ref()
            .map(|r| {
                r.payload
                    .pages
                    .iter()
                    .flat_map(|p| [&p.initial_contents, &p.final_values])
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl<F: PrimeField32> MachineAir<F> for LeafHashChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "LeafHash"
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = Self::pages_to_hash(input).len() * BLOCKS_PER_HASH;
        let size_log2 = input.fixed_log2_rows::<F, Self>(self);
        Some(next_multiple_of_32(nb_rows, size_log2))
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let payload = match input.merkle_proof_record.as_ref() {
            Some(r) => &r.payload,
            None => return,
        };
        let n_hashes = payload.pages.len() * 2;
        if n_hashes == 0 {
            return;
        }
        let hashes = Self::pages_to_hash(input);
        let chunk_size = std::cmp::max(n_hashes / num_cpus::get(), 1);
        let blu_batches = (0..n_hashes)
            .into_par_iter()
            .chunks(chunk_size)
            .map(|hs| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                for h in hs {
                    let page_id = payload.page_ids[h / 2];
                    let page = hashes[h];
                    for b in 0..BLOCKS_PER_HASH {
                        blu.add_bit_range_check((page_id & 0x1F) as u16, 5);
                        blu.add_bit_range_check(((page_id >> 5) & 0xFFFF) as u16, 16);
                        blu.add_bit_range_check(((page_id >> 21) & 0xFF) as u16, 8);
                        blu.add_byte_lookup_event(ByteLookupEvent {
                            opcode: ByteOpcode::LTU,
                            a: 1,
                            b: b as u8,
                            c: BLOCKS_PER_HASH as u8,
                        });
                        blu.add_byte_lookup_event(ByteLookupEvent {
                            opcode: ByteOpcode::LTU,
                            a: (b < 11) as u16,
                            b: b as u8,
                            c: 11,
                        });
                        blu.add_byte_lookup_event(ByteLookupEvent {
                            opcode: ByteOpcode::LTU,
                            a: (b < 10) as u16,
                            b: b as u8,
                            c: 10,
                        });

                        let base = b * WORDS_PER_BLOCK;
                        let e1 = page[base];
                        let e2 = page.get(base + 1).copied().unwrap_or(0);
                        let e3 = page.get(base + 2).copied().unwrap_or(0);
                        blu.add_u16_range_checks_field(&Word::<F>::from(e1).0);
                        blu.add_u16_range_checks_field(&Word::<F>::from(e2).0);
                        blu.add_u8_range_checks(&e3.to_le_bytes());
                    }
                }
                blu
            })
            .collect::<Vec<_>>();
        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
    }

    fn global_width(&self) -> usize {
        NUM_LEAF_HASH_GLOBAL_COLS
    }

    fn generate_global_trace_into(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let width = <Self as MachineAir<F>>::global_width(self);
        let padded_nb_rows = <Self as MachineAir<F>>::num_rows(self, input).unwrap();
        let payload = input.merkle_proof_record.as_ref().map(|r| &r.payload);
        let hashes = Self::pages_to_hash(input);
        let real_rows = hashes.len() * BLOCKS_PER_HASH;

        unsafe {
            core::ptr::write_bytes(buffer.as_mut_ptr(), 0, padded_nb_rows * width);
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, padded_nb_rows * width) };

        values[..real_rows * width].par_chunks_mut(BLOCKS_PER_HASH * width).enumerate().for_each(
            |(h, segment)| {
                let page = hashes[h];
                let page_idx = h / 2;
                let page_id = payload.unwrap().page_ids[page_idx];
                let is_init = h % 2 == 0;
                let last_clk = &payload.unwrap().pages[page_idx].last_clk;
                for (b, row) in segment.chunks_exact_mut(width).enumerate() {
                    let base = b * WORDS_PER_BLOCK;
                    let e1 = page[base];
                    let e2 = page.get(base + 1).copied().unwrap_or(0);
                    let e3 = page.get(base + 2).copied().unwrap_or(0);
                    let e3_bytes = e3.to_le_bytes();

                    let cols: &mut LeafHashGlobalCols<F> = row.borrow_mut();
                    cols.page_id = F::from_canonical_u32(page_id);
                    cols.is_init = F::from_bool(is_init);
                    cols.block = F::from_canonical_usize(b);
                    cols.value_1 = Word::from(e1);
                    cols.value_2 = Word::from(e2);
                    cols.value_3 = core::array::from_fn(|j| F::from_canonical_u8(e3_bytes[j]));
                    if !is_init {
                        let split = |clk: u64| {
                            [
                                F::from_canonical_u32((clk >> 24) as u32),
                                F::from_canonical_u32((clk & 0xFFFFFF) as u32),
                            ]
                        };
                        cols.timestamp_1 = split(last_clk[base]);
                        cols.timestamp_2 = split(last_clk.get(base + 1).copied().unwrap_or(0));
                        cols.timestamp_3 = split(last_clk.get(base + 2).copied().unwrap_or(0));
                    }
                    cols.is_last_block = F::from_canonical_u32((b == 85) as u32);

                    cols.page_id_0_5 = F::from_canonical_u32(page_id & 0x1F);
                    cols.page_id_5_21 = F::from_canonical_u32((page_id >> 5) & 0xFFFF);
                    cols.page_id_21_29 = F::from_canonical_u32((page_id >> 21) & 0xFF);

                    let is_reg = page_id == 0;
                    cols.offset = F::from_canonical_usize(if is_reg { b } else { 8 * b });
                    cols.step = F::from_canonical_u32(if is_reg { 1 } else { 8 });
                    cols.block_lt_10 = F::from_bool(b < 10);
                    cols.block_lt_11 = F::from_bool(b < 11);
                    let real =
                        if is_reg { [b < 11, b < 11, b < 10] } else { [true, b != 85, b != 85] };
                    let sign = if is_init { F::one() } else { F::neg_one() };
                    cols.memory_multiplicity =
                        core::array::from_fn(|k| if real[k] { sign } else { F::zero() });

                    cols.is_page_id_zero.populate(page_id as u64);
                    cols.is_real = F::one();
                }
            },
        );
    }

    fn generate_trace_into(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let width = <Self as BaseAir<F>>::width(self);
        let padded_nb_rows = <Self as MachineAir<F>>::num_rows(self, input).unwrap();
        let hashes = Self::pages_to_hash(input);
        let real_rows = hashes.len() * BLOCKS_PER_HASH;

        unsafe {
            let padding_start = real_rows * width;
            let padding_size = (padded_nb_rows - real_rows) * width;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let dummy = populate_perm_deg3::<F>([F::zero(); WIDTH], None);

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, padded_nb_rows * width) };

        values[..real_rows * width].par_chunks_mut(BLOCKS_PER_HASH * width).enumerate().for_each(
            |(h, segment)| {
                let page = hashes[h];
                let mut state = [F::zero(); WIDTH];
                for (b, row) in segment.chunks_exact_mut(width).enumerate() {
                    let state_in = state;
                    let base = b * WORDS_PER_BLOCK;
                    let e1 = page[base];
                    let e2 = page.get(base + 1).copied().unwrap_or(0);
                    let e3 = page.get(base + 2).copied().unwrap_or(0);

                    state[..RATE].copy_from_slice(&pack_block::<F>(e1, e2, e3));
                    let op = populate_perm_deg3(state, None);
                    state = *op.permutation.perm_output();

                    let cols: &mut LeafHashMainCols<F> = row.borrow_mut();
                    cols.poseidon2 = op;
                    cols.state_in = state_in[8..16].try_into().unwrap();
                    cols.is_last_block_check.populate_from_field_element(
                        F::from_canonical_usize(b) - F::from_canonical_usize(BLOCKS_PER_HASH - 1),
                    );
                }
            },
        );

        values[real_rows * width..].par_chunks_mut(width).for_each(|row| {
            let cols: &mut LeafHashMainCols<F> = row.borrow_mut();
            cols.poseidon2 = dummy;
        });
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !Self::pages_to_hash(shard).is_empty()
        }
    }
}

impl<AB> Air<AB> for LeafHashChip
where
    AB: SP1CoreAirBuilder + PairBuilder + GlobalBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let global_trace = builder.global();
        let global = global_trace.row_slice(0);
        let global: &LeafHashGlobalCols<AB::Var> = (*global).borrow();
        let main_trace = builder.main();
        let main = main_trace.row_slice(0);
        let main: &LeafHashMainCols<AB::Var> = (*main).borrow();

        // `is_real` is boolean.
        builder.assert_bool(global.is_real);
        // `is_init` is boolean.
        builder.assert_bool(global.is_init);
        // `is_last_block` is boolean.
        builder.assert_bool(global.is_last_block);
        // `is_real == 0` => `is_init == 0`.
        builder.when_not(global.is_real).assert_zero(global.is_init);
        // `is_real == 0` => `is_last_block == 0`.
        builder.when_not(global.is_real).assert_zero(global.is_last_block);

        // Constrain `is_last_block == (block == BLOCKS_PER_HASH - 1)`.
        IsZeroOperation::<AB::F>::eval(
            builder,
            IsZeroOperationInput::new(
                global.block.into() - AB::Expr::from_canonical_usize(BLOCKS_PER_HASH - 1),
                main.is_last_block_check,
                global.is_real.into(),
            ),
        );
        builder
            .when(global.is_real)
            .assert_eq(global.is_last_block, main.is_last_block_check.result);

        // Constrain `0 <= block < BLOCKS_PER_HASH`.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::LTU as u32),
            AB::Expr::one(),
            global.block,
            AB::Expr::from_canonical_usize(BLOCKS_PER_HASH),
            global.is_real,
        );

        // On init, the timestamps are zero.
        for ts in [global.timestamp_1, global.timestamp_2, global.timestamp_3] {
            builder.when(global.is_init).assert_zero(ts[0]);
            builder.when(global.is_init).assert_zero(ts[1]);
        }

        // Decompose `page_id` into the (5, 16, 8)-bit limbs and range check.
        builder.assert_eq(
            global.page_id.into(),
            global.page_id_0_5.into()
                + global.page_id_5_21.into() * AB::Expr::from_canonical_u32(1 << 5)
                + global.page_id_21_29.into() * AB::Expr::from_canonical_u32(1 << 21),
        );
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            global.page_id_0_5,
            AB::Expr::from_canonical_u32(5),
            AB::Expr::zero(),
            global.is_real,
        );
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            global.page_id_5_21,
            AB::Expr::from_canonical_u32(16),
            AB::Expr::zero(),
            global.is_real,
        );
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            global.page_id_21_29,
            AB::Expr::from_canonical_u32(8),
            AB::Expr::zero(),
            global.is_real,
        );

        // Range check `value_1, value_2, value_3` accordingly.
        builder.slice_range_check_u16(&global.value_1.0, global.is_real);
        builder.slice_range_check_u16(&global.value_2.0, global.is_real);
        builder.slice_range_check_u8(&global.value_3, global.is_real);

        // Constrain `is_reg = [page_id == 0]`.
        IsZeroOperation::<AB::F>::eval(
            builder,
            IsZeroOperationInput::new(
                global.page_id.into(),
                global.is_page_id_zero,
                global.is_real.into(),
            ),
        );
        let is_reg: AB::Expr = global.is_page_id_zero.result.into();

        // Constrain `block_lt_11 = [block < 11]`.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::LTU as u32),
            global.block_lt_11,
            global.block,
            AB::Expr::from_canonical_u32(11),
            global.is_real,
        );
        // Constrain `block_lt_10 = [block < 10]`.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::LTU as u32),
            global.block_lt_10,
            global.block,
            AB::Expr::from_canonical_u32(10),
            global.is_real,
        );

        // If `is_reg` is true, `step == 1`. If not, `step == 8`.
        // Therefore, `step == 8 - 7 * is_reg`.
        let one = AB::Expr::one();
        builder.when(global.is_real).assert_eq(
            global.step.into(),
            AB::Expr::from_canonical_u32(8) - is_reg.clone() * AB::Expr::from_canonical_u32(7),
        );
        // Constrain that `offset = block * step`.
        builder
            .when(global.is_real)
            .assert_eq(global.offset.into(), global.block.into() * global.step.into());

        // The multiplicity is equal to the following.
        // If `is_reg == 1`, `[block_lt_11, block_lt_11, block_lt_10]`.
        // If `is_reg == 0`, `[1, 1 - is_last_block, 1 - is_last_block]`.
        // This is with sign `2 * is_init - 1`, `+1` for init, `-1` for finalize.
        let block_lt_10: AB::Expr = global.block_lt_10.into();
        let block_lt_11: AB::Expr = global.block_lt_11.into();
        let is_last: AB::Expr = global.is_last_block.into();
        let real = [
            is_reg.clone() * block_lt_11.clone() + (global.is_real - is_reg.clone()),
            is_reg.clone() * block_lt_11
                + (global.is_real - is_reg.clone()) * (global.is_real - is_last.clone()),
            is_reg.clone() * block_lt_10 + (global.is_real - is_reg) * (global.is_real - is_last),
        ];
        let sign = global.is_init.into() * AB::Expr::two() - one;
        for (k, real_k) in real.into_iter().enumerate() {
            builder
                .when(global.is_real)
                .assert_eq(global.memory_multiplicity[k].into() * sign.clone(), real_k);
            // If `is_real` is false, then the multiplicities are all zero.
            builder.when_not(global.is_real).assert_zero(global.memory_multiplicity[k]);
        }

        // The permutation round transitions.
        for r in 0..NUM_EXTERNAL_ROUNDS {
            eval_external_round(builder, &main.poseidon2.permutation, r);
        }
        eval_internal_rounds(builder, &main.poseidon2.permutation);

        // The capacity is carried from the incoming state into the permutation input.
        let perm_input = &main.poseidon2.permutation.external_rounds_state()[0];
        for i in 0..8 {
            builder.assert_eq(perm_input[i + 8], main.state_in[i]);
        }

        // The rate is from the word values.
        for i in 0..4 {
            builder.assert_eq(
                perm_input[i],
                global.value_1[i] * AB::Expr::from_canonical_u32(1 << 8) + global.value_3[i],
            );
            builder.assert_eq(
                perm_input[i + 4],
                global.value_2[i] * AB::Expr::from_canonical_u32(1 << 8) + global.value_3[i + 4],
            );
        }

        // Receive the incoming state.
        builder.receive_leaf_hash(
            global.page_id,
            global.is_init,
            global.block,
            main.state_in,
            global.is_real,
            InteractionScope::Local,
        );
        // Send the output state, for the case where this isn't the last permutation.
        builder.send_leaf_hash(
            global.page_id,
            global.is_init,
            global.block + AB::Expr::one(),
            main.poseidon2.permutation.perm_output()[8..16].try_into().unwrap(),
            global.is_real - global.is_last_block,
            InteractionScope::Local,
        );
        // Send the output state, for the case where this is the last permutation.
        builder.send_leaf_hash(
            global.page_id,
            global.is_init,
            global.block + AB::Expr::one(),
            main.poseidon2.permutation.perm_output()[0..8].try_into().unwrap(),
            global.is_last_block,
            InteractionScope::Local,
        );

        // Handle the memory interactions accordingly.
        let words: [[AB::Expr; 4]; 3] = [
            global.value_1.0.map(Into::into),
            global.value_2.0.map(Into::into),
            core::array::from_fn(|m| {
                global.value_3[2 * m]
                    + global.value_3[2 * m + 1] * AB::Expr::from_canonical_u32(256)
            }),
        ];
        let timestamps = [global.timestamp_1, global.timestamp_2, global.timestamp_3];
        let base_addr = global.offset * AB::Expr::from_canonical_u32(3)
            + global.page_id_0_5 * AB::Expr::from_canonical_u32(1 << 11);
        for k in 0..3 {
            let mut values: Vec<AB::Expr> = vec![timestamps[k][0].into(), timestamps[k][1].into()];
            values.push(base_addr.clone() + global.step * AB::Expr::from_canonical_u32(k as u32));
            values.push(global.page_id_5_21.into());
            values.push(global.page_id_21_29.into());
            values.extend(words[k].clone());
            builder.send(
                AirInteraction::new(
                    values,
                    global.memory_multiplicity[k].into(),
                    InteractionKind::Memory,
                ),
                InteractionScope::Global,
            );
        }
    }
}
