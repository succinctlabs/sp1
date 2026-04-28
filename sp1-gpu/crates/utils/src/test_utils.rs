//! Common test utilities shared across crates.

#[cfg(any(test, feature = "test-utils"))]
pub mod random {
    use rand::{
        distributions::{Distribution, Standard},
        Rng,
    };
    use slop_air::BaseAir;
    use slop_algebra::Field;
    use slop_alloc::{Buffer, CpuBackend};
    use sp1_hypercube::{air::MachineAir, Chip};

    use crate::{JaggedTraceMle, TraceDenseData};

    /// Generate a random [`TraceDenseData`] on the CPU backend. The data does not satisfy any constraints.
    ///
    /// `chips` and `heights` are parallel slices: `heights[i]` is the row count for
    /// `chips[i]`. The dense buffer's preprocessed and main sections are each padded
    /// up to a multiple of `2^log_stacking_height` with zeros; the unpadded regions
    /// are filled with uniformly random field elements. The values are not constrained
    /// to satisfy any chip's AIR — this is only structural padding/layout.
    pub fn random_trace_dense_data<F, A, R>(
        rng: &mut R,
        chips: &[Chip<F, A>],
        heights: &[u32],
        log_stacking_height: u32,
    ) -> TraceDenseData<F, CpuBackend>
    where
        F: Field,
        A: MachineAir<F>,
        Standard: Distribution<F>,
        R: Rng,
    {
        assert_eq!(chips.len(), heights.len(), "chips and heights must be the same length");

        let names: Vec<&str> = chips.iter().map(|c| c.air.name()).collect();
        let prep_widths: Vec<usize> = chips.iter().map(|c| c.preprocessed_width()).collect();
        let main_widths: Vec<usize> = chips.iter().map(|c| c.width()).collect();
        let heights_usize: Vec<usize> = heights.iter().map(|&h| h as usize).collect();

        let stacking = 1usize << log_stacking_height;
        let total_preprocessed: usize =
            prep_widths.iter().zip(&heights_usize).map(|(w, h)| w * h).sum();
        let total_main: usize = main_widths.iter().zip(&heights_usize).map(|(w, h)| w * h).sum();
        let padded_preprocessed = total_preprocessed.next_multiple_of(stacking);
        let padded_main = total_main.next_multiple_of(stacking);

        let mut data = vec![F::zero(); padded_preprocessed + padded_main];
        for slot in &mut data[..total_preprocessed] {
            *slot = rng.sample(Standard);
        }
        for slot in &mut data[padded_preprocessed..padded_preprocessed + total_main] {
            *slot = rng.sample(Standard);
        }

        TraceDenseData::from_chip_layout(
            Buffer::from(data),
            &names,
            &prep_widths,
            &main_widths,
            &heights_usize,
            log_stacking_height,
        )
    }

    /// Generate a random [`JaggedTraceMle`] whose total dense size (preprocessed +
    /// main, before stacking-height padding) is approximately `total_area` field
    /// elements, partitioned randomly among `chips`.
    ///
    /// Per-chip row counts are multiples of 4 (matching the alignment downstream
    /// jagged code expects). Allocation greedily picks a random fitting chip and
    /// assigns it a random number of 4-row blocks until no chip fits in the
    /// remaining budget; any remainder smaller than the smallest chip's row cost
    /// is discarded.
    pub fn random_jagged_trace_mle<F, A, R>(
        rng: &mut R,
        chips: &[Chip<F, A>],
        total_area: u64,
        log_stacking_height: u32,
    ) -> JaggedTraceMle<F, CpuBackend>
    where
        F: Field,
        A: MachineAir<F>,
        Standard: Distribution<F>,
        R: Rng,
    {
        assert!(!chips.is_empty(), "must have at least one chip");

        // Heights are multiples of 4 — required so that `column_heights = height/2`
        // is even and matches the `height.div_ceil(4) * 2` pattern in
        // `next_start_indices_and_column_heights`.
        const ALIGN: u32 = 4;

        // Cost per row: each row contributes `preprocessed_width + width` field
        // elements to the dense buffer.
        let widths: Vec<u64> =
            chips.iter().map(|c| (c.preprocessed_width() + c.width()) as u64).collect();

        let mut heights = vec![0u32; chips.len()];
        let mut remaining = total_area;
        loop {
            let candidates: Vec<usize> =
                (0..chips.len()).filter(|&i| widths[i] * ALIGN as u64 <= remaining).collect();
            if candidates.is_empty() {
                break;
            }
            let i = candidates[rng.gen_range(0..candidates.len())];
            let max_blocks = remaining / (widths[i] * ALIGN as u64);
            let blocks = rng.gen_range(1..=max_blocks);
            heights[i] += blocks as u32 * ALIGN;
            remaining -= blocks * widths[i] * ALIGN as u64;
        }

        let dense = random_trace_dense_data(rng, chips, &heights, log_stacking_height);
        build_jagged_trace_mle(dense, chips, &heights)
    }

    /// Build the jagged column index / start index / column heights buffers around
    /// a [`TraceDenseData`] following the layout used in zerocheck's reference
    /// `get_input`: one column per chip column for both preprocessed and main, plus
    /// a single padding column for each section that has nonzero padding.
    fn build_jagged_trace_mle<F, A>(
        dense: TraceDenseData<F, CpuBackend>,
        chips: &[Chip<F, A>],
        heights: &[u32],
    ) -> JaggedTraceMle<F, CpuBackend>
    where
        F: Field,
        A: MachineAir<F>,
    {
        let total_dense = dense.dense.len() as u32;
        let preprocessed_padding = dense.preprocessed_padding as u32;
        let main_padding = dense.main_padding as u32;

        let num_data_cols: u32 =
            chips.iter().map(|c| (c.preprocessed_width() + c.width()) as u32).sum();
        let mut num_cols = num_data_cols;
        if preprocessed_padding > 0 {
            num_cols += 1;
        }
        if main_padding > 0 {
            num_cols += 1;
        }

        let mut col_index = vec![0u32; (total_dense / 2) as usize];
        let mut start_idx = vec![0u32; (num_cols + 1) as usize];
        let mut column_heights: Vec<u32> = Vec::with_capacity(num_cols as usize);

        let mut col = 0u32;
        let mut cnt: usize = 0;

        let mut emit_col = |w: u32, h: u32, col: &mut u32, cnt: &mut usize| {
            for _ in 0..w {
                let half = (h / 2) as usize;
                col_index[*cnt..*cnt + half].fill(*col);
                *cnt += half;
                start_idx[(*col + 1) as usize] = start_idx[*col as usize] + h / 2;
                column_heights.push(h / 2);
                *col += 1;
            }
        };

        for (chip, &h) in chips.iter().zip(heights) {
            emit_col(chip.preprocessed_width() as u32, h, &mut col, &mut cnt);
        }
        if preprocessed_padding > 0 {
            emit_col(1, preprocessed_padding, &mut col, &mut cnt);
        }
        for (chip, &h) in chips.iter().zip(heights) {
            emit_col(chip.width() as u32, h, &mut col, &mut cnt);
        }
        if main_padding > 0 {
            emit_col(1, main_padding, &mut col, &mut cnt);
        }

        debug_assert_eq!(cnt, (total_dense / 2) as usize);
        debug_assert_eq!(col, num_cols);

        JaggedTraceMle::new(dense, Buffer::from(col_index), Buffer::from(start_idx), column_heights)
    }
}
