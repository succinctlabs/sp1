//! Common test utilities shared across crates.

#[cfg(any(test, feature = "test-utils"))]
pub mod random {
    use std::path::Path;

    use rand::{
        distributions::{Distribution, Standard},
        Rng,
    };
    use serde::Deserialize;
    use slop_air::BaseAir;
    use slop_algebra::Field;
    use slop_alloc::{Buffer, CpuBackend};
    use sp1_hypercube::{air::MachineAir, Chip};

    use crate::{AbstractChipLayout, JaggedTraceMle};

    //
    // Helpers
    //

    impl AbstractChipLayout {
        /// Build an `AbstractChipLayout` from a slice of `Chip`s, reading each chip's
        /// name and preprocessed/main widths.
        pub fn from_chips<F, A>(chips: &[Chip<F, A>]) -> Self
        where
            F: Field,
            A: MachineAir<F>,
        {
            Self(
                chips
                    .iter()
                    .map(|c| (c.air.name().to_string(), c.preprocessed_width(), c.width()))
                    .collect(),
            )
        }
    }

    /// One chip's entry in the JSON file consumed by [`read_layout_from_json`].
    #[derive(Deserialize)]
    struct ChipEntry {
        name: String,
        preprocessed_width: usize,
        main_width: usize,
        height: usize,
    }

    /// Read an [`AbstractChipLayout`] and matching per-chip heights from a JSON file.
    ///
    /// The file must be a top-level JSON array of objects, each with the fields
    /// `name`, `preprocessed_width`, `main_width`, and `height`:
    ///
    /// ```json
    /// [
    ///   {"name": "Cpu",    "preprocessed_width": 4, "main_width": 64, "height": 1024},
    ///   {"name": "Memory", "preprocessed_width": 0, "main_width": 32, "height": 512}
    /// ]
    /// ```
    pub fn read_layout_from_json(
        path: impl AsRef<Path>,
    ) -> std::io::Result<(AbstractChipLayout, Vec<usize>)> {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let entries: Vec<ChipEntry> = serde_json::from_reader(reader)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let layout = AbstractChipLayout(
            entries.iter().map(|e| (e.name.clone(), e.preprocessed_width, e.main_width)).collect(),
        );
        let heights = entries.into_iter().map(|e| e.height).collect();
        Ok((layout, heights))
    }

    /// Randomly partition `total_area` field elements among the chips in `layout`,
    /// returning a per-chip row count.
    ///
    /// Every chip is guaranteed at least one 4-row block; downstream consumers like
    /// `round_batch_evaluations` walk the column index expecting one evaluation per
    /// non-zero-height column and underflow if any chip is left empty. Panics if
    /// `total_area` is too small to give every chip its minimum allocation.
    ///
    /// Heights are multiples of 4 (required so that `column_heights = height/2` is
    /// even and matches the `height.div_ceil(4) * 2` pattern in
    /// `next_start_indices_and_column_heights`). After the floor allocation, the
    /// remaining budget is distributed greedily: pick a random fitting chip and
    /// give it a random number of 4-row blocks until no chip fits in the leftover.
    pub fn generate_random_heights<R: Rng>(
        rng: &mut R,
        layout: &AbstractChipLayout,
        total_area: u64,
    ) -> Vec<usize> {
        const ALIGN: usize = 4;

        // Cost per row: each row contributes `preprocessed_width + width` field
        // elements to the dense buffer.
        let row_costs: Vec<u64> = layout.0.iter().map(|(_, p, m)| (p + m) as u64).collect();

        // Floor: every chip gets one 4-row block up front so no chip is left at h=0.
        let min_total: u64 = row_costs.iter().sum::<u64>() * ALIGN as u64;
        assert!(
            total_area >= min_total,
            "total_area = {total_area} is too small to give every chip {ALIGN} rows \
             (need at least {min_total})",
        );

        let mut heights = vec![ALIGN; layout.0.len()];
        let mut remaining = total_area - min_total;
        loop {
            let candidates: Vec<usize> =
                (0..layout.0.len()).filter(|&i| row_costs[i] * ALIGN as u64 <= remaining).collect();
            if candidates.is_empty() {
                break;
            }
            let i = candidates[rng.gen_range(0..candidates.len())];
            let max_blocks = remaining / (row_costs[i] * ALIGN as u64);
            let blocks = rng.gen_range(1..=max_blocks);
            heights[i] += blocks as usize * ALIGN;
            remaining -= blocks * row_costs[i] * ALIGN as u64;
        }
        heights
    }

    /// Allocate a `padded_preprocessed + padded_main`-sized buffer of `F::zero()` and
    /// scribble uniformly-random field elements into the unpadded preprocessed and
    /// main regions, leaving the padding zero. The returned values do not satisfy
    /// any chip's AIR — this is purely structural.
    pub fn random_dense_buffer<F, R>(
        rng: &mut R,
        layout: &AbstractChipLayout,
        heights: &[usize],
        log_stacking_height: u32,
    ) -> Vec<F>
    where
        F: Field,
        Standard: Distribution<F>,
        R: Rng,
    {
        let stacking = 1usize << log_stacking_height;
        let total_preprocessed: usize =
            layout.0.iter().zip(heights).map(|((_, p, _), h)| p * h).sum();
        let total_main: usize = layout.0.iter().zip(heights).map(|((_, _, m), h)| m * h).sum();
        let padded_preprocessed = total_preprocessed.next_multiple_of(stacking);
        let padded_main = total_main.next_multiple_of(stacking);

        let mut data = vec![F::zero(); padded_preprocessed + padded_main];
        for slot in &mut data[..total_preprocessed] {
            *slot = rng.sample(Standard);
        }
        for slot in &mut data[padded_preprocessed..padded_preprocessed + total_main] {
            *slot = rng.sample(Standard);
        }
        data
    }

    //
    // Public random generators
    //

    /// Generate a random [`JaggedTraceMle`] for the given `layout` and per-chip row
    /// counts. The dense buffer is filled with uniformly-random field elements in
    /// the unpadded regions; padding regions are zero.   
    ///
    /// Requires log_stacking_height as an input to compute padding for the preprocessed and main regions.
    pub fn random_jagged_trace_mle_from_layout<F, R>(
        rng: &mut R,
        layout: &AbstractChipLayout,
        heights: &[usize],
        log_stacking_height: u32,
    ) -> JaggedTraceMle<F, CpuBackend>
    where
        F: Field,
        Standard: Distribution<F>,
        R: Rng,
    {
        let data = random_dense_buffer(rng, layout, heights, log_stacking_height);
        JaggedTraceMle::from_chip_layout(Buffer::from(data), layout, heights, log_stacking_height)
    }

    /// Generate a random [`JaggedTraceMle`] whose total dense size (preprocessed +
    /// main, before stacking-height padding) is approximately `total_area` field
    /// elements, partitioned randomly among `chips` via [`generate_random_heights`].
    ///
    /// Requires log_stacking_height as an input to compute padding for the preprocessed and main regions.
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

        let layout = AbstractChipLayout::from_chips(chips);
        let heights = generate_random_heights(rng, &layout, total_area);
        random_jagged_trace_mle_from_layout(rng, &layout, &heights, log_stacking_height)
    }

    /// Read a chip layout and per-chip heights from a JSON file (see
    /// [`read_layout_from_json`] for the schema) and produce a random
    /// [`JaggedTraceMle`] with that shape.
    ///
    /// Requires log_stacking_height as an input to compute padding for the preprocessed and main regions.
    pub fn random_jagged_trace_mle_from_json<F, R>(
        rng: &mut R,
        path: impl AsRef<Path>,
        log_stacking_height: u32,
    ) -> std::io::Result<JaggedTraceMle<F, CpuBackend>>
    where
        F: Field,
        Standard: Distribution<F>,
        R: Rng,
    {
        let (layout, heights) = read_layout_from_json(path)?;
        Ok(random_jagged_trace_mle_from_layout(rng, &layout, &heights, log_stacking_height))
    }
}
