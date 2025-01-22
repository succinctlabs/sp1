use enum_map::EnumMap;
use hashbrown::HashMap;
use sp1_stark::SP1CoreOpts;

use crate::RiscvAirId;

const BYTE_NUM_ROWS: u64 = 1 << 16;

#[derive(Default, Clone)]
pub struct TraceAreaEstimator {
    pub core_area: u64,
    pub deferred_events: EnumMap<RiscvAirId, u64>,
}

impl TraceAreaEstimator {
    /// An estimate of the total trace area required for the core proving stage.
    /// This provides a prover gas metric.
    pub fn total_trace_area(
        &self,
        program_len: usize,
        costs: &HashMap<RiscvAirId, u64>,
        opts: &SP1CoreOpts,
    ) -> u64 {
        let deferred_area = self
            .deferred_events
            .iter()
            .map(|(id, &count)| {
                let (rows_per_event, threshold) = match id {
                    RiscvAirId::ShaExtend => (48, opts.split_opts.sha_extend),
                    RiscvAirId::ShaCompress => (80, opts.split_opts.sha_compress),
                    RiscvAirId::KeccakPermute => (24, opts.split_opts.keccak),
                    RiscvAirId::MemoryGlobalInit | RiscvAirId::MemoryGlobalFinalize => {
                        (1, opts.split_opts.memory)
                    }
                    _ => (1, opts.split_opts.deferred),
                };
                let threshold = threshold as u64;
                let rows = count * rows_per_event;
                let num_full_airs = rows / threshold;
                let num_remainder_air_rows = rows % threshold;
                let num_padded_rows = num_full_airs * threshold.next_power_of_two()
                    + num_remainder_air_rows.next_power_of_two();
                // The costs already seem to include the `rows_per_event` factor.
                let cost_per_row = costs[&id] / rows_per_event;
                cost_per_row * num_padded_rows
            })
            .sum::<u64>();

        let byte_area = BYTE_NUM_ROWS * costs[&RiscvAirId::Byte];

        // // Compute the program chip contribution.
        let program_area = program_len as u64 * costs[&RiscvAirId::Program];

        self.core_area + deferred_area + byte_area + program_area
    }

    /// Mark the end of a shard. Estimates the area of core AIRs and defers appropriate counts.
    pub(crate) fn flush_shard(
        &mut self,
        event_counts: &EnumMap<RiscvAirId, u64>,
        costs: &HashMap<RiscvAirId, u64>,
    ) {
        for (id, count) in event_counts {
            if id.is_deferred() {
                self.deferred_events[id] += count;
            } else {
                self.core_area += costs[&id] * count.next_power_of_two();
            }
        }
    }
}
