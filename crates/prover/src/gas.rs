use std::borrow::Cow;

use enum_map::EnumMap;
use hashbrown::HashMap;
use p3_field::PrimeField32;

use sp1_core_executor::{estimator::TraceAreaEstimator, RiscvAirId};
use sp1_core_machine::shape::{CoreShapeConfig, CoreShapeError, Shapeable, ShardKind};
use sp1_stark::SplitOpts;

pub fn core_prover_gas<F: PrimeField32>(
    config: &CoreShapeConfig<F>,
    split_opts: &SplitOpts,
    precompile_local_mem_events_per_row: &HashMap<RiscvAirId, usize>,
    estimator: &TraceAreaEstimator,
) -> Result<usize, CoreShapeError> {
    // TODO(tqn) decide whether or not to implement the Packed shard estimation
    let TraceAreaEstimator { core_shards, deferred_events } = estimator;

    // Calculate and sum the cost of each core shard.
    let core_cost = core_shards
        .iter()
        .enumerate()
        .map(|(i, shard)| {
            let shape = config
                .find_shape(CoreShard {
                    shard_index: i as u32,
                    record: Cow::Borrowed(shard),
                    precompile_local_mem_events_per_row,
                })
                .unwrap();
            Ok(config.estimate_lde_size(&shape))
        })
        .sum::<Result<usize, _>>()?;

    let mut num_shards = core_shards.len();

    let mut calc_area = |record: EnumMap<RiscvAirId, u64>| {
        let shard = CoreShard {
            shard_index: num_shards as u32,
            record: Cow::Owned(record),
            precompile_local_mem_events_per_row,
        };
        let shape = config.find_shape(shard).unwrap();
        num_shards += 1;
        Ok(config.estimate_lde_size(&shape))
    };

    let precompile_area = deferred_events
        .iter()
        .map(|(id, &count)| {
            // Skip AIR if there are no events.
            if count == 0 {
                return Ok(0);
            }
            let threshold = match id {
                RiscvAirId::ShaExtend => split_opts.sha_extend,
                RiscvAirId::ShaCompress => split_opts.sha_compress,
                RiscvAirId::KeccakPermute => split_opts.keccak,
                RiscvAirId::MemoryGlobalInit | RiscvAirId::MemoryGlobalFinalize => {
                    // Process these in their own shard(s).
                    return Ok(0);
                }
                _ => split_opts.deferred,
            };
            let threshold = threshold as u64;
            let num_full_airs = count / threshold;
            let num_remainder_air_rows = count % threshold;

            let mut area = 0;

            if num_full_airs > 0 {
                area += num_full_airs as usize * calc_area([(id, threshold)].into_iter().collect())?
            }
            if num_remainder_air_rows > 0 {
                area += calc_area([(id, num_remainder_air_rows)].into_iter().collect())?
            }
            Ok(area)
        })
        .sum::<Result<usize, _>>()?;

    let global_memory_area = {
        let num_memory_global_init = deferred_events[RiscvAirId::MemoryGlobalInit];
        assert_eq!(
            num_memory_global_init,
            deferred_events[RiscvAirId::MemoryGlobalFinalize],
            "memory finalize AIR height should equal memory initialize AIR height"
        );

        let threshold = split_opts.memory as u64;
        let num_full_airs = num_memory_global_init / threshold;
        let num_remainder_air_rows = num_memory_global_init % threshold;

        let event_counts = |num_rows: u64| -> EnumMap<RiscvAirId, u64> {
            [
                (RiscvAirId::MemoryGlobalInit, num_rows),
                (RiscvAirId::MemoryGlobalFinalize, num_rows),
                (RiscvAirId::Global, 2 * num_rows),
            ]
            .into_iter()
            .collect()
        };

        let mut area = 0;
        if num_full_airs > 0 {
            area += num_full_airs as usize * calc_area(event_counts(threshold))?;
        }
        if num_remainder_air_rows > 0 {
            area += num_full_airs as usize * calc_area(event_counts(num_remainder_air_rows))?;
        }
        area
    };

    Ok(core_cost + precompile_area + global_memory_area)
}

struct CoreShard<'a> {
    shard_index: u32,
    record: Cow<'a, EnumMap<RiscvAirId, u64>>,
    precompile_local_mem_events_per_row: &'a HashMap<RiscvAirId, usize>,
}

impl<'a, F: PrimeField32> Shapeable<F> for CoreShard<'a> {
    fn kind(&self) -> ShardKind {
        let contains_cpu = self.record[RiscvAirId::Cpu] > 0;
        let contains_global_memory = self.record[RiscvAirId::MemoryGlobalInit] > 0
            || self.record[RiscvAirId::MemoryGlobalFinalize] > 0;
        match (contains_cpu, contains_global_memory) {
            (true, true) => ShardKind::PackedCore,
            (true, false) => ShardKind::Core,
            (false, true) => ShardKind::GlobalMemory,
            (false, false) => ShardKind::Precompile,
        }
    }

    fn shard(&self) -> u32 {
        self.shard_index
    }

    fn log2_shard_size(&self) -> usize {
        self.record[RiscvAirId::Cpu].next_power_of_two().ilog2() as usize
    }

    fn debug_stats(&self) -> HashMap<String, usize> {
        self.record.iter().map(|(k, &v)| (k.to_string(), v as usize)).collect()
    }

    fn core_heights(&self) -> Vec<(RiscvAirId, usize)> {
        self.record.iter().filter_map(|(k, &v)| k.is_core().then_some((k, v as usize))).collect()
    }

    fn memory_heights(&self) -> Vec<(RiscvAirId, usize)> {
        self.record.iter().filter_map(|(k, &v)| k.is_memory().then_some((k, v as usize))).collect()
    }

    fn precompile_heights(&self) -> impl Iterator<Item = (RiscvAirId, (usize, usize, usize))> {
        self.record.iter().filter_map(|(id, &num_events)| {
            // Filter precompiles.
            let num_local_mem_events = *self.precompile_local_mem_events_per_row.get(&id)?;
            let num_events = num_events as usize;
            // Skip empty events.
            (num_events > 0).then_some(())?;
            let rows = num_events * id.rows_per_event();
            let num_global_events = 2 * num_local_mem_events + num_events;
            Some((id, (rows, num_local_mem_events, num_global_events)))
        })
    }
}
