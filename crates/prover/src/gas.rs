use std::{borrow::Cow, iter};

use enum_map::EnumMap;
use hashbrown::HashMap;
use p3_field::PrimeField32;

use sp1_core_executor::{estimator::TraceAreaEstimator, RiscvAirId};
use sp1_core_machine::shape::{CoreShapeConfig, CoreShapeError, Shapeable, ShardKind};
use sp1_stark::{shape::Shape, SplitOpts};

/// Returns core, precompile, mem shapes
pub fn get_shapes<F: PrimeField32>(
    config: &CoreShapeConfig<F>,
    split_opts: &SplitOpts,
    precompile_local_mem_events_per_row: &HashMap<RiscvAirId, usize>,
    estimator: &TraceAreaEstimator,
) -> Result<EnumMap<ShardKind, Vec<Shape<RiscvAirId>>>, CoreShapeError> {
    // TODO(tqn) decide whether or not to implement the Packed shard estimation
    let TraceAreaEstimator { core_shards, deferred_events } = estimator;
    // `Global` heights are sometimes overestimated.
    // When the fractional part of the log2 is above this, we round down.
    const THRESHOLD: f64 = 0.1;

    // Calculate and sum the cost of each core shard.
    let core_shapes = core_shards
        .iter()
        .enumerate()
        .map(|(i, shard)| {
            let record = if (shard[RiscvAirId::Global] as f64).log2().fract() < THRESHOLD {
                let mut shard = *shard;
                shard[RiscvAirId::Global] = 1 << shard[RiscvAirId::Global].ilog2();
                Cow::Owned(shard)
            } else {
                Cow::Borrowed(shard)
            };
            config.find_shape(CoreShard {
                shard_index: i as u32,
                record,
                precompile_local_mem_events_per_row,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut num_shards = core_shards.len();

    let precompile_shapes = deferred_events
        .iter()
        .filter_map(|(id, &count)| {
            // Skip AIR if there are no events.
            if count == 0 {
                return None;
            }
            let threshold = match id {
                RiscvAirId::ShaExtend => split_opts.sha_extend,
                RiscvAirId::ShaCompress => split_opts.sha_compress,
                RiscvAirId::KeccakPermute => split_opts.keccak,
                RiscvAirId::MemoryGlobalInit | RiscvAirId::MemoryGlobalFinalize => {
                    // Process these in their own shard(s).
                    return None;
                }
                _ => split_opts.deferred,
            };
            Some(((id, count), threshold))
        })
        .flat_map(|((id, count), threshold)| {
            let threshold = threshold as u64;
            let num_full_airs = count / threshold;
            let num_remainder_air_rows = count % threshold;

            iter::repeat((id, threshold))
                .take(num_full_airs as usize)
                .chain((num_remainder_air_rows > 0).then_some((id, num_remainder_air_rows)))
        })
        .map(|air_entry| {
            let shape = config.find_shape(CoreShard {
                shard_index: num_shards as u32,
                record: Cow::Owned(iter::once(air_entry).collect()),
                precompile_local_mem_events_per_row,
            });
            num_shards += 1;
            shape
        })
        .collect::<Result<Vec<_>, _>>()?;

    let global_memory_shapes = {
        let num_memory_global_init = deferred_events[RiscvAirId::MemoryGlobalInit];
        assert_eq!(
            num_memory_global_init,
            deferred_events[RiscvAirId::MemoryGlobalFinalize],
            "memory finalize AIR height should equal memory initialize AIR height"
        );

        let threshold = split_opts.memory as u64;
        let num_full_airs = num_memory_global_init / threshold;
        let num_remainder_air_rows = num_memory_global_init % threshold;

        iter::repeat(threshold)
            .take(num_full_airs as usize)
            .chain((num_remainder_air_rows > 0).then_some(num_remainder_air_rows))
            .map(|num_rows| {
                let shape = config.find_shape(CoreShard {
                    shard_index: num_shards as u32,
                    record: Cow::Owned(
                        [
                            (RiscvAirId::MemoryGlobalInit, num_rows),
                            (RiscvAirId::MemoryGlobalFinalize, num_rows),
                            (RiscvAirId::Global, 2 * num_rows),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                    precompile_local_mem_events_per_row,
                });
                num_shards += 1;
                shape
            })
            .collect::<Result<Vec<_>, _>>()?
    };

    Ok([
        (ShardKind::PackedCore, vec![]),
        (ShardKind::Core, core_shapes),
        (ShardKind::GlobalMemory, global_memory_shapes),
        (ShardKind::Precompile, precompile_shapes),
    ]
    .into_iter()
    .collect())
}

pub fn core_prover_gas<F: PrimeField32>(
    config: &CoreShapeConfig<F>,
    split_opts: &SplitOpts,
    precompile_local_mem_events_per_row: &HashMap<RiscvAirId, usize>,
    estimator: &TraceAreaEstimator,
) -> Result<usize, CoreShapeError> {
    Ok(get_shapes(config, split_opts, precompile_local_mem_events_per_row, estimator)?
        .values()
        .flatten()
        .map(|shape| config.estimate_lde_size(shape))
        .sum::<usize>())
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
