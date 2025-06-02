mod model;

pub use model::*;
use thiserror::Error;

use std::borrow::Cow;

use enum_map::EnumMap;
use hashbrown::HashMap;
use p3_field::PrimeField32;

use sp1_core_executor::{estimator::RecordEstimator, RiscvAirId};
use sp1_core_machine::shape::{CoreShapeConfig, CoreShapeError, Shapeable, ShardKind};
use sp1_stark::{shape::Shape, SP1CoreOpts, SplitOpts};

pub const GAS_OPTS: SP1CoreOpts = SP1CoreOpts {
    shard_size: 2097152,
    shard_batch_size: 1,
    split_opts: sp1_stark::SplitOpts {
        combine_memory_threshold: 131072,
        deferred: 16384,
        keccak: 5461,
        sha_extend: 10922,
        sha_compress: 6553,
        memory: 1048576,
    },
    trace_gen_workers: 4,
    checkpoints_channel_capacity: 128,
    records_and_traces_channel_capacity: 4,
};

#[derive(Error, Debug)]
pub enum GasError {
    #[error("Gas is non-finite: {0}")]
    NonFinite(f64),
    #[error("Gas is non-positive: {0}")]
    Negative(f64),
    #[error("Gas cannot fit inside a u64: {0}")]
    Overflow(f64),
}

pub fn final_transform(raw_gas: f64) -> Result<u64, GasError> {
    let raw_gas = (APPROX_CYCLES_PER_RAW_GAS * (raw_gas + OVERHEAD)).round();
    if !raw_gas.is_finite() {
        Err(GasError::NonFinite(raw_gas))
    } else if raw_gas.is_sign_negative() {
        Err(GasError::Negative(raw_gas))
    } else if raw_gas > u64::MAX as f64 {
        Err(GasError::Overflow(raw_gas))
    } else {
        Ok(raw_gas as u64)
    }
}

/// Calculates core, precompile, mem records. Does not implement packed or last shard logic.
#[allow(clippy::manual_repeat_n)]
pub fn estimated_records<'a>(
    split_opts: &SplitOpts,
    estimator: &'a RecordEstimator,
) -> impl Iterator<Item = Cow<'a, EnumMap<RiscvAirId, u64>>> {
    let RecordEstimator {
        ref core_records,
        ref precompile_records,
        memory_global_init_events,
        memory_global_finalize_events,
        ..
    } = *estimator;
    // `Global` heights are sometimes overestimated.
    // When the fractional part of the log2 is above this, we round down.
    const THRESHOLD: f64 = 0.1;

    // Calculate and sum the cost of each core shard.
    let core_records = core_records.iter().map(|shard| {
        if (shard[RiscvAirId::Global] as f64).log2().fract() < THRESHOLD {
            let mut shard = *shard;
            shard[RiscvAirId::Global] = 1 << shard[RiscvAirId::Global].ilog2();
            Cow::Owned(shard)
        } else {
            Cow::Borrowed(shard)
        }
    });

    let precompile_records = precompile_records.iter().flat_map(|(id, shards)| {
        shards.iter().map(move |&(precompile_events, local_memory_events)| {
            Cow::Owned(EnumMap::from_iter([
                (id, precompile_events),
                (RiscvAirId::MemoryLocal, local_memory_events),
            ]))
        })
    });

    let global_memory_records = {
        let threshold = split_opts.memory as u64;

        let init_final_events = [memory_global_init_events, memory_global_finalize_events];

        let quotients = init_final_events.map(|x| x / threshold);
        let remainders = init_final_events.map(|x| x % threshold);

        let full_airs = quotients.into_iter().min().unwrap();

        #[inline]
        fn memory_air(init_ht: u64, final_ht: u64) -> EnumMap<RiscvAirId, u64> {
            EnumMap::from_iter([
                (RiscvAirId::MemoryGlobalInit, init_ht),
                (RiscvAirId::MemoryGlobalFinalize, final_ht),
                (RiscvAirId::Global, init_ht + final_ht),
            ])
        }

        std::iter::repeat(Cow::Owned(memory_air(threshold, threshold)))
            .take(full_airs as usize)
            .chain(
                remainders
                    .iter()
                    .any(|x| *x > 0)
                    .then(|| Cow::Owned(memory_air(remainders[0], remainders[1]))),
            )
    };

    core_records.chain(global_memory_records).chain(precompile_records)
}

pub fn fit_records_to_shapes<'a, F: PrimeField32>(
    config: &'a CoreShapeConfig<F>,
    records: impl IntoIterator<Item = Cow<'a, EnumMap<RiscvAirId, u64>>> + 'a,
) -> impl Iterator<Item = Result<Shape<RiscvAirId>, CoreShapeError>> + 'a {
    records.into_iter().enumerate().map(|(i, record)| {
        config.find_shape(&CoreShard { shard_index: i as u32, record: record.as_ref() })
    })
}

struct CoreShard<'a> {
    shard_index: u32,
    record: &'a EnumMap<RiscvAirId, u64>,
}

impl Shapeable for CoreShard<'_> {
    fn kind(&self) -> ShardKind {
        let contains_cpu = self.record[RiscvAirId::Cpu] > 0;
        let contains_global_memory = self.record[RiscvAirId::MemoryGlobalInit] > 0 ||
            self.record[RiscvAirId::MemoryGlobalFinalize] > 0;
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
        let num_local_mem_events = self.record[RiscvAirId::MemoryLocal] as usize;
        self.record.iter().filter_map(move |(id, &num_events)| {
            let num_events = num_events as usize;
            // Skip empty events and filter by precompiles.
            (num_events > 0 && id.is_precompile()).then_some(())?;
            let rows = num_events * id.rows_per_event();
            let num_global_events = 2 * num_local_mem_events + num_events;
            Some((id, (rows, num_local_mem_events, num_global_events)))
        })
    }
}
