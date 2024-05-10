use sp1_core::air::MachineAir;
use sp1_core::stark::RiscvAir;
use sp1_core::utils::BabyBearPoseidon2;
use std::path::PathBuf;

use regex::Regex;

// TODO: Need to add the shard index to the logs
// Which shard are we proving for?
// Need some sort of shard index to expand the chip metric
// to a general metric
#[derive(Debug, Clone)]
struct ChipTraceMetric {
    phase: Phase,
    shard_index: u32,
    chip: String,
    time: f64,
    permutation: bool,
}

#[derive(Default, Debug, Clone)]
struct PcsMetric {
    phase: Phase,
    time: f64,
    // States whether we are committing to a permutation trace
    permutation: bool,
}

// struct Metric {
//     phase: Phase,
//     metadata:
// }

// Phase of the prover from which a log trace comes
#[derive(Default, Debug, Clone)]
enum Phase {
    #[default]
    Commit,
    Prove,
}

fn main() {
    let log_path = std::env::var("SP1_LOG_DIR").unwrap();
    let contents =
        std::fs::read_to_string(log_path).expect("Should have been able to read the file");

    let logs = contents.split('\n').collect::<Vec<_>>();

    let config = BabyBearPoseidon2::new();
    let machine = RiscvAir::machine(config);
    let chips = machine.chips();
    let chip_names = chips.iter().map(|chip| chip.name()).collect::<Vec<_>>();

    let mut chip_trace_times = Vec::new();

    let mut pcs_commit_metric = Vec::new();
    for log in logs {
        println!("{}", log);
        // If no chips were found the ANSI encoding on the tracing logger may have been turned to true.
        // ANSI encoding should always be turned to false for parsing the logs
        if log.contains("chip_name=") {
            for chip_name in chip_names.iter() {
                if log.contains(chip_name) {
                    let shard_index = fetch_shard_index(log);
                    let time = fetch_time_from_log(log);
                    if log.contains("commit_shards") {
                        chip_trace_times.push(ChipTraceMetric {
                            phase: Phase::Commit,
                            shard_index,
                            chip: chip_name.clone(),
                            time,
                            permutation: false,
                        });
                    } else if log.contains("open_shards") {
                        if log.contains("permuation trace for chip") {
                            chip_trace_times.push(ChipTraceMetric {
                                phase: Phase::Prove,
                                shard_index,
                                chip: chip_name.clone(),
                                time,
                                permutation: true,
                            });
                        } else {
                            chip_trace_times.push(ChipTraceMetric {
                                phase: Phase::Prove,
                                shard_index,
                                chip: chip_name.clone(),
                                time,
                                permutation: false,
                            });
                        }
                    }
                    // If we have found the chip name we do not need to keep going through the loop
                    // Some chips also have the same substrings contained within them so we want to make sure
                    // that we do not match twice
                    break;
                }
            }
        } else if log.contains("pcs.commit to permutation traces: close") {
            let time = fetch_time_from_log(log);
            pcs_commit_metric.push(PcsMetric {
                phase: Phase::Prove,
                time,
                permutation: true,
            });
        } else if log.contains("pcs.commit to traces: close") {
            let time = fetch_time_from_log(log);
            if log.contains("commit_shards") {
                pcs_commit_metric.push(PcsMetric {
                    phase: Phase::Commit,
                    time,
                    permutation: false,
                });
            } else if log.contains("open_shards") {
                pcs_commit_metric.push(PcsMetric {
                    phase: Phase::Prove,
                    time,
                    permutation: false,
                });
            }
        }
    }

    // TODO: switch debug output to something actually readable
    dbg!(chip_trace_times.clone());
    dbg!(chip_trace_times.len());

    dbg!(pcs_commit_metric.clone());
}

fn fetch_time_from_log(log: &str) -> f64 {
    // We use `time.busy=` to find the start but do `+ 10` to start at the actual time amount
    // Reverse search in both cases as the time comes at the end of the log
    // TODO: this can probably be switched to use regex
    let start = log.rfind("time.busy=").unwrap() + 10;
    let end = log.rfind(" time.idle").unwrap();
    let time_with_unit = &log[start..end];
    // We transform everything into microseconds to have one unit of measurement
    // TODO: Figure out how to get the tracing logs to always use one unit of time
    let (end_offset, multiplier) = if time_with_unit.contains("µs") {
        // `µ` is two characters so the offset for `µs` is 3
        (3, 1f64)
    } else if time_with_unit.contains("ms") {
        (2, 1000f64)
    } else {
        // Panic if we do not otherwise have a second
        assert!(time_with_unit.contains('s'));
        (1, 1000000f64)
    };
    let time = &log[start..(end - end_offset)];
    let time: f64 = time.parse::<f64>().expect("Failed to parse time");
    // The final time in µs
    time * multiplier
}

fn fetch_shard_index(log: &str) -> u32 {
    if log.contains("shard_index") {
        let start = log.rfind("shard_index=").unwrap();
        let shard_index = &log[start..];
        let shard_index_str = Regex::new(r"shard_index=[0-9]+")
            .unwrap()
            .find(log)
            .expect("Should have a shard index");
        let shard_index = shard_index_str.as_str()[12..]
            .parse::<u32>()
            .expect("Failed to parse shard index");
        shard_index
    } else {
        panic!("Misplaced fetch_shard_index method.\n{}", log);
    }
}
