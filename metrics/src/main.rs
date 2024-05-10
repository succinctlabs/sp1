use sp1_core::air::MachineAir;
use sp1_core::stark::RiscvAir;
use sp1_core::utils::BabyBearPoseidon2;
use std::collections::BTreeMap;

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
    dbg!(chip_names.len());
    let mut chip_trace_times = Vec::new();

    let mut pcs_commit_metric = Vec::new();

    // TODO: consider better names for these?
    let mut total_commit_time = 0f64;
    let mut total_prove_time = 0f64;
    let mut total_commit_and_prove_time = 0f64;
    for log in logs {
        // println!("{}", log);
        // If no chips were found the ANSI encoding on the tracing logger may have been turned to true.
        // ANSI encoding should always be turned to false for parsing the logs
        if log.contains("chip_name=") {
            for chip_name in chip_names.iter() {
                // Some chips also have the same substrings contained within them so
                // we precede the match with an equal sign so that we do not match twice.
                if log.contains(&format!("={}", chip_name)) {
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
        } else if log.contains("prove_shards:commit_shards: close") {
            total_commit_time = fetch_time_from_log(log);
        } else if log.contains("prove_shards:open_shards: close") {
            total_prove_time = fetch_time_from_log(log);
        } else if log.contains("prove_shards: close") {
            total_commit_and_prove_time = fetch_time_from_log(log);
        }
    }

    dbg!(total_commit_time);
    dbg!(total_prove_time);
    dbg!(total_commit_time + total_prove_time);
    dbg!(total_commit_and_prove_time);

    // TODO: switch debug output to something actually readable
    // dbg!(chip_trace_times.clone());
    dbg!(chip_trace_times.len());
    // dbg!(pcs_commit_metric.clone());

    // Let's get some basic metrics here in Rust
    // Probably will want to convert it into JSON to be ported for deeper data analysis in python or something
    // Using BTreeMaps for my own debugging purposes so things do not get re-ordered
    let mut commit_phase_time_per_chip: BTreeMap<String, f64> = BTreeMap::new();
    let mut prove_phase_time_per_chip: BTreeMap<String, f64> = BTreeMap::new();
    for chip_trace in chip_trace_times.into_iter() {
        match chip_trace.phase {
            // TOOD: DRY, both match statements do the same thing
            Phase::Commit => {
                if let Some(accumulated_time) = commit_phase_time_per_chip.get_mut(&chip_trace.chip)
                {
                    *accumulated_time += chip_trace.time
                } else {
                    commit_phase_time_per_chip.insert(chip_trace.chip, chip_trace.time);
                }
            }
            Phase::Prove => {
                if let Some(accumulated_time) = prove_phase_time_per_chip.get_mut(&chip_trace.chip)
                {
                    *accumulated_time += chip_trace.time
                } else {
                    prove_phase_time_per_chip.insert(chip_trace.chip, chip_trace.time);
                }
            }
        }
    }
    dbg!(commit_phase_time_per_chip.clone());
    dbg!(prove_phase_time_per_chip.clone());

    println!("Some commit phase numbers: ");
    for (commit_chip, commit_time) in commit_phase_time_per_chip.iter() {
        let percent_of_commit = commit_time / total_commit_time;
        let percent_of_total = commit_time / total_commit_and_prove_time;

        println!("Chip: {}", commit_chip);
        println!(
            "percent_of_commit: {}, percent_of_total: {}",
            percent_of_commit, percent_of_total
        );
    }

    println!("Some prove phase numbers: ");
    for (prove_chip, prove_time) in prove_phase_time_per_chip.iter() {
        let percent_of_prove = prove_time / total_prove_time;
        let percent_of_total = prove_time / total_commit_and_prove_time;

        println!("Chip: {}", prove_chip);
        println!(
            "percent_of_prove: {}, percent_of_total: {}",
            percent_of_prove, percent_of_total
        );
    }
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
