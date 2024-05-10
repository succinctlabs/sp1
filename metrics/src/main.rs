use sp1_core::air::MachineAir;
use sp1_core::stark::RiscvAir;
use sp1_core::utils::BabyBearPoseidon2;
use std::path::PathBuf;

// TODO: Need to add the shard index to the logs
// Which shard are we proving for?
// Need some sort of shard index to expand the chip metric
// to a general metric
#[derive(Debug, Clone)]
struct ChipTraceMetric {
    phase: Phase,
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

// Phase of the prover for which we are tracking a log
#[derive(Default, Debug, Clone)]
enum Phase {
    #[default]
    Commit,
    Prove,
}

fn main() {
    // TODO: currently hardcoding the file but make this based off of env variables
    let fibonacci_path = PathBuf::from(
        "/Users/maximvezenov/Documents/dev/succinctlabs/.sp1-logs/sp1-core/fibonacci.log",
    );

    let contents =
        std::fs::read_to_string(fibonacci_path).expect("Should have been able to read the file");

    let logs = contents.split('\n').collect::<Vec<_>>();

    let config = BabyBearPoseidon2::new();
    let machine = RiscvAir::machine(config);
    let chips = machine.chips();
    let chip_names = chips.iter().map(|chip| chip.name()).collect::<Vec<_>>();

    let mut phase_one_trace_times = Vec::new();
    let mut phase_two_trace_times = Vec::new();

    let mut phase_one_pcs_commit = Vec::new();
    let mut phase_two_pcs_commit = Vec::new();
    for log in logs {
        println!("{}", log);
        fetch_shard_index(log);
        // If no chips were found the ANSI encoding on the tracing logger may have been turned to true.
        // ANSI encoding should always be turned to false for parsing the logs
        if log.contains("chip_name=") {
            for chip_name in chip_names.iter() {
                if log.contains(chip_name) {
                    let time = fetch_time_from_log(log);
                    if log.contains("commit_shards") {
                        phase_one_trace_times.push(ChipTraceMetric {
                            phase: Phase::Commit,
                            chip: chip_name.clone(),
                            time,
                            permutation: false,
                        });
                    } else if log.contains("open_shards") {
                        if log.contains("permuation trace for chip") {
                            phase_two_trace_times.push(ChipTraceMetric {
                                phase: Phase::Prove,
                                chip: chip_name.clone(),
                                time,
                                permutation: true,
                            });
                        } else {
                            phase_two_trace_times.push(ChipTraceMetric {
                                phase: Phase::Prove,
                                chip: chip_name.clone(),
                                time,
                                permutation: false,
                            });
                        }
                    }
                }
            }
        } else if log.contains("pcs.commit to permutation traces: close") {
            let time = fetch_time_from_log(log);
            phase_two_pcs_commit.push(PcsMetric {
                phase: Phase::Prove,
                time,
                permutation: true,
            });
        } else if log.contains("pcs.commit to traces: close") {
            let time = fetch_time_from_log(log);
            if log.contains("commit_shards") {
                phase_one_pcs_commit.push(PcsMetric {
                    phase: Phase::Commit,
                    time,
                    permutation: false,
                });
            } else if log.contains("open_shards") {
                phase_two_pcs_commit.push(PcsMetric {
                    phase: Phase::Prove,
                    time,
                    permutation: false,
                });
            }
        }
    }

    // TODO: switch debug output to something actually readable
    dbg!(phase_one_trace_times.clone());
    dbg!(phase_two_trace_times.clone());
    dbg!(phase_one_trace_times.len());
    dbg!(phase_two_trace_times.len());

    dbg!(phase_one_pcs_commit);
    dbg!(phase_two_pcs_commit);
}

fn fetch_time_from_log(log: &str) -> f64 {
    // We use `time.busy=` to find the start but do `+ 10` to start at the actual time amount
    // Reverse search in both cases as the time comes at the end of the log
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

fn fetch_shard_index(log: &str) {
    if log.contains("shard_index") {
        dbg!("got shard index");
    }
}
