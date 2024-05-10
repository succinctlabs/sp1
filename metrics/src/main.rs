use prettytable::{row, table, Row};
use std::{collections::BTreeMap, fmt::Display};

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

impl From<ChipTraceMetric> for Row {
    fn from(chip_metric: ChipTraceMetric) -> Self {
        row![
            Fr->format!("{}", chip_metric.phase),
            Fm->format!("{}", chip_metric.shard_index),
            Fm->format!("{}", chip_metric.chip),
            Fm->format!("{}", chip_metric.permutation),
            Fg->format!("{}", chip_metric.time),
        ]
    }
}

#[derive(Debug, Clone)]
struct QuotientValuesMetric {
    chip: String,
    shard_index: u32,
    time: f64,
}

#[derive(Default, Debug, Clone)]
struct PcsMetric {
    phase: Phase,
    // States what kind of evaluation domain for which we are committing upon
    evaluation: EvaluationType,
    time: f64,
}

#[derive(Default, Debug, Clone)]
enum EvaluationType {
    #[default]
    Trace,
    Permutation,
    Quotient,
}

impl Display for EvaluationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvaluationType::Trace => write!(f, "trace"),
            EvaluationType::Permutation => write!(f, "permutation"),
            EvaluationType::Quotient => write!(f, "quotient"),
        }
    }
}

impl From<PcsMetric> for Row {
    fn from(value: PcsMetric) -> Self {
        row![
            Fr->format!("{}", value.phase),
            Fm->format!("{}", value.evaluation),
            Fg->format!("{}", value.time),
        ]
    }
}

// Phase of the prover from which a log trace comes
#[derive(Default, Debug, Clone, Copy)]
enum Phase {
    #[default]
    Commit,
    Prove,
}

impl Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Phase::Commit => write!(f, "Commit"),
            Phase::Prove => write!(f, "Prove Opening"),
        }
    }
}

fn main() {
    let log_path = std::env::var("SP1_LOG_DIR").unwrap();
    let contents =
        std::fs::read_to_string(log_path).expect("Should have been able to read the file");

    let logs = contents.split('\n').collect::<Vec<_>>();

    let mut chip_trace_times = Vec::new();
    let mut pcs_commit_metrics = Vec::new();
    let mut chip_quotient_values_times = Vec::new();

    // These are the following total time of the parallel
    // chip executions
    let mut total_generate_trace_time = 0f64;
    let mut total_permutation_trace_time = 0f64;
    let mut total_quotient_values_time = 0f64;

    // Total time to comptue the phase one commitment
    let mut total_phase_one = 0f64;
    // Total time to compute phase two
    let mut total_phase_two = 0f64;
    // This is the complete total time to generate a proof for all shards
    let mut total_prove_time = 0f64;
    for log in logs {
        println!("{}", log);
        // If no chips were found the ANSI encoding on the tracing logger may have been turned to true.
        // ANSI encoding should always be turned to false for parsing the logs
        // TODO: switch these trace names to constants. Any project using these metrics should use these constants as well
        if let Some(chip_name) = Regex::new(r"chip_name=[a-zA-Z]+").unwrap().find(log) {
            let chip_name = &chip_name.as_str()[10..];
            let shard_index = fetch_shard_index(log);
            let time = fetch_time_from_log(log);
            if log.contains("commit_shards") {
                chip_trace_times.push(ChipTraceMetric {
                    phase: Phase::Commit,
                    shard_index,
                    chip: chip_name.to_owned(),
                    time,
                    permutation: false,
                });
            } else if log.contains("open_shards") {
                if log.contains("permuation trace for chip") {
                    chip_trace_times.push(ChipTraceMetric {
                        phase: Phase::Prove,
                        shard_index,
                        chip: chip_name.to_owned(),
                        time,
                        permutation: true,
                    });
                } else if log.contains("generate trace for chip") {
                    chip_trace_times.push(ChipTraceMetric {
                        phase: Phase::Prove,
                        shard_index,
                        chip: chip_name.to_owned(),
                        time,
                        permutation: false,
                    });
                } else if log.contains("compute quotient values for domain") {
                    chip_quotient_values_times.push(QuotientValuesMetric {
                        chip: chip_name.to_owned(),
                        shard_index,
                        time,
                    })
                }
            }
        } else if log.contains("pcs.commit to permutation traces: close") {
            let time = fetch_time_from_log(log);
            pcs_commit_metrics.push(PcsMetric {
                phase: Phase::Prove,
                time,
                evaluation: EvaluationType::Permutation,
            });
        } else if log.contains("pcs.commit to traces: close") {
            let time = fetch_time_from_log(log);
            if log.contains("commit_shards") {
                pcs_commit_metrics.push(PcsMetric {
                    phase: Phase::Commit,
                    time,
                    evaluation: EvaluationType::Trace,
                });
            } else if log.contains("open_shards") {
                pcs_commit_metrics.push(PcsMetric {
                    phase: Phase::Prove,
                    time,
                    evaluation: EvaluationType::Trace,
                });
            }
        } else if log.contains("pcs.commit to quotient traces: close") {
            let time = fetch_time_from_log(log);
            pcs_commit_metrics.push(PcsMetric {
                phase: Phase::Prove,
                time,
                evaluation: EvaluationType::Quotient,
            });
        } else if log.contains("prove_shards:commit_shards: close") {
            total_phase_one = fetch_time_from_log(log);
        } else if log.contains("prove_shards:open_shards: close") {
            total_phase_two = fetch_time_from_log(log);
        } else if log.contains("generate traces for shard: close") {
            total_generate_trace_time = fetch_time_from_log(log);
        } else if log.contains("generate permutation traces: close ") {
            total_permutation_trace_time = fetch_time_from_log(log);
        } else if log.contains("compute quotient values: close") {
            total_quotient_values_time = fetch_time_from_log(log);
        } else if log.contains("prove_shards: close") {
            total_prove_time = fetch_time_from_log(log);
        }
    }

    let mut total_trace_time = 0f64;
    for chip_trace in chip_trace_times.iter() {
        total_trace_time += chip_trace.time;
    }
    dbg!(total_trace_time);

    let mut total_pcs_commit_time = 0f64;
    for pcs_commit_metric in pcs_commit_metrics.iter() {
        total_pcs_commit_time += pcs_commit_metric.time;
    }
    dbg!(total_pcs_commit_time);

    dbg!(total_trace_time + total_pcs_commit_time);

    dbg!(total_generate_trace_time);
    dbg!(total_permutation_trace_time);
    dbg!(total_quotient_values_time);
    dbg!(total_generate_trace_time + total_permutation_trace_time);
    dbg!(
        total_pcs_commit_time
            + total_generate_trace_time
            + total_permutation_trace_time
            + total_quotient_values_time
    );
    dbg!(total_prove_time);

    let mut chip_trace_table =
        table!([Fc->"Phase", Fc->"Shard", Fc->"Chip", Fc->"Permutation Trace", Fc->"Time (mus)"]);

    // Let's get some basic metrics here in Rust
    // Probably will want to convert it into JSON to be ported for deeper data analysis in python or something
    // Using BTreeMaps for my own debugging purposes so things do not get re-ordered
    // TODO: Also some of the computation inside of these loops are reported

    let mut total_percent = 0f64;
    let mut chip_commit_report_table = table!([Fc->"Chip", Fc->"Shard", Fc->"Percent of Generate Trace Time", Fc->"Percent of Phase One", Fc->"Percent of Total Time"]);
    let mut chip_prove_report_table = table!([Fc->"Chip", Fc->"Shard", Fc->"Permutation Trace", Fc->"Percent of Generate Trace Time", Fc->"Percent of Phase Two", Fc->"Percent of Total Time"]);

    for chip_trace in chip_trace_times.into_iter() {
        let chip_row: Row = chip_trace.clone().into();
        chip_trace_table.add_row(chip_row);

        match chip_trace.phase {
            Phase::Commit => {
                let commit_time = chip_trace.time;
                let percent_of_generate_trace = commit_time / total_generate_trace_time * 100f64;
                let percent_of_phase_one = commit_time / total_phase_one * 100f64;
                let percent_of_total = commit_time / total_prove_time * 100f64;
                total_percent += percent_of_total;

                let commit_report = ChipCommitReport {
                    chip: chip_trace.chip,
                    shard: chip_trace.shard_index,
                    percent_of_generate_trace,
                    percent_of_phase_one,
                    percent_of_total,
                };
                chip_commit_report_table.add_row(commit_report.into());
            }
            Phase::Prove => {
                let prove_time = chip_trace.time;
                let percent_of_perm_trace = prove_time / total_permutation_trace_time * 100f64;
                let percent_of_phase_two = prove_time / total_phase_two * 100f64;
                let percent_of_total = prove_time / total_prove_time * 100f64;

                total_percent += percent_of_total;

                let prove_report = ChipProveReport {
                    chip: chip_trace.chip,
                    shard: chip_trace.shard_index,
                    permutation: chip_trace.permutation,
                    percent_of_perm_trace,
                    percent_of_phase_two,
                    percent_of_total,
                };
                chip_prove_report_table.add_row(prove_report.into());
            }
        }
    }

    println!("\x1B[1;31mAll Trace Generation Times\x1B[0m");
    chip_trace_table.printstd();
    println!("\x1B[1;31mCommit Shards (phase one) Trace Generation\x1B[0m");
    chip_commit_report_table.printstd();
    println!("\x1B[1;31mOpen Shards (phase two) Trace Generation\x1B[0m");
    chip_prove_report_table.printstd();

    let mut quotient_values_report_table = table!([Fc->"Chip", Fc->"Shard", Fc->"Percent of Quotient Values Comp", Fc->"Percent of Phase Two", Fc->"Percent of Total Time"]);
    for quotient_metric in chip_quotient_values_times.into_iter() {
        let percent_of_quotient_comp = quotient_metric.time / total_quotient_values_time * 100f64;
        let percent_of_phase_two = quotient_metric.time / total_phase_two * 100f64;
        let percent_of_total = quotient_metric.time / total_prove_time * 100f64;

        let quotient_report = QuotientValueReport {
            quotient_metric,
            percent_of_quotient_comp,
            percent_of_phase_two,
            percent_of_total,
        };

        quotient_values_report_table.add_row(quotient_report.into());
    }
    println!("\x1B[1;31mQuotient Values Computation\x1B[0m");
    quotient_values_report_table.printstd();

    let mut pcs_metrics_table = table!([Fc->"Phase", Fc->"Evaluation Domain Type", Fc->"Time (mus)", Fc->"Percent of Total Time"]);
    for pcs_metric in pcs_commit_metrics.into_iter() {
        let percent_of_total = pcs_metric.time / total_prove_time * 100f64;

        let pcs_metric_report = PcsCommitReport {
            pcs_metric,
            percent_of_total,
        };

        let pcs_row: Row = pcs_metric_report.into();
        pcs_metrics_table.add_row(pcs_row);
    }
    println!("\x1B[1;31mpcs.commit table\x1B[0m");
    pcs_metrics_table.printstd();

    dbg!(total_percent);
}

struct ChipCommitReport {
    chip: String,
    shard: u32,
    percent_of_generate_trace: f64,
    percent_of_phase_one: f64,
    percent_of_total: f64,
}

impl From<ChipCommitReport> for Row {
    fn from(value: ChipCommitReport) -> Self {
        row![
            Fr->format!("{}", value.chip),
            Fm->format!("{}", value.shard),
            Fg->format!("{:.3}", value.percent_of_generate_trace),
            Fg->format!("{:.3}", value.percent_of_phase_one),
            Fg->format!("{:.3}", value.percent_of_total),
        ]
    }
}

struct ChipProveReport {
    chip: String,
    shard: u32,
    permutation: bool,
    percent_of_perm_trace: f64,
    percent_of_phase_two: f64,
    percent_of_total: f64,
}

impl From<ChipProveReport> for Row {
    fn from(value: ChipProveReport) -> Self {
        row![
            Fr->format!("{}", value.chip),
            Fm->format!("{}", value.shard),
            Fm->format!("{}", value.permutation),
            Fg->format!("{:.3}", value.percent_of_perm_trace),
            Fg->format!("{:.3}", value.percent_of_phase_two),
            Fg->format!("{:.3}", value.percent_of_total),
        ]
    }
}

struct QuotientValueReport {
    quotient_metric: QuotientValuesMetric,
    percent_of_quotient_comp: f64,
    percent_of_phase_two: f64,
    percent_of_total: f64,
}

impl From<QuotientValueReport> for Row {
    fn from(value: QuotientValueReport) -> Self {
        row![
            Fr->format!("{}", value.quotient_metric.chip),
            Fm->format!("{}", value.quotient_metric.shard_index),
            Fg->format!("{:.3}", value.percent_of_quotient_comp),
            Fg->format!("{:.3}", value.percent_of_phase_two),
            Fg->format!("{:.3}", value.percent_of_total),
        ]
    }
}

struct PcsCommitReport {
    pcs_metric: PcsMetric,
    percent_of_total: f64,
}

impl From<PcsCommitReport> for Row {
    fn from(value: PcsCommitReport) -> Self {
        row![
            Fr->format!("{}", value.pcs_metric.phase),
            Fm->format!("{}", value.pcs_metric.evaluation),
            Fg->format!("{}", value.pcs_metric.time),
            Fg->format!("{:.3}", value.percent_of_total),
        ]
    }
}

// NOTE: This method will only work if `FmtSpan::CLOSE` is activated for the tracing subscriber
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
    let shard_index_str = Regex::new(r"shard_index=[0-9]+")
        .unwrap()
        .find(log)
        .expect("Should have a shard index");
    let shard_index = shard_index_str.as_str()[12..]
        .parse::<u32>()
        .expect("Failed to parse shard index");
    shard_index
}
