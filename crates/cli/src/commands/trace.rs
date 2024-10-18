//! RISC-V tracer for SP1 traces. This tool can be used to analyze function call graphs and
//! instruction counts from a trace file from SP1 execution by setting the `TRACE_FILE` env
//! variable.
//
// Adapted from Sovereign's RISC-V tracer tool: https://github.com/Sovereign-Labs/riscv-cycle-tracer.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Modified by Succinct Labs on July 25, 2024.

use anyhow::Result;
use clap::Parser;
use goblin::elf::{sym::STT_FUNC, Elf};
use indicatif::{ProgressBar, ProgressStyle};
use prettytable::{format, Cell, Row, Table};
use regex::Regex;
use rustc_demangle::demangle;
use std::{
    cmp::Ordering,
    collections::HashMap,
    io::Read,
    process::Command,
    str,
    sync::{atomic::AtomicBool, Arc},
};
use textwrap::wrap;

#[derive(Parser, Debug)]
#[command(name = "trace", about = "Trace a program execution and analyze cycle counts.")]
pub struct TraceCmd {
    /// Include the "top" number of functions.
    #[arg(short, long, default_value_t = 30)]
    top: usize,

    /// Don't print stack aware instruction counts
    #[arg(long)]
    no_stack_counts: bool,

    /// Don't print raw (stack un-aware) instruction counts.
    #[arg(long)]
    no_raw_counts: bool,

    /// Path to the ELF.
    #[arg(long, required = true)]
    elf: String,

    /// Path to the trace file. Simply run the program with `TRACE_FILE=trace.log` environment
    /// variable. File must be one u64 program counter per line
    #[arg(long, required = true)]
    trace: String,

    /// Strip the hashes from the function name while printing.
    #[arg(short, long)]
    keep_hashes: bool,

    /// Function name to target for getting stack counts.
    #[arg(short, long)]
    function_name: Option<String>,

    /// Exclude functions matching these patterns from display.
    ///
    /// Usage: `-e func1 -e func2 -e func3`.
    #[arg(short, long)]
    exclude_view: Vec<String>,
}

fn strip_hash(name_with_hash: &str) -> String {
    let re = Regex::new(r"::h[0-9a-fA-F]{16}").unwrap();
    let mut result = re.replace(name_with_hash, "").to_string();
    let re2 = Regex::new(r"^<(.+) as .+>").unwrap();
    result = re2.replace(&result, "$1").to_string();
    let re2 = Regex::new(r"^<(.+) as .+>").unwrap();
    result = re2.replace(&result, "$1").to_string();
    let re2 = Regex::new(r"([^\:])<.+>::").unwrap();
    result = re2.replace_all(&result, "$1::").to_string();
    result
}

fn print_instruction_counts(
    first_header: &str,
    count_vec: Vec<(String, usize)>,
    top_n: usize,
    strip_hashes: bool,
    exclude_list: Option<&[String]>,
) {
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_LINESEP);
    table.set_titles(Row::new(vec![Cell::new(first_header), Cell::new("Instruction Count")]));

    let wrap_width = 120;
    let mut row_count = 0;
    for (key, value) in count_vec {
        let mut cont = false;
        if let Some(ev) = exclude_list {
            for e in ev {
                if key.contains(e) {
                    cont = true;
                    break;
                }
            }
            if cont {
                continue;
            }
        }
        let mut stripped_key = key.clone();
        if strip_hashes {
            stripped_key = strip_hash(&key);
        }
        row_count += 1;
        if row_count > top_n {
            break;
        }
        let wrapped_key = wrap(&stripped_key, wrap_width);
        let key_cell_content = wrapped_key.join("\n");
        table.add_row(Row::new(vec![Cell::new(&key_cell_content), Cell::new(&value.to_string())]));
    }

    table.printstd();
}

fn focused_stack_counts(
    function_stack: &[String],
    filtered_stack_counts: &mut HashMap<Vec<String>, usize>,
    function_name: &str,
    num_instructions: usize,
) {
    if let Some(index) = function_stack.iter().position(|s| s == function_name) {
        let truncated_stack = &function_stack[0..=index];
        let count = filtered_stack_counts.entry(truncated_stack.to_vec()).or_insert(0);
        *count += num_instructions;
    }
}

fn _build_radare2_lookups(
    start_lookup: &mut HashMap<u64, String>,
    end_lookup: &mut HashMap<u64, String>,
    func_range_lookup: &mut HashMap<String, (u64, u64)>,
    elf_name: &str,
) -> std::io::Result<()> {
    let output = Command::new("r2").arg("-q").arg("-c").arg("aa;afl").arg(elf_name).output()?;

    if output.status.success() {
        let result_str = str::from_utf8(&output.stdout).unwrap();
        for line in result_str.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let address = u64::from_str_radix(&parts[0][2..], 16).unwrap();
            let size = parts[2].parse::<u64>().unwrap();
            let end_address = address + size - 4;
            let function_name = parts[3];
            start_lookup.insert(address, function_name.to_string());
            end_lookup.insert(end_address, function_name.to_string());
            func_range_lookup.insert(function_name.to_string(), (address, end_address));
        }
    } else {
        eprintln!("Error executing command: {}", str::from_utf8(&output.stderr).unwrap());
    }
    Ok(())
}

fn build_goblin_lookups(
    start_lookup: &mut HashMap<u64, String>,
    end_lookup: &mut HashMap<u64, String>,
    func_range_lookup: &mut HashMap<String, (u64, u64)>,
    elf_name: &str,
) -> std::io::Result<()> {
    let buffer = std::fs::read(elf_name).unwrap();
    let elf = Elf::parse(&buffer).unwrap();

    for sym in &elf.syms {
        if sym.st_type() == STT_FUNC {
            let name = elf.strtab.get_at(sym.st_name).unwrap_or("");
            let demangled_name = demangle(name);
            let size = sym.st_size;
            let start_address = sym.st_value;
            let end_address = start_address + size - 4;
            start_lookup.insert(start_address, demangled_name.to_string());
            end_lookup.insert(end_address, demangled_name.to_string());
            func_range_lookup.insert(demangled_name.to_string(), (start_address, end_address));
        }
    }
    Ok(())
}

fn increment_stack_counts(
    instruction_counts: &mut HashMap<String, usize>,
    function_stack: &[String],
    filtered_stack_counts: &mut HashMap<Vec<String>, usize>,
    function_name: &Option<String>,
    num_instructions: usize,
) {
    for f in function_stack {
        *instruction_counts.entry(f.clone()).or_insert(0) += num_instructions;
    }
    if let Some(f) = function_name {
        focused_stack_counts(function_stack, filtered_stack_counts, f, num_instructions)
    }
}

impl TraceCmd {
    pub fn run(&self) -> Result<()> {
        let top_n = self.top;
        let elf_path = self.elf.clone();
        let trace_path = self.trace.clone();
        let no_stack_counts = self.no_stack_counts;
        let no_raw_counts = self.no_raw_counts;
        let strip_hashes = !self.keep_hashes;
        let function_name = self.function_name.clone();
        let exclude_view = self.exclude_view.clone();

        let mut start_lookup = HashMap::new();
        let mut end_lookup = HashMap::new();
        let mut func_range_lookup = HashMap::new();
        build_goblin_lookups(&mut start_lookup, &mut end_lookup, &mut func_range_lookup, &elf_path)
            .unwrap();

        let mut function_ranges: Vec<(u64, u64, String)> =
            func_range_lookup.iter().map(|(f, &(start, end))| (start, end, f.clone())).collect();

        function_ranges.sort_by_key(|&(start, _, _)| start);

        let file = std::fs::File::open(trace_path).unwrap();
        let file_size = file.metadata().unwrap().len();
        let mut buf = std::io::BufReader::new(file);
        let mut function_stack: Vec<String> = Vec::new();
        let mut instruction_counts: HashMap<String, usize> = HashMap::new();
        let mut counts_without_callgraph: HashMap<String, usize> = HashMap::new();
        let mut filtered_stack_counts: HashMap<Vec<String>, usize> = HashMap::new();
        let total_lines = file_size / 4;
        let mut current_function_range: (u64, u64) = (0, 0);

        let update_interval = 1000usize;
        let pb = ProgressBar::new(total_lines);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
                )
                .unwrap()
                .progress_chars("#>-"),
        );

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        ctrlc::set_handler(move || {
            r.store(false, std::sync::atomic::Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");

        for c in 0..total_lines {
            if (c as usize) % update_interval == 0 {
                pb.inc(update_interval as u64);
                if !running.load(std::sync::atomic::Ordering::SeqCst) {
                    pb.finish_with_message("Interrupted");
                    break;
                }
            }

            // Parse pc from hex.
            let mut pc_bytes = [0u8; 4];
            buf.read_exact(&mut pc_bytes).unwrap();
            let pc = u32::from_be_bytes(pc_bytes) as u64;

            // Only 1 instruction per opcode.
            let num_instructions = 1;

            // Raw counts without considering the callgraph at all we're just checking if the PC
            // belongs to a function if so we're incrementing. This would ignore the call stack
            // so for example "main" would only have a hundred instructions or so.
            if let Ok(index) = function_ranges.binary_search_by(|&(start, end, _)| {
                if pc < start {
                    Ordering::Greater
                } else if pc > end {
                    Ordering::Less
                } else {
                    Ordering::Equal
                }
            }) {
                let (_, _, fname) = &function_ranges[index];
                *counts_without_callgraph.entry(fname.clone()).or_insert(0) += num_instructions
            } else {
                *counts_without_callgraph.entry("anonymous".to_string()).or_insert(0) +=
                    num_instructions;
            }

            // The next section considers the callstack. We build a callstack and maintain it based
            // on some rules. Functions lower in the stack get their counts incremented.

            // We are still in the current function.
            if pc > current_function_range.0 && pc <= current_function_range.1 {
                increment_stack_counts(
                    &mut instruction_counts,
                    &function_stack,
                    &mut filtered_stack_counts,
                    &function_name,
                    num_instructions,
                );
                continue;
            }

            // Jump to a new function (or the same one).
            if let Some(f) = start_lookup.get(&pc) {
                increment_stack_counts(
                    &mut instruction_counts,
                    &function_stack,
                    &mut filtered_stack_counts,
                    &function_name,
                    num_instructions,
                );

                // Jump to a new function (not recursive).
                if !function_stack.contains(f) {
                    function_stack.push(f.clone());
                    current_function_range = *func_range_lookup.get(f).unwrap();
                }
            } else {
                // This means pc now points to an instruction that is
                //
                // 1. not in the current function's range
                // 2. not a new function call
                //
                // We now account for a new possibility where we're returning to a function in the
                // stack this need not be the immediate parent and can be any of the existing
                // functions in the stack due to some optimizations that the compiler can make.
                let mut unwind_point = 0;
                let mut unwind_found = false;
                for (c, f) in function_stack.iter().enumerate() {
                    let (s, e) = func_range_lookup.get(f).unwrap();
                    if pc > *s && pc <= *e {
                        unwind_point = c;
                        unwind_found = true;
                        break;
                    }
                }

                // Unwinding until the parent.
                if unwind_found {
                    function_stack.truncate(unwind_point + 1);
                    increment_stack_counts(
                        &mut instruction_counts,
                        &function_stack,
                        &mut filtered_stack_counts,
                        &function_name,
                        num_instructions,
                    );
                    continue;
                }

                // If no unwind point has been found, that means we jumped to some random location
                // so we'll just increment the counts for everything in the stack.
                increment_stack_counts(
                    &mut instruction_counts,
                    &function_stack,
                    &mut filtered_stack_counts,
                    &function_name,
                    num_instructions,
                );
            }
        }

        pb.finish_with_message("done");

        let mut raw_counts: Vec<(String, usize)> =
            instruction_counts.iter().map(|(key, value)| (key.clone(), *value)).collect();
        raw_counts.sort_by(|a, b| b.1.cmp(&a.1));

        println!("\n\nTotal instructions in trace: {}", total_lines);
        if !no_stack_counts {
            println!("\n\n Instruction counts considering call graph");
            print_instruction_counts(
                "Function Name",
                raw_counts,
                top_n,
                strip_hashes,
                Some(&exclude_view),
            );
        }

        let mut raw_counts: Vec<(String, usize)> =
            counts_without_callgraph.iter().map(|(key, value)| (key.clone(), *value)).collect();
        raw_counts.sort_by(|a, b| b.1.cmp(&a.1));
        if !no_raw_counts {
            println!("\n\n Instruction counts ignoring call graph");
            print_instruction_counts(
                "Function Name",
                raw_counts,
                top_n,
                strip_hashes,
                Some(&exclude_view),
            );
        }

        let mut raw_counts: Vec<(String, usize)> = filtered_stack_counts
            .iter()
            .map(|(stack, count)| {
                let numbered_stack = stack
                    .iter()
                    .rev()
                    .enumerate()
                    .map(|(index, line)| {
                        let modified_line =
                            if strip_hashes { strip_hash(line) } else { line.clone() };
                        format!("({}) {}", index + 1, modified_line)
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                (numbered_stack, *count)
            })
            .collect();

        raw_counts.sort_by(|a, b| b.1.cmp(&a.1));
        if let Some(f) = function_name {
            println!("\n\n Stack patterns for function '{f}' ");
            print_instruction_counts("Function Stack", raw_counts, top_n, strip_hashes, None);
        }
        Ok(())
    }
}
