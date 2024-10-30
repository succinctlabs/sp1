//! RISC-V tracing and profiling for SP1 traces. This tool can be used to analyze function call graphs and
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
// Modified by Succinct Labs on Oct 18, 2024.

use clap::Parser;
use gecko_profile::{Frame, ProfileBuilder, ThreadBuilder};
use std::io::SeekFrom;
use std::process::Stdio;
use std::{io::Seek, path::PathBuf};

use anyhow::{Context, Result};
use goblin::elf::{sym::STT_FUNC, Elf};
use rustc_demangle::demangle;
use std::{collections::HashMap, io::Read, path::Path, rc::Rc, str};

#[derive(Parser, Debug)]
#[command(name = "profile", about = "Create a gecko profile from a trace file.")]
pub struct ProfileCmd {
    /// Path to the ELF.
    #[arg(long, required = true)]
    elf: PathBuf,

    /// Path to the trace file. Simply run the program with `TRACE_FILE=trace.log` environment
    /// variable. File must be one u64 program counter per line
    #[arg(short = 't', long, required = true)]
    trace: PathBuf,

    /// The output file to write the gecko profile to, should be a json
    #[arg(short = 'o', long)]
    output: PathBuf,

    /// The sample rate to use for the profile.
    /// This is the number of instructions in between samples.
    #[arg(short = 'r', long, default_value = "10")]
    sample_rate: usize,

    /// Name the circuit, this will be displayed in the UI
    #[arg(short = 'n', long, default_value = "sp1")]
    name: String,

    /// Do not open the profiler visualizer after creating the profile.
    #[arg(long)]
    no_open: bool,
}

pub struct Sample {
    /// cheaper than allocating a String per sample
    pub stack: Vec<Rc<str>>,
}

impl ProfileCmd {
    pub fn run(&self) -> anyhow::Result<()> {
        let samples = collect_samples(&self.elf, &self.trace, self.sample_rate as u64)?;

        println!(
            "Collected {} samples from {} instructions",
            samples.len(),
            samples.len() * self.sample_rate
        );

        check_samples(&samples)?;

        let start_time = std::time::Instant::now();
        let mut profile_builder = ProfileBuilder::new(
            start_time,
            std::time::SystemTime::now(),
            &self.name,
            0,
            std::time::Duration::from_micros(1),
        );

        let mut thread_builder = ThreadBuilder::new(1, 0, start_time, false, false);

        let mut last_known_time = std::time::Instant::now();
        for sample in samples.into_iter() {
            let mut frames = Vec::new();
            for frame in sample.stack {
                frames.push(Frame::Label(thread_builder.intern_string(&frame)))
            }

            thread_builder.add_sample(
                last_known_time,
                frames.into_iter(),
                // this is actually in instructions but
                std::time::Duration::from_micros(self.sample_rate as u64),
            );

            last_known_time += std::time::Duration::from_micros(self.sample_rate as u64);
        }

        profile_builder.add_thread(thread_builder);

        let canon_path = crate::util::canon_path(&self.output)?;
        let mut file = std::fs::File::create(&canon_path)?;
        serde_json::to_writer(&mut file, &profile_builder.to_serializable())?;

        if !self.no_open && has_samply() {
            samply_load(&canon_path);
        }

        Ok(())
    }
}

fn build_goblin_lookups(
    start_lookup: &mut HashMap<u64, usize>,
    end_lookup: &mut HashMap<u64, usize>,
    func_range_lookup: &mut Vec<(u64, u64, Rc<str>)>,
    elf_name: impl AsRef<Path>,
) -> Result<()> {
    let buffer = std::fs::read(elf_name).context("Failed to open elf file")?;
    let elf = Elf::parse(&buffer).context("Failed to parse elf file")?;

    for sym in &elf.syms {
        if sym.st_type() == STT_FUNC {
            let name = elf.strtab.get_at(sym.st_name).unwrap_or("");
            let demangled_name = demangle(name);
            let size = sym.st_size;
            let start_address = sym.st_value;
            let end_address = start_address + size - 4;
            let demangled: Rc<str> = demangled_name.to_string().into();

            let index = func_range_lookup.len();
            func_range_lookup.push((start_address, end_address, demangled));
            start_lookup.insert(start_address, index);
            end_lookup.insert(end_address, index);
        }
    }
    Ok(())
}

pub fn collect_samples(
    elf_path: impl AsRef<Path>,
    trace_path: impl AsRef<Path>,
    sample_rate: u64,
) -> Result<Vec<Sample>> {
    let trace_path = trace_path.as_ref();

    let mut start_lookup = HashMap::new();
    let mut end_lookup = HashMap::new();
    let mut function_ranges = Vec::new();
    build_goblin_lookups(&mut start_lookup, &mut end_lookup, &mut function_ranges, elf_path)?;

    let file = std::fs::File::open(trace_path).context("Failed to open trace path file")?;
    let file_size = file.metadata().unwrap().len();
    let mut buf = std::io::BufReader::new(file);
    let mut function_stack: Vec<Rc<str>> = Vec::new();
    let mut function_stack_indices: Vec<usize> = Vec::new();
    let mut function_stack_ranges: Vec<(u64, u64)> = Vec::new();
    let total_lines = file_size / 4;
    let mut current_function_range: (u64, u64) = (0, 0);

    // unsafe on 32 bit systems but ...
    let mut samples = Vec::with_capacity(total_lines as usize);
    for i in 0..total_lines {
        if i % 1000000 == 0 {
            println!("Processed {} cycles ({:.2}%)", i, i as f64 / total_lines as f64 * 100.0);
        }

        // Parse pc from hex.
        let mut pc_bytes = [0u8; 4];
        buf.read_exact(&mut pc_bytes).unwrap();
        let pc = u32::from_be_bytes(pc_bytes) as u64;

        // We are still in the current function.
        if pc > current_function_range.0 && pc <= current_function_range.1 {
            if i % sample_rate == 0 {
                samples.push(Sample { stack: function_stack.clone() });
            }

            continue;
        }

        // Jump to a new function (or the same one).
        if let Some(f) = start_lookup.get(&pc) {
            if i % sample_rate == 0 {
                samples.push(Sample { stack: function_stack.clone() });
            }

            // Jump to a new function (not recursive).
            if !function_stack_indices.contains(f) {
                function_stack_indices.push(f.clone());
                let (start, end, name) = function_ranges.get(*f).unwrap();
                current_function_range = (*start, *end);
                function_stack_ranges.push((*start, *end));
                function_stack.push(name.clone());
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
            for (c, (f, (s, e))) in
                function_stack_indices.iter().zip(function_stack_ranges.iter()).enumerate()
            {
                if pc > *s && pc <= *e {
                    unwind_point = c;
                    unwind_found = true;
                    break;
                }
            }

            // Unwinding until the parent.
            if unwind_found {
                function_stack.truncate(unwind_point + 1);
                function_stack_ranges.truncate(unwind_point + 1);
                function_stack_indices.truncate(unwind_point + 1);
                if i % sample_rate == 0 {
                    samples.push(Sample { stack: function_stack.clone() });
                }
                continue;
            }

            // If no unwind point has been found, that means we jumped to some random location
            // so we'll just increment the counts for everything in the stack.
            if i % sample_rate == 0 {
                samples.push(Sample { stack: function_stack.clone() });
            }
        }
    }

    Ok(samples)
}

/// ensure the samples collected appear valid
/// for now, we just make sure that the `main` function is present
/// for at least 90% of the samples
///
/// Panics if the samples are invalid
fn check_samples(samples: &[Sample]) -> Result<()> {
    let main_count = samples.iter().filter(|s| s.stack.iter().any(|f| &**f == "main")).count();

    let main_ratio = main_count as f64 / samples.len() as f64;
    if main_ratio < 0.9 {
        println!("Warning: This trace appears to be invalid. The `main` function is present in only {:.2}% of the samples, this is likely caused by the using the wrong Elf file", main_ratio * 100.0);
    }

    Ok(())
}

fn has_samply() -> bool {
    let samply = std::process::Command::new("samply")
        .stdout(Stdio::null())
        .arg("--version")
        .status()
        .is_ok();

    if !samply {
        println!("Samply not found. Please install it to view the profile in your browser.");
        println!("cargo install --locked samply");
    }

    samply
}

fn samply_load(file: impl AsRef<Path>) {
    println!("Loading profile with samply");
    let status = std::process::Command::new("samply")
        .arg("load")
        .arg(file.as_ref())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .status();

    if let Err(e) = status {
        eprintln!("Failed to load samply profile: {}", e);
    }
}
