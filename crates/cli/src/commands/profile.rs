use clap::Parser;
use gecko_profile::{Frame, ProfileBuilder, ThreadBuilder};
use std::path::PathBuf;

use anyhow::Result;
use goblin::elf::{sym::STT_FUNC, Elf};
use rustc_demangle::demangle;
use std::{cmp::Ordering, collections::HashMap, io::Read, path::Path, rc::Rc, str};

#[derive(Parser, Debug)]
#[command(name = "profile", about = "Create a gecko profile from a trace file.")]
pub struct ProfileCmd {
    /// Path to the ELF.
    #[arg(long, required = true)]
    elf: PathBuf,

    /// Path to the trace file. Simply run the program with `TRACE_FILE=trace.log` environment
    /// variable. File must be one u64 program counter per line
    #[arg(long, required = true)]
    trace: PathBuf,

    /// The output file to write the gecko profile to
    #[arg(short = 'o', long)]
    output: PathBuf,
}

pub struct Sample {
    /// cheaper than allocating a String per sample
    pub stack: Vec<Rc<str>>,
}

impl ProfileCmd {
    pub fn run(&self) -> anyhow::Result<()> {
        let samples = collect_samples(&self.elf, &self.trace)?;

        println!("Profiled samples len: {}", samples.len());

        let start_time = std::time::Instant::now();
        let mut profile_builder = ProfileBuilder::new(
            start_time,
            std::time::SystemTime::now(),
            "sp1",
            0,
            std::time::Duration::from_micros(1),
        );

        let mut thread_builder = ThreadBuilder::new(1, 0, start_time, false, false);

        let mut last_known_time = std::time::Instant::now();
        for sample in samples {
            let mut frames = Vec::new();
            for frame in sample.stack {
                frames.push(Frame::Label(thread_builder.intern_string(&frame)))
            }

            thread_builder.add_sample(
                last_known_time,
                frames.into_iter(),
                // this is actually in instructions but
                std::time::Duration::from_micros(1),
            );

            last_known_time += std::time::Duration::from_micros(1);
        }

        profile_builder.add_thread(thread_builder);

        let mut file = std::fs::File::create(&self.output)?;
        serde_json::to_writer(&mut file, &profile_builder.to_serializable())?;

        Ok(())
    }
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

pub fn collect_samples(
    elf_path: impl AsRef<Path>,
    trace_path: impl AsRef<Path>,
) -> Result<Vec<Sample>> {
    let elf_path = elf_path.as_ref();
    let trace_path = trace_path.as_ref();

    let mut start_lookup = HashMap::new();
    let mut end_lookup = HashMap::new();
    let mut func_range_lookup = HashMap::new();
    build_goblin_lookups(
        &mut start_lookup,
        &mut end_lookup,
        &mut func_range_lookup,
        &elf_path.to_string_lossy(),
    )
    .unwrap();

    let mut function_ranges: Vec<(u64, u64, String)> =
        func_range_lookup.iter().map(|(f, &(start, end))| (start, end, f.clone())).collect();

    function_ranges.sort_by_key(|&(start, _, _)| start);

    let file = std::fs::File::open(trace_path).unwrap();
    let file_size = file.metadata().unwrap().len();
    let mut buf = std::io::BufReader::new(file);
    let mut function_stack: Vec<Rc<str>> = Vec::new();
    let mut counts_without_callgraph: HashMap<String, usize> = HashMap::new();
    let total_lines = file_size / 4;
    let mut current_function_range: (u64, u64) = (0, 0);

    // unsafe on 32 bit systems but ...
    let mut samples = Vec::with_capacity(total_lines as usize);
    for _ in 0..total_lines {
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
            samples.push(Sample { stack: function_stack.clone() });

            continue;
        }

        // Jump to a new function (or the same one).
        if let Some(f) = start_lookup.get(&pc) {
            samples.push(Sample { stack: function_stack.clone() });

            // Jump to a new function (not recursive).
            if !function_stack.iter().any(|stack_item| &**stack_item == f.as_str()) {
                function_stack.push(f.clone().into());
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
                let (s, e) = func_range_lookup.get(&**f).unwrap();
                if pc > *s && pc <= *e {
                    unwind_point = c;
                    unwind_found = true;
                    break;
                }
            }

            // Unwinding until the parent.
            if unwind_found {
                function_stack.truncate(unwind_point + 1);
                samples.push(Sample { stack: function_stack.clone() });
                continue;
            }

            // If no unwind point has been found, that means we jumped to some random location
            // so we'll just increment the counts for everything in the stack.
            samples.push(Sample { stack: function_stack.clone() });
        }
    }

    Ok(samples)
}
