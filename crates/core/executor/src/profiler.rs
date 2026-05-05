use crate::Program;
use gecko_profile::{Frame, ProfileBuilder, StringIndex, ThreadBuilder};
use hashbrown::HashMap;
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Debug, thiserror::Error)]
pub enum ProfilerError {
    #[error("Failed to read ELF file {}", .0)]
    Io(#[from] std::io::Error),
    #[error("Failed to parse ELF file {}", .0)]
    Elf(#[from] eyre::Error),
    #[error("Failed to serialize samples {}", .0)]
    Serde(#[from] serde_json::Error),
}

/// During execution, the profiler always keeps track of the callstack
/// and will occasionally save the stack according to the sample rate.
pub struct Profiler {
    sample_rate: u64,
    /// `start_address`-> index in `function_ranges`
    start_lookup: HashMap<u64, usize>,
    /// the start and end of the function
    function_ranges: Vec<(u64, u64, String, Frame)>,

    /// the current known call stack
    function_stack: Vec<Frame>,
    /// useful for quick search as to not count recursive calls
    function_stack_indices: Vec<usize>,
    /// The call stacks code ranges, useful for keeping track of unwinds
    function_stack_ranges: Vec<(u64, u64)>,
    /// The deepest function code range
    current_function_range: (u64, u64),

    main_idx: Option<StringIndex>,
    builder: ThreadBuilder,
    samples: Vec<Sample>,
}

struct Sample {
    stack: Vec<Frame>,
}

impl Profiler {
    pub(super) fn from_program(program: &Program, sample_rate: u64) -> Self {
        let mut start_lookup = HashMap::new();
        let mut function_ranges = Vec::new();
        let mut builder = ThreadBuilder::new(1, 0, std::time::Instant::now(), false, false);

        let mut main_idx = None;
        for (demangled_name, start_address, size) in &program.function_symbols {
            let end_address = start_address + size - 4;
            let string_idx = builder.intern_string(demangled_name);

            if main_idx.is_none() && demangled_name == "main" {
                main_idx = Some(string_idx);
            }

            let start_idx = function_ranges.len();
            function_ranges.push((
                *start_address,
                end_address,
                demangled_name.clone(),
                Frame::Label(string_idx),
            ));
            start_lookup.insert(*start_address, start_idx);
        }

        let mut function_stack = Vec::new();
        let mut function_stack_indices = Vec::new();
        let mut function_stack_ranges = Vec::new();

        for start_address in &program.dump_elf_stack {
            let idx = start_lookup[start_address];
            let (_, end_address, _, frame) = &function_ranges[idx];

            function_stack.push(frame.clone());
            function_stack_indices.push(idx);
            function_stack_ranges.push((*start_address, *end_address));
        }

        let current_function_range = function_stack_ranges.last().copied().unwrap_or_default();

        Self {
            builder,
            main_idx,
            sample_rate,
            samples: Vec::new(),
            start_lookup,
            function_ranges,
            function_stack,
            function_stack_indices,
            function_stack_ranges,
            current_function_range,
        }
    }

    pub(super) fn insert(&mut self, name: &str, addr: u64, len: u64) {
        let string_idx = self.builder.intern_string(name);
        let start_idx = self.function_ranges.len();
        self.function_ranges.push((
            addr,
            addr + len - 4,
            name.to_string(),
            Frame::Label(string_idx),
        ));
        self.start_lookup.insert(addr, start_idx);
    }

    pub(super) fn delete(&mut self, addr: u64) {
        let start_idx = self.start_lookup.get(&addr).copied();
        if let Some(start_idx) = start_idx {
            if start_idx == self.function_ranges.len() - 1 {
                self.function_ranges.pop();
            } else {
                let (last_start_address, last_end_address, last_name, last_label) =
                    self.function_ranges.pop().unwrap();
                self.function_ranges[start_idx] =
                    (last_start_address, last_end_address, last_name, last_label);
                self.start_lookup.insert(last_start_address, start_idx);
            }
            self.start_lookup.remove(&addr);
        }
    }

    pub(super) fn dump(&self) -> (Vec<(String, u64, u64)>, Vec<u64>) {
        let loaded_functions =
            self.function_ranges.iter().map(|f| (f.2.clone(), f.0, f.1 + 4 - f.0)).collect();
        let stack = self.function_stack_ranges.iter().map(|(start, _)| *start).collect();
        (loaded_functions, stack)
    }

    pub(super) fn record(&mut self, clk: u64, pc: u64) {
        // We are still in the current function.
        if pc > self.current_function_range.0 && pc <= self.current_function_range.1 {
            if clk.is_multiple_of(self.sample_rate) {
                self.samples.push(Sample { stack: self.function_stack.clone() });
            }

            return;
        }

        // Jump to a new function (or the same one).
        if let Some(f) = self.start_lookup.get(&pc) {
            // Jump to a new function (not recursive).
            if !self.function_stack_indices.contains(f) {
                self.function_stack_indices.push(*f);
                let (start, end, _, name) = self.function_ranges.get(*f).unwrap();
                self.current_function_range = (*start, *end);
                self.function_stack_ranges.push((*start, *end));
                self.function_stack.push(name.clone());
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
            for (c, (s, e)) in self.function_stack_ranges.iter().enumerate() {
                if pc > *s && pc <= *e {
                    unwind_point = c;
                    unwind_found = true;
                    break;
                }
            }

            // Unwinding until the parent.
            if unwind_found {
                self.function_stack.truncate(unwind_point + 1);
                self.function_stack_ranges.truncate(unwind_point + 1);
                self.function_stack_indices.truncate(unwind_point + 1);
            }

            // If no unwind point has been found, that means we jumped to some random location
            // so we'll just increment the counts for everything in the stack.
        }

        if clk.is_multiple_of(self.sample_rate) {
            self.samples.push(Sample { stack: self.function_stack.clone() });
        }
    }

    /// Write the captured samples so far to the `std::io::Write`. This will output a JSON gecko
    /// profile.
    pub(super) fn write(mut self, writer: impl std::io::Write) -> Result<(), ProfilerError> {
        self.check_samples();

        let start_time = std::time::Instant::now();
        let mut profile_builder = ProfileBuilder::new(
            start_time,
            std::time::SystemTime::now(),
            "SP1 ZKVM",
            0,
            std::time::Duration::from_micros(1),
        );

        let pb = ProgressBar::new(self.samples.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    #[allow(clippy::literal_string_with_formatting_args)]
                    "{msg} \n {spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
                )
                .unwrap()
                .progress_chars("#>-"),
        );

        pb.set_message("Creating profile");

        let mut last_known_time = std::time::Instant::now();
        for sample in self.samples.drain(..) {
            pb.inc(1);

            self.builder.add_sample(
                last_known_time,
                sample.stack.into_iter(),
                // We don't have a way to know the duration of each sample, so we just use 1us for
                // all instructions.
                std::time::Duration::from_micros(self.sample_rate),
            );

            last_known_time += std::time::Duration::from_micros(self.sample_rate);
        }

        profile_builder.add_thread(self.builder);

        pb.finish();

        eprintln!("Writing profile, this can take awhile");
        serde_json::to_writer(writer, &profile_builder.to_serializable())?;
        eprintln!("Profile written successfully");

        Ok(())
    }

    /// Simple check to makes sure we have valid main function that lasts
    /// for most of the execution time.
    fn check_samples(&self) {
        let Some(main_idx) = self.main_idx else {
            eprintln!(
                "Warning: The `main` function is not present in the Elf file, this is likely caused by using the wrong Elf file"
            );
            return;
        };

        let main_count = self
            .samples
            .iter()
            .filter(|s| {
                s.stack
                    .iter()
                    .any(|f| if let Frame::Label(idx) = f { *idx == main_idx } else { false })
            })
            .count();

        #[allow(clippy::cast_precision_loss)]
        let main_ratio = main_count as f64 / self.samples.len() as f64;
        if main_ratio < 0.9 {
            eprintln!(
                "Warning: This trace appears to be invalid. The `main` function is present in only {:.2}% of the samples, this is likely caused by the using the wrong Elf file",
                main_ratio * 100.0
            );
        }
    }
}
