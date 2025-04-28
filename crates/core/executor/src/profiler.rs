use gecko_profile::{Frame, ProfileBuilder, StringIndex, ThreadBuilder};
use gimli::{
    AttributeValue, DW_AT_high_pc, DW_AT_ranges, DW_TAG_inlined_subroutine, DebugInfoOffset,
    DebuggingInformationEntry, DwAt, Dwarf, EndianArcSlice, Range, Reader, RunTimeEndian,
    SectionId, Unit, UnitOffset,
};
use goblin::elf::{sym::STT_FUNC, Elf};
use indicatif::{ProgressBar, ProgressStyle};
use object::{File, Object, ObjectSection};
use rustc_demangle::demangle;
use std::{borrow::Cow, collections::HashMap, sync::Arc};

use crate::StackEvent;

#[derive(Debug, thiserror::Error)]
pub enum ProfilerError {
    #[error("Failed to read ELF file {}", .0)]
    Io(#[from] std::io::Error),
    #[error("Failed to parse ELF file {}", .0)]
    Elf(#[from] goblin::error::Error),
    #[error("Failed to serialize samples {}", .0)]
    Serde(#[from] serde_json::Error),
    #[error("Failed retrieve inline functions {}", .0)]
    InlineRetrieval(#[from] gimli::Error),
    #[error("No unit for offset {}", .0)]
    NoUnitForOffset(usize),
    #[error("Invalid abstract origin")]
    InvalidAbstractOrigin,
    #[error("DwAt {} missing", .0)]
    DwAtMissing(DwAt),
    #[error("Onvalid attribute abstract origin")]
    InvalidAttributeAbstractOrigin,
    #[error("Unexpected abstract origin")]
    UnexpectedAbstractOrigin,
    #[error("Unexpected low pc")]
    UnexpectedLowPc,
}

/// During execution, the profiler always keeps track of the callstack
/// and will occasionally save the stack according to the sample rate.
pub struct Profiler {
    sample_rate: u64,
    /// `start_address`-> index in `function_ranges`
    start_lookup: HashMap<u64, usize>,
    /// `start_address`-> index in `function_ranges` for inlined functions
    inline_functions_start_lookup: HashMap<u64, Vec<usize>>,
    /// the start and end of the function
    function_ranges: Vec<(u64, u64, Frame)>,

    /// the current known call stack
    function_stack: Vec<Function>,
    pop_stack: Vec<u64>,

    main_idx: Option<StringIndex>,
    builder: ThreadBuilder,
    samples: Vec<Sample>,
}

struct Sample {
    stack: Vec<Frame>,
}

#[derive(Debug, PartialEq, Eq)]
struct Function {
    pub frame: Frame,
    pub kind: FunctionKind,
}

impl Function {
    pub fn regular(frame: Frame) -> Self {
        Self { frame, kind: FunctionKind::Regular }
    }

    pub fn inline(frame: Frame, start: u64, end: u64) -> Self {
        Self { frame, kind: FunctionKind::inline(start, end) }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum FunctionKind {
    Regular,
    Inline { start: u64, end: u64 },
}

impl FunctionKind {
    pub fn inline(start: u64, end: u64) -> Self {
        Self::Inline { start, end }
    }
}

impl Profiler {
    pub(super) fn new(elf_bytes: &[u8], sample_rate: u64) -> Result<Self, ProfilerError> {
        let elf = Elf::parse(elf_bytes)?;
        let mut start_lookup = HashMap::new();
        let mut inline_functions_start_lookup = HashMap::new();
        let mut function_ranges = Vec::new();
        let mut builder = ThreadBuilder::new(1, 0, std::time::Instant::now(), false, false);
        let mut frames_to_names = HashMap::new();
        // We need to extract all the functions from the ELF file
        // and their corresponding PC ranges.
        let mut main_idx = None;
        for sym in &elf.syms {
            // check if its a function
            if sym.st_type() == STT_FUNC {
                let name = elf.strtab.get_at(sym.st_name).unwrap_or("");
                let demangled_name = demangle(name);
                let size = sym.st_size;
                let start_address = sym.st_value;
                let end_address = start_address + size - 4;

                // Now that we have the name let's immediately intern it so we only need to copy
                // around a usize
                let demangled_name = demangled_name.to_string();
                let string_idx = builder.intern_string(&demangled_name);
                if main_idx.is_none() && demangled_name == "main" {
                    main_idx = Some(string_idx);
                }

                let start_idx = function_ranges.len();
                function_ranges.push((start_address, end_address, Frame::Label(string_idx)));
                frames_to_names.insert(start_address, demangled_name.clone());
                start_lookup.insert(start_address, start_idx);
            }
        }

        if trace_inline_functions() {
            let file = File::parse(elf_bytes).unwrap();
            let dwarf = load_dwarf(&file)?;
            let inline_fn_builder = InlineFunctionFrameBuilder::new(&dwarf);
            let mut iter = dwarf.units();

            while let Some(header) = iter.next()? {
                let unit = dwarf.unit(header)?;

                let mut entries = unit.entries();
                while let Some((_, entry)) = entries.next_dfs()? {
                    if entry.tag() == DW_TAG_inlined_subroutine {
                        inline_fn_builder.build(
                            &unit,
                            entry,
                            &mut builder,
                            &mut function_ranges,
                            &mut inline_functions_start_lookup,
                        )?;
                    }
                }
            }
        }

        Ok(Self {
            builder,
            main_idx,
            sample_rate,
            samples: Vec::new(),
            start_lookup,
            inline_functions_start_lookup,
            function_ranges,
            function_stack: Vec::new(),
            pop_stack: Vec::new(),
        })
    }

    pub(super) fn record(
        &mut self,
        clk: u64,
        pc: u64,
        previous_pc: u64,
        stack_event: Option<&StackEvent>,
    ) {
        if let Some(stack_event) = stack_event {
            if stack_event.is_pop() {
                loop {
                    // Pop all inline functions
                    while matches!(
                        self.function_stack.last().map(|f| f.kind),
                        Some(FunctionKind::Inline { .. })
                    ) {
                        self.function_stack.pop();
                    }

                    self.function_stack.pop();
                    let popped = self.pop_stack.pop().unwrap();

                    if popped == pc - 4 {
                        break;
                    }
                }
            }

            if stack_event.is_push() {
                if let Some(f) = self.start_lookup.get(&pc) {
                    // Jump to a new function.
                    let (_, _, name) = self.function_ranges.get(*f).unwrap();
                    self.function_stack.push(Function::regular(name.clone()));
                    self.pop_stack.push(previous_pc);
                }
            }
        }

        // Pop inline functions when the current PC is not in theirs range
        loop {
            let Some(FunctionKind::Inline { start, end }) =
                self.function_stack.last().map(|f| f.kind)
            else {
                break;
            };

            if start <= pc && pc < end {
                break;
            }
            self.function_stack.pop();
        }

        // Push all inline functions that starts at the current PC
        if let Some(inline_functions) = self.inline_functions_start_lookup.get(&pc) {
            for f in inline_functions {
                let (start, end, name) = self.function_ranges.get(*f).unwrap();
                let f = Function::inline(name.clone(), *start, *end);
                if self.function_stack.last() != Some(&f) {
                    self.function_stack.push(f);
                }
            }
        }

        if clk % self.sample_rate == 0 {
            self.samples.push(Sample {
                stack: self.function_stack.iter().map(|f| f.frame.clone()).collect(),
            });
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

struct InlineFunctionFrameBuilder<'a> {
    dwarf: &'a Dwarf<EndianArcSlice<RunTimeEndian>>,
    units: Vec<Unit<EndianArcSlice<RunTimeEndian>>>,
}

impl<'a> InlineFunctionFrameBuilder<'a> {
    pub fn new(dwarf: &'a Dwarf<EndianArcSlice<RunTimeEndian>>) -> Self {
        let mut units = vec![];
        let mut iter = dwarf.units();

        while let Some(header) = iter.next().unwrap() {
            units.push(dwarf.unit(header).unwrap());
        }
        Self { dwarf, units }
    }

    pub fn build(
        &self,
        unit: &Unit<EndianArcSlice<RunTimeEndian>>,
        entry: &DebuggingInformationEntry<'_, '_, EndianArcSlice<RunTimeEndian>>,
        thread_builder: &mut ThreadBuilder,
        function_ranges: &mut Vec<(u64, u64, Frame)>,
        start_lookup: &mut HashMap<u64, Vec<usize>>,
    ) -> Result<(), ProfilerError> {
        let name = self.get_abstract_origin_name(unit, entry)?;

        let demangled_name = demangle(&name).to_string();

        if demangled_name.starts_with("core::") ||
            demangled_name.starts_with("<core::") ||
            demangled_name.contains(" as core::")
        {
            return Ok(());
        }

        let mut ranges = vec![];

        if let Some(range) = self.get_pc_range(unit, entry)? {
            ranges.push(range);
        } else {
            ranges.extend(self.get_pc_ranges(unit, entry)?);
        }

        for (low_pc, high_pc) in ranges {
            let string_idx = thread_builder.intern_string(&demangled_name);
            let start_idx = function_ranges.len();
            let start_lookup_entry = start_lookup.entry(low_pc).or_default();

            start_lookup_entry.push(start_idx);
            function_ranges.push((low_pc, high_pc, Frame::Label(string_idx)));

            eprintln!("{demangled_name} {low_pc} -> {high_pc}, {string_idx:?}");
        }

        Ok(())
    }

    fn get_pc_ranges(
        &self,
        unit: &Unit<EndianArcSlice<RunTimeEndian>>,
        entry: &DebuggingInformationEntry<'_, '_, EndianArcSlice<RunTimeEndian>>,
    ) -> Result<Vec<(u64, u64)>, gimli::Error> {
        let Ok(value) = dwarf_attr(entry, DW_AT_ranges) else {
            return Ok(vec![]);
        };

        let Some(ranges_offset) = self.dwarf.attr_ranges_offset(unit, value)? else {
            return Ok(vec![]);
        };

        let mut ranges = vec![];
        let mut range_iter = self.dwarf.ranges(unit, ranges_offset)?;
        while let Some(Range { begin, end }) = range_iter.next()? {
            if begin < end && begin != 0 {
                ranges.push((begin, end));
            }
        }

        Ok(ranges)
    }

    fn get_pc_range(
        &self,
        unit: &Unit<EndianArcSlice<RunTimeEndian>>,
        entry: &DebuggingInformationEntry<'_, '_, EndianArcSlice<RunTimeEndian>>,
    ) -> Result<Option<(u64, u64)>, ProfilerError> {
        let Some(low_pc) = self.get_low_pc(unit, entry)? else {
            return Ok(None);
        };
        let high_pc = self.get_high_pc(unit, entry, low_pc)?;

        Ok(Some((low_pc, high_pc)))
    }

    fn get_low_pc(
        &self,
        unit: &gimli::Unit<gimli::EndianArcSlice<gimli::RunTimeEndian>>,
        entry: &gimli::DebuggingInformationEntry<
            '_,
            '_,
            gimli::EndianArcSlice<gimli::RunTimeEndian>,
        >,
    ) -> Result<Option<u64>, ProfilerError> {
        let Ok(value) = dwarf_attr(entry, gimli::DW_AT_low_pc) else {
            return Ok(None);
        };
        let low_pc = match value {
            AttributeValue::Addr(val) => Ok(val),
            AttributeValue::DebugAddrIndex(index) => Ok(self.dwarf.address(unit, index)?),
            _ => Err(ProfilerError::UnexpectedLowPc),
        }?;
        Ok((low_pc != 0).then_some(low_pc))
    }

    fn get_high_pc(
        &self,
        unit: &Unit<EndianArcSlice<RunTimeEndian>>,
        entry: &DebuggingInformationEntry<'_, '_, EndianArcSlice<RunTimeEndian>>,
        low_pc: u64,
    ) -> Result<u64, ProfilerError> {
        match dwarf_attr(entry, DW_AT_high_pc)? {
            AttributeValue::Addr(val) => Ok(val),
            AttributeValue::DebugAddrIndex(index) => Ok(self.dwarf.address(unit, index)?),
            AttributeValue::Udata(val) => Ok(low_pc + val),
            _ => Err(ProfilerError::UnexpectedAbstractOrigin),
        }
    }

    fn get_abstract_origin_name(
        &self,
        unit: &Unit<EndianArcSlice<RunTimeEndian>>,
        entry: &DebuggingInformationEntry<'_, '_, EndianArcSlice<RunTimeEndian>>,
    ) -> Result<String, ProfilerError> {
        match dwarf_attr(entry, gimli::DW_AT_abstract_origin)? {
            gimli::AttributeValue::UnitRef(unit_offset) => {
                Ok(get_abstract_origin_name(self.dwarf, unit, unit_offset)?)
            }
            gimli::AttributeValue::DebugInfoRef(debug_info_offset) => {
                let unit = find_unit(self.units.as_slice(), debug_info_offset)?;
                let unit_offset = debug_info_offset
                    .to_unit_offset(&unit.header)
                    .ok_or(ProfilerError::InvalidAttributeAbstractOrigin)?;
                Ok(get_abstract_origin_name(self.dwarf, unit, unit_offset)?)
            }
            _ => Err(ProfilerError::UnexpectedAbstractOrigin),
        }
    }
}

fn load_dwarf(file: &File) -> Result<Dwarf<EndianArcSlice<RunTimeEndian>>, ProfilerError> {
    let endian = if file.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    let dwarf = Dwarf::load(&|id| Ok::<_, gimli::Error>(load_section(id, file, endian)))?;

    Ok(dwarf)
}

fn load_section(
    id: SectionId,
    file: &File,
    endian: RunTimeEndian,
) -> EndianArcSlice<RunTimeEndian> {
    let data = file
        .section_by_name(id.name())
        .and_then(|section| section.uncompressed_data().ok())
        .unwrap_or(Cow::Borrowed(&[]));

    EndianArcSlice::new(Arc::from(&*data), endian)
}

fn dwarf_attr<ReaderT: Reader>(
    entry: &DebuggingInformationEntry<'_, '_, ReaderT>,
    dw_at: DwAt,
) -> Result<AttributeValue<ReaderT>, ProfilerError> {
    Ok(entry.attr(dw_at)?.ok_or(ProfilerError::DwAtMissing(dw_at))?.value())
}

fn get_abstract_origin_name(
    dwarf: &Dwarf<EndianArcSlice<RunTimeEndian>>,
    unit: &Unit<EndianArcSlice<RunTimeEndian>>,
    abstract_origin: UnitOffset<usize>,
) -> Result<String, ProfilerError> {
    let mut entries = unit.entries_raw(Some(abstract_origin))?;
    let abbrev = entries.read_abbreviation()?.ok_or(ProfilerError::InvalidAbstractOrigin)?;

    for spec in abbrev.attributes() {
        let attr = entries.read_attribute(*spec)?;
        match attr.name() {
            gimli::DW_AT_linkage_name | gimli::DW_AT_MIPS_linkage_name => {
                return Ok(dwarf.attr_string(unit, attr.value())?.to_string_lossy()?.into());
            }
            gimli::DW_AT_name => {
                return Ok(dwarf.attr_string(unit, attr.value())?.to_string_lossy()?.into());
            }
            _ => {}
        }
    }

    Err(ProfilerError::InvalidAbstractOrigin)
}

fn find_unit(
    units: &[Unit<EndianArcSlice<RunTimeEndian>>],
    offset: DebugInfoOffset<usize>,
) -> Result<&Unit<EndianArcSlice<RunTimeEndian>>, ProfilerError> {
    match units.binary_search_by_key(&offset.0, |unit| {
        unit.header.offset().as_debug_info_offset().unwrap().0
    }) {
        Ok(_) | Err(0) => Err(ProfilerError::NoUnitForOffset(offset.0)),
        Err(i) => Ok(&units[i - 1]),
    }
}

fn trace_inline_functions() -> bool {
    let value = std::env::var("TRACE_INLINE_FUNCTIONS").unwrap_or_else(|_| "false".to_string());
    value == "1" || value.to_lowercase() == "true"
}
