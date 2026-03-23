#![allow(clippy::fn_to_numeric_cast)]

use super::{TranspilerBackend, CONTEXT};
use crate::{
    DebugFn, EcallHandler, ExternFn, JitFunction, JitMemory, RiscOperand, RiscRegister,
    RiscvTranspiler,
};
use dynasmrt::{
    dynasm,
    mmap::MutableBuffer,
    x64::{Rq, X64Relocation},
    DynasmApi, VecAssembler,
};
use hashbrown::HashMap;
use std::io;

impl RiscvTranspiler for TranspilerBackend {
    fn new(
        program_size: usize,
        memory_size: usize,
        max_trace_size: u64,
        pc_start: u64,
        pc_base: u64,
        clk_bump: u64,
    ) -> Result<Self, std::io::Error> {
        if pc_start < pc_base {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "pc_start must be greater than pc_base",
            ));
        }

        let mut this = Self {
            inner: VecAssembler::<X64Relocation>::new(0),
            jump_table: Vec::with_capacity(program_size),
            memory_size,
            has_instructions: false,
            pc_base,
            pc_start,
            // Register a dummy ecall handler.
            ecall_handler: super::ecallk as _,
            control_flow_instruction_inserted: false,
            instruction_started: false,
            branch_generated: false,
            clk_bump,
            max_trace_size,
            may_early_exit: false,
            pc_current: pc_base,
            reg_values: HashMap::new(),
            labels: HashMap::new(),
            program_size,
            ecall_ptr_offsets: Vec::new(),
            unimp_ptr_offsets: Vec::new(),
            unimp_handler: super::unimpk as _,
            has_non_ecall_extern_calls: false,
        };

        // Handle calling conventions and save anything were gonna clobber.
        this.prologue();

        Ok(this)
    }

    fn register_ecall_handler(&mut self, handler: EcallHandler) {
        self.ecall_handler = handler;
    }

    fn start_instr(&mut self) {
        // We dont want to compile without a single jumpdest, otherwise we will sigsegv.
        self.has_instructions = true;

        // If the instruction has already started, then we are in a bad state.
        if self.instruction_started {
            panic!("start_instr called without calling end_instr");
        }

        // Push the offset of the jumpdest for this instruction.
        let offset = self.inner.offset();
        self.jump_table.push(offset.0);

        // We are now "within" an instruction.
        self.instruction_started = true;
    }

    fn end_instr(&mut self) {
        if self.control_flow_instruction_inserted {
            // Control flow instructions might have multiple branch targets,
            // as a result, we let them call `end_branch` directly. Here we
            // only handle bookkeeping tasks for control flow instructions.
            if !self.branch_generated {
                panic!("No branch has been generated, maybe a JIT mistake?");
            }

            // When basic block ends, reset all transpile-time register values, as they
            // would be incorrect for the next basic block.
            self.reg_values.clear();
        } else {
            // Add the base amount of cycles for the instruction.
            self.bump_clk();

            // We only bump / update PC when:
            // * A control flow instruction is executing.
            // * Before ecall and unimp calls extern functions.
            // * When trace is complete, execution suspends.
            // For normal, sequential operations, there is no need to bump PC.

            // We dont have a control flow insruction so we need to bump the pc first.
            if self.may_early_exit {
                self.exit_if_trace_exceeds(self.max_trace_size);
            }
        }

        // Transpiling is done for current instruction
        self.pc_current += 4;

        self.may_early_exit = false;
        self.control_flow_instruction_inserted = false;
        self.instruction_started = false;
        self.branch_generated = false;
    }

    fn finalize<M: JitMemory>(mut self) -> io::Result<JitFunction<M>> {
        self.epilogue();

        let code_bytes = self.inner.finalize().expect("failed to finalize x86 backend");
        debug_assert!(!code_bytes.is_empty(), "Got empty x86 code buffer");

        // VecAssembler produces plain bytes; copy into executable memory.
        let code_len = code_bytes.len();
        let mut buf = MutableBuffer::new(code_len)?;
        buf.set_len(code_len);
        buf[..].copy_from_slice(&code_bytes);
        let exec_buf = buf.make_exec()?;

        JitFunction::new(exec_buf, self.jump_table, self.memory_size, self.pc_start)
    }

    fn call_extern_fn(&mut self, fn_ptr: ExternFn) {
        // Load the JitContext pointer into the argument register.
        dynasm! {
            self;
            .arch x64;
            mov rdi, Rq(CONTEXT)
        };

        // Non-ECALL external call: the pointer cannot be patched at restore time.
        let _ = self.call_extern_fn_raw(fn_ptr as _);
        self.has_non_ecall_extern_calls = true;
    }

    fn inspect_register(&mut self, reg: RiscRegister, handler: DebugFn) {
        // Load into the argument register for the function call.
        self.emit_risc_operand_load(RiscOperand::Register(reg), Rq::RDI as u8);

        // Non-ECALL external call: the pointer cannot be patched at restore time.
        let _ = self.call_extern_fn_raw(handler as _);
        self.has_non_ecall_extern_calls = true;
    }

    fn inspect_immediate(&mut self, imm: u64, handler: DebugFn) {
        dynasm! {
            self;
            .arch x64;

            mov rdi, imm as i32
        }

        // Non-ECALL external call: the pointer cannot be patched at restore time.
        let _ = self.call_extern_fn_raw(handler as _);
        self.has_non_ecall_extern_calls = true;
    }
}

use crate::CompiledCode;

impl TranspilerBackend {
    /// Register the handler called when an `unimp` instruction is executed.
    pub fn register_unimp_handler(&mut self, handler: ExternFn) {
        self.unimp_handler = handler;
    }

    /// Finalize the backend and return a [`CompiledCode`] snapshot instead of a
    /// [`JitFunction`].
    ///
    /// This is the save-side of the JIT cache: after calling this you can
    /// persist the blob with [`CompiledCode::save`] and later restore it with
    /// [`JitFunction::from_compiled_code`].
    ///
    /// Unlike [`RiscvTranspiler::finalize`], this method does **not** allocate
    /// JIT memory or build a live jump table, so it is suitable for offline
    /// code-generation pipelines.
    ///
    /// # Note on embedded function pointers
    ///
    /// Function pointers (e.g. the ECALL handler, precompile stubs) are embedded
    /// as 64-bit immediates in the generated code.  The returned [`CompiledCode`]
    /// records their locations in [`CompiledCode::fn_ptr_relocations`] so that
    /// they can be patched when restoring in a different address space.
    pub fn into_compiled_code(mut self) -> io::Result<CompiledCode> {
        // Fail fast: non-ECALL external calls embed arbitrary function pointers that
        // are unknown at restore time and cannot be patched, so caching is unsafe.
        if self.has_non_ecall_extern_calls {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot serialize JIT code that contains external function calls other than \
                 the ECALL and UNIMP handlers (e.g. call_extern_fn, inspect_register, \
                 inspect_immediate); those embedded pointers cannot be patched when restoring",
            ));
        }

        self.epilogue();

        // VecAssembler::finalize() resolves all internal relocations and returns
        // the raw bytes directly — no mmap allocation or buffer copy required.
        let code = self.inner.finalize().expect("failed to finalize x86 backend");
        debug_assert!(!code.is_empty(), "Got empty x86 code buffer");

        Ok(CompiledCode {
            code,
            jump_table: self.jump_table,
            pc_start: self.pc_start,
            pc_base: self.pc_base,
            memory_size: self.memory_size,
            max_trace_size: self.max_trace_size,
            ecall_ptr_offsets: self.ecall_ptr_offsets,
            unimp_ptr_offsets: self.unimp_ptr_offsets,
        })
    }
}
