#![allow(clippy::fn_to_numeric_cast)]

use super::{TranspilerBackend, CONTEXT};
use crate::{
    DebugFn, EcallHandler, ExternFn, JitFunction, RiscOperand, RiscRegister, RiscvTranspiler,
};
use dynasmrt::{
    dynasm,
    x64::{Assembler, Rq},
    DynasmApi,
};
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

        let inner = Assembler::new()?;

        // Allocate a trace buffer with enough headroom for the worst-case single-instruction
        // overflow. The chunk-stop check only runs between instructions, so a precompile ecall
        // can emit up to ~288 trace entries (sha256_extend) beyond max_trace_size.
        const MAX_SINGLE_INSTRUCTION_MEM_OPS: usize = 512;
        let capacity_bytes = if max_trace_size == 0 {
            0
        } else {
            let event_bytes = max_trace_size as usize * std::mem::size_of::<crate::MemValue>();
            // Scale by 10/9 for proportional leeway on large traces.
            let event_bytes = event_bytes * 10 / 9;
            // Add fixed headroom for worst-case single-instruction overflow.
            let worst_case_bytes =
                MAX_SINGLE_INSTRUCTION_MEM_OPS * std::mem::size_of::<crate::MemValue>();
            let header_bytes = std::mem::size_of::<crate::TraceChunkHeader>();
            event_bytes + worst_case_bytes + header_bytes
        };

        let mut this = Self {
            inner,
            jump_table: Vec::with_capacity(program_size),
            // Double the size of memory.
            // We are going to store entries of the form (clk, word).
            memory_size: memory_size * 2,
            trace_buf_size: capacity_bytes,
            has_instructions: false,
            pc_base,
            pc_start,
            // Register a dummy ecall handler.
            ecall_handler: super::ecallk as _,
            control_flow_instruction_inserted: false,
            instruction_started: false,
            clk_bump,
            max_trace_size,
            may_early_exit: false,
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
        // Add the base amount of cycles for the instruction.
        self.bump_clk();

        // If the instruction is branch, jal, jalr or ecall then we need to emit a jump to pc
        if self.control_flow_instruction_inserted {
            // If we have a control flow instruction that may early exit, we need to check if the
            // trace size has been exceeded.
            if self.may_early_exit {
                self.exit_if_trace_exceeds(self.max_trace_size);
            }

            self.jump_to_pc();
        } else {
            self.bump_pc(4);

            // We dont have a control flow insruction so we need to bump the pc first.
            if self.may_early_exit {
                self.exit_if_trace_exceeds(self.max_trace_size);
            }
        }

        self.may_early_exit = false;
        self.control_flow_instruction_inserted = false;
        self.instruction_started = false;
    }

    fn finalize(mut self) -> io::Result<JitFunction> {
        self.epilogue();

        let code = self.inner.finalize().expect("failed to finalize x86 backend");

        debug_assert!(code.size() > 0, "Got empty x86 code buffer");

        JitFunction::new(
            code,
            self.jump_table,
            self.memory_size,
            self.trace_buf_size,
            self.pc_start,
        )
    }

    fn call_extern_fn(&mut self, fn_ptr: ExternFn) {
        // Load the JitContext pointer into the argument register.
        dynasm! {
            self;
            .arch x64;
            mov rdi, Rq(CONTEXT)
        };

        self.call_extern_fn_raw(fn_ptr as _);
    }

    fn inspect_register(&mut self, reg: RiscRegister, handler: DebugFn) {
        // Load into the argument register for the function call.
        self.emit_risc_operand_load(RiscOperand::Register(reg), Rq::RDI as u8);

        // Call the handler with the value of the register.
        self.call_extern_fn_raw(handler as _);
    }

    fn inspect_immediate(&mut self, imm: u64, handler: DebugFn) {
        dynasm! {
            self;
            .arch x64;

            mov rdi, imm as i32
        }

        self.call_extern_fn_raw(handler as _);
    }
}
