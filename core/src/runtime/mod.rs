mod instruction;
mod opcode;
mod register;

pub use instruction::*;
pub use opcode::*;

use crate::prover::debug_cumulative_sums;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Pcs, UnivariatePcs, UnivariatePcsWithLde};
use p3_uni_stark::decompose_and_flatten;
use p3_util::log2_ceil_usize;
pub use register::*;

use crate::utils::AirChip;
use std::collections::BTreeMap;

use crate::alu::lt::LtChip;
use crate::alu::shift::ShiftChip;
use crate::memory::MemoryChip;
use crate::prover::debug_constraints;
use crate::prover::quotient_values;
use p3_field::{ExtensionField, PrimeField, TwoAdicField};
use p3_matrix::Matrix;
use p3_uni_stark::StarkConfig;
use p3_util::log2_strict_usize;

use crate::prover::generate_permutation_trace;
use crate::{
    alu::{add::AddChip, bitwise::BitwiseChip, sub::SubChip, AluEvent},
    cpu::{trace::CpuChip, CpuEvent},
    memory::{MemOp, MemoryEvent},
    program::ProgramChip,
};

/// An implementation of a runtime for the Curta VM.
///
/// The runtime is responsible for executing a user program and tracing important events which occur
/// during execution (i.e., memory reads, alu operations, etc).
///
/// For more information on the RV32IM instruction set, see the following:
/// https://www.cs.sfu.ca/~ashriram/Courses/CS295/assets/notebooks/RISCV/RISCV_CARD.pdf
pub struct Runtime {
    /// The clock keeps track of how many instructions have been executed.
    pub clk: u32,

    /// The program counter keeps track of the next instruction.
    pub pc: u32,

    /// The prgram used during execution.
    pub program: Vec<Instruction>,

    /// The memory which instructions operate over.
    pub memory: BTreeMap<u32, u32>,

    /// A trace of the CPU events which get emitted during execution.
    pub cpu_events: Vec<CpuEvent>,

    /// A trace of the memory events which get emitted during execution.
    pub memory_events: Vec<MemoryEvent>,

    /// A trace of the ADD, and ADDI events.
    pub add_events: Vec<AluEvent>,

    /// A trace of the SUB events.
    pub sub_events: Vec<AluEvent>,

    /// A trace of the XOR, XORI, OR, ORI, AND, and ANDI events.
    pub bitwise_events: Vec<AluEvent>,

    /// A trace of the SLL, SLLI, SRL, SRLI, SRA, and SRAI events.
    pub shift_events: Vec<AluEvent>,

    /// A trace of the SLT, SLTI, SLTU, and SLTIU events.
    pub lt_events: Vec<AluEvent>,
}

impl Runtime {
    /// Create a new runtime.
    pub fn new(program: Vec<Instruction>) -> Self {
        Self {
            clk: 0,
            pc: 0,
            memory: BTreeMap::new(),
            program,
            cpu_events: Vec::new(),
            memory_events: Vec::new(),
            add_events: Vec::new(),
            sub_events: Vec::new(),
            bitwise_events: Vec::new(),
            shift_events: Vec::new(),
            lt_events: Vec::new(),
        }
    }

    pub fn new_with_pc(program: Vec<Instruction>, init_pc: u32) -> Self {
        Self {
            clk: 0,
            pc: init_pc,
            memory: BTreeMap::new(),
            program,
            cpu_events: Vec::new(),
            memory_events: Vec::new(),
            add_events: Vec::new(),
            sub_events: Vec::new(),
            bitwise_events: Vec::new(),
            shift_events: Vec::new(),
            lt_events: Vec::new(),
        }
    }

    /// Read from memory.
    fn mr(&mut self, addr: u32) -> u32 {
        let value = match self.memory.get(&addr) {
            Some(value) => *value,
            None => 0,
        };
        self.emit_memory(self.clk, addr, MemOp::Read, value);
        return value;
    }

    /// Write to memory.
    fn mw(&mut self, addr: u32, value: u32) {
        self.memory.insert(addr, value);
        self.emit_memory(self.clk, addr, MemOp::Write, value);
    }

    /// Convert a register to a memory address.
    fn r2m(&self, register: Register) -> u32 {
        1024 * 1024 * 8 + (register as u32)
    }

    /// Read from register.
    fn rr(&mut self, register: Register) -> u32 {
        let addr = self.r2m(register);
        self.mr(addr)
    }

    /// Write to register.
    fn rw(&mut self, register: Register, value: u32) {
        if register == Register::X0 {
            // We don't write to %x0. See 2.6 Load and Store Instruction on
            // P.18 of the RISC-V spec.
            return;
        }
        let addr = self.r2m(register);
        self.mw(addr, value);
    }

    /// Get the current values of the registers.
    pub fn registers(&self) -> [u32; 32] {
        let mut registers = [0; 32];
        for i in 0..32 {
            let addr = self.r2m(Register::from_u32(i as u32));
            registers[i] = match self.memory.get(&addr) {
                Some(value) => *value,
                None => 0,
            };
        }
        return registers;
    }

    /// Fetch the instruction at the current program counter.
    fn fetch(&self) -> Instruction {
        let idx = (self.pc / 4) as usize;
        return self.program[idx];
    }

    /// Emit a CPU event.
    fn emit_cpu(
        &mut self,
        clk: u32,
        pc: u32,
        instruction: Instruction,
        a: u32,
        b: u32,
        c: u32,
        memory_value: Option<u32>,
    ) {
        self.cpu_events.push(CpuEvent {
            clk: clk,
            pc: pc,
            instruction,
            a,
            b,
            c,
            memory_value,
        });
    }

    /// Emit a memory event.
    fn emit_memory(&mut self, clk: u32, addr: u32, op: MemOp, value: u32) {
        self.memory_events.push(MemoryEvent {
            clk,
            addr,
            op,
            value,
        });
    }

    /// Emit an ALU event.
    fn emit_alu(&mut self, clk: u32, opcode: Opcode, a: u32, b: u32, c: u32) {
        let event = AluEvent {
            clk,
            opcode,
            a,
            b,
            c,
        };
        match opcode {
            Opcode::ADD | Opcode::ADDI => {
                self.add_events.push(event);
            }
            Opcode::SUB => {
                self.sub_events.push(event);
            }
            Opcode::XOR | Opcode::XORI | Opcode::OR | Opcode::ORI | Opcode::AND | Opcode::ANDI => {
                self.bitwise_events.push(event);
            }
            _ => {}
        }
    }

    /// Execute the given instruction over the current state of the runtime.
    fn execute(&mut self, instruction: Instruction) {
        let pc = self.pc;
        let (mut a, mut b, mut c, mut memory_value): (u32, u32, u32, Option<u32>) =
            (u32::MAX, u32::MAX, u32::MAX, None);

        // By default, we add 4 to the next PC. However, some instructions (e.g., JAL) will modify
        // this value.
        let mut next_pc = self.pc.wrapping_add(4);
        match instruction.opcode {
            // R-type instructions.
            Opcode::ADD => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = b.wrapping_add(c);
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SUB => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = b.wrapping_sub(c);
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::XOR => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = b ^ c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::OR => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = b | c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::AND => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = b & c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SLL => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = b << c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SRL => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = b >> c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SRA => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = (b as i32 >> c) as u32;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SLT => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = if (b as i32) < (c as i32) { 1 } else { 0 };
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SLTU => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = if b < c { 1 } else { 0 };
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }

            // I-type instructions.
            Opcode::ADDI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = b.wrapping_add(c);
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::XORI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = b ^ c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::ORI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = b | c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::ANDI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = b & c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SLLI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = b << c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SRLI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = b >> c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SRAI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = (b as i32 >> c) as u32;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SLTI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = if (b as i32) < (c as i32) { 1 } else { 0 };
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SLTIU => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = if b < c { 1 } else { 0 };
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }

            // Load instructions
            Opcode::LB => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                let addr = b.wrapping_add(c);
                memory_value = Some(self.mr(addr));
                a = (memory_value.unwrap() as i8) as u32;
                self.rw(rd, a);
            }
            Opcode::LH => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                let addr = b.wrapping_add(c);
                memory_value = Some(self.mr(addr));
                a = (memory_value.unwrap() as i16) as u32;
                self.rw(rd, a);
            }
            Opcode::LW => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                let addr = b.wrapping_add(c);
                memory_value = Some(self.mr(addr));
                a = memory_value.unwrap();
                self.rw(rd, a);
            }
            Opcode::LBU => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                let addr = b.wrapping_add(c);
                memory_value = Some(self.mr(addr));
                let a = (memory_value.unwrap() as u8) as u32;
                self.rw(rd, a);
            }
            Opcode::LHU => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                let addr = b.wrapping_add(c);
                memory_value = Some(self.mr(addr));
                let a = (memory_value.unwrap() as u16) as u32;
                self.rw(rd, a);
            }

            // S-type instructions.
            Opcode::SB => {
                let (rs1, rs2, imm) = instruction.s_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                let addr = b.wrapping_add(c);
                let value = (a as u8) as u32;
                memory_value = Some(value);
                self.mw(addr, value);
            }
            Opcode::SH => {
                let (rs1, rs2, imm) = instruction.s_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                let addr = b.wrapping_add(c);
                let value = (a as u16) as u32;
                memory_value = Some(value);
                self.mw(addr, value);
            }
            Opcode::SW => {
                let (rs1, rs2, imm) = instruction.s_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                let addr = b.wrapping_add(c);
                let value = a;
                memory_value = Some(value);
                self.mw(addr, value);
            }

            // B-type instructions.
            Opcode::BEQ => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if a == b {
                    next_pc = self.pc.wrapping_add(c);
                }
            }
            Opcode::BNE => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if self.rr(rs1) != self.rr(rs2) {
                    next_pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BLT => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if (self.rr(rs1) as i32) < (self.rr(rs2) as i32) {
                    next_pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BGE => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if (self.rr(rs1) as i32) >= (self.rr(rs2) as i32) {
                    next_pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BLTU => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if self.rr(rs1) < self.rr(rs2) {
                    next_pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BGEU => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if self.rr(rs1) >= self.rr(rs2) {
                    next_pc = self.pc.wrapping_add(imm);
                }
            }

            // Jump instructions.
            Opcode::JAL => {
                let (rd, imm) = instruction.j_type();
                (b, c) = (imm, 0);
                a = self.pc + 4;
                self.rw(rd, a);
                next_pc = self.pc.wrapping_add(imm);
            }
            Opcode::JALR => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = self.pc + 4;
                self.rw(rd, a);
                next_pc = b.wrapping_add(c);
            }

            // Upper immediate instructions.
            Opcode::LUI => {
                let (rd, imm) = instruction.u_type();
                (b, c) = (imm, 12); // Note that we'll special-case this in the CPU table
                a = b << 12;
                self.rw(rd, a);
            }
            Opcode::AUIPC => {
                let (rd, imm) = instruction.u_type();
                (b, c) = (imm, imm << 12); // Note that we'll special-case this in the CPU table
                a = self.pc.wrapping_add(b << 12);
                self.rw(rd, a);
            }

            // System instructions.
            Opcode::ECALL => {
                // While not all ECALLs obviously halt the CPU, we will for now halt. We need to
                // come back to this and figure out how to handle this properly.
                println!("ECALL encountered! Halting!");
                next_pc = self.program.len() as u32 * 4;
            }

            Opcode::EBREAK => {
                todo!()
            }

            // Multiply instructions.
            Opcode::MUL => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = b.wrapping_mul(c);
                self.rw(rd, a);
            }
            Opcode::MULH => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = ((b as i64).wrapping_mul(c as i64) >> 32) as u32;
                self.rw(rd, a);
            }
            Opcode::MULHSU => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = ((b as i64).wrapping_mul(c as i64) >> 32) as u32;
                self.rw(rd, a);
            }
            Opcode::MULHU => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = ((b as u64).wrapping_mul(c as u64) >> 32) as u32;
                self.rw(rd, a);
            }
            Opcode::DIV => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = (b as i32).wrapping_div(c as i32) as u32;
                self.rw(rd, a);
            }
            Opcode::DIVU => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = b.wrapping_div(c);
                self.rw(rd, a);
            }
            Opcode::REM => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1) as i32, self.rr(rs2) as i32);
                let a = (b as i32).wrapping_rem(c as i32) as u32;
                self.rw(rd, a);
            }
            Opcode::REMU => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = b.wrapping_rem(c);
                self.rw(rd, a);
            }
            Opcode::UNIMP => {
                // See https://github.com/riscv-non-isa/riscv-asm-manual/blob/master/riscv-asm.md#instruction-aliases
                panic!("UNIMP encountered, we should never get here.");
            }
        }
        self.pc = next_pc;

        // Emit the CPU event for this cycle.
        self.emit_cpu(self.clk, pc, instruction, a, b, c, memory_value);
    }

    /// Execute the program.
    pub fn run(&mut self) {
        // Set %x2 to the size of memory when the CPU is initialized.
        self.rw(Register::X2, 1024 * 1024 * 8);

        // Set the return address to the end of the program.
        self.rw(Register::X1, (self.program.len() * 4) as u32);

        self.clk += 1;
        while self.pc < (self.program.len() * 4) as u32 {
            // Fetch the instruction at the current program counter.
            let instruction = self.fetch();

            // Execute the instruction.
            self.execute(instruction);

            // Increment the clock.
            self.clk += 1;
        }
    }

    /// Prove the program.
    #[allow(unused)]
    pub fn prove<F, EF, SC>(&mut self, config: &SC, challenger: &mut SC::Challenger)
    where
        F: PrimeField + TwoAdicField,
        EF: ExtensionField<F>,
        SC: StarkConfig<Val = F, Challenge = EF>,
    {
        // Initialize chips.
        let program = ProgramChip::new();
        let cpu = CpuChip::new();
        let memory = MemoryChip::new();
        let add = AddChip::new();
        let sub = SubChip::new();
        let bitwise = BitwiseChip::new();
        let shift = ShiftChip::new();
        let lt = LtChip::new();
        let chips: [Box<dyn AirChip<SC>>; 8] = [
            Box::new(program),
            Box::new(cpu),
            Box::new(memory),
            Box::new(add),
            Box::new(sub),
            Box::new(bitwise),
            Box::new(shift),
            Box::new(lt),
        ];

        // Compute some statistics.
        let mut main_cols = 0usize;
        let mut perm_cols = 0usize;
        for chip in chips.iter() {
            main_cols += chip.air_width();
            perm_cols += (chip.all_interactions().len() + 1) * 5;
        }
        println!("MAIN_COLS: {}", main_cols);
        println!("PERM_COLS: {}", perm_cols);

        // For each chip, generate the trace.
        let traces = chips
            .iter()
            .map(|chip| chip.generate_trace(self))
            .collect::<Vec<_>>();

        // For each trace, compute the degree.
        let degrees: [usize; 8] = traces
            .iter()
            .map(|trace| trace.height())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let log_degrees = degrees.map(|d| log2_strict_usize(d));
        let max_constraint_degree = 3;
        let log_quotient_degree = log2_ceil_usize(max_constraint_degree - 1);
        let g_subgroups = log_degrees.map(|log_deg| SC::Val::two_adic_generator(log_deg));

        // Commit to the batch of traces.
        let (main_commit, main_data) = config.pcs().commit_batches(traces.to_vec());
        challenger.observe(main_commit);

        // Obtain the challenges used for the permutation argument.
        let mut permutation_challenges: Vec<EF> = Vec::new();
        for _ in 0..2 {
            permutation_challenges.push(challenger.sample_ext_element());
        }

        // Generate the permutation traces.
        let permutation_traces = chips
            .iter()
            .enumerate()
            .map(|(i, chip)| {
                generate_permutation_trace(
                    chip.as_ref(),
                    &traces[i],
                    permutation_challenges.clone(),
                )
            })
            .collect::<Vec<_>>();

        // Commit to the permutation traces.
        let flattened_permutation_traces = permutation_traces
            .iter()
            .map(|trace| trace.flatten_to_base())
            .collect::<Vec<_>>();
        let (permutation_commit, permutation_data) =
            config.pcs().commit_batches(flattened_permutation_traces);
        challenger.observe(permutation_commit);

        // For each chip, compute the quotient polynomial.
        let main_ldes = config.pcs().get_ldes(&main_data);
        let permutation_ldes = config.pcs().get_ldes(&permutation_data);
        let alpha: SC::Challenge = challenger.sample_ext_element::<SC::Challenge>();

        // Compute the quotient values.
        let quotient_values = (0..chips.len()).map(|i| {
            quotient_values(
                config,
                &*chips[i],
                log_degrees[i],
                log_quotient_degree,
                &main_ldes[i],
                alpha,
            )
        });

        // Compute the quotient chunks.
        let quotient_chunks = quotient_values
            .map(|values| {
                decompose_and_flatten::<SC>(
                    values,
                    SC::Challenge::from_base(config.pcs().coset_shift()),
                    log_quotient_degree,
                )
            })
            .collect::<Vec<_>>();

        // Commit to the quotient chunks.
        let (quotient_commit, quotient_commit_data): (Vec<_>, Vec<_>) = (0..chips.len())
            .map(|i| {
                config.pcs().commit_shifted_batch(
                    quotient_chunks[i].clone(),
                    config
                        .pcs()
                        .coset_shift()
                        .exp_power_of_2(log_quotient_degree),
                )
            })
            .into_iter()
            .unzip();

        // Observe the quotient commitments.
        for commit in quotient_commit {
            challenger.observe(commit);
        }

        // Compute the quotient argument.
        let zeta: SC::Challenge = challenger.sample_ext_element();
        let zeta_and_next = [zeta, zeta * g_subgroups[0]];
        let prover_data_and_points = [
            (&main_data, zeta_and_next.as_slice()),
            (&permutation_data, zeta_and_next.as_slice()),
        ];
        let (openings, opening_proof) = config
            .pcs()
            .open_multi_batches(&prover_data_and_points, challenger);
        let (openings, opening_proofs): (Vec<_>, Vec<_>) = (0..chips.len())
            .map(|i| {
                let prover_data_and_points = [(&quotient_commit_data[i], zeta_and_next.as_slice())];
                config
                    .pcs()
                    .open_multi_batches(&prover_data_and_points, challenger)
            })
            .into_iter()
            .unzip();

        // Check that the table-specific constraints are correct for each chip.
        for i in 0..chips.len() {
            debug_constraints(
                &*chips[i],
                &traces[i],
                &permutation_traces[i],
                &permutation_challenges,
            );
        }

        // Check the permutation argument between all tables.
        debug_cumulative_sums::<F, EF>(&permutation_traces[..]);
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
pub mod tests {
    use p3_baby_bear::BabyBear;
    use p3_challenger::DuplexChallenger;
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::Field;
    use p3_fri::FriBasedPcs;
    use p3_fri::FriConfigImpl;
    use p3_fri::FriLdt;
    use p3_keccak::Keccak256Hash;
    use p3_ldt::QuotientMmcs;
    use p3_mds::coset_mds::CosetMds;
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_poseidon2::DiffusionMatrixBabybear;
    use p3_poseidon2::Poseidon2;
    use p3_symmetric::CompressionFunctionFromHasher;
    use p3_symmetric::SerializingHasher32;
    use p3_uni_stark::StarkConfigImpl;
    use rand::thread_rng;

    use crate::runtime::instruction::Instruction;

    use super::Opcode;
    use super::Register;
    use super::Runtime;

    pub fn get_simple_program() -> Vec<Instruction> {
        // int main() {
        //     int a = 5;
        //     int b = 8;
        //     int result = a + b;
        //     return 0;
        //   }
        // main:
        // addi    sp,sp,-32
        // sw      s0,28(sp)
        // addi    s0,sp,32
        // li      a5,5
        // sw      a5,-20(s0)
        // li      a5,8
        // sw      a5,-24(s0)
        // lw      a4,-20(s0)
        // lw      a5,-24(s0)
        // add     a5,a4,a5
        // sw      a5,-28(s0)
        // lw      a5,-28(s0)
        // mv      a0,a5
        // lw      s0,28(sp)
        // addi    sp,sp,32
        // jr      ra
        // Mapping taken from here: https://en.wikichip.org/wiki/risc-v/registers
        let SP = Register::X2 as u32;
        let X0 = Register::X0 as u32;
        let S0 = Register::X8 as u32;
        let A0 = Register::X10 as u32;
        let A5 = Register::X15 as u32;
        let A4 = Register::X14 as u32;
        let _RA = Register::X1 as u32;
        let code = vec![
            Instruction::new(Opcode::ADDI, SP, SP, (-32i32) as u32),
            Instruction::new(Opcode::SW, S0, SP, 28),
            Instruction::new(Opcode::ADDI, S0, SP, 32),
            Instruction::new(Opcode::ADDI, A5, X0, 5),
            Instruction::new(Opcode::SW, A5, S0, (-20i32) as u32),
            Instruction::new(Opcode::ADDI, A5, X0, 8),
            Instruction::new(Opcode::SW, A5, S0, (-24i32) as u32),
            Instruction::new(Opcode::LW, A4, S0, (-20i32) as u32),
            Instruction::new(Opcode::LW, A5, S0, (-24i32) as u32),
            Instruction::new(Opcode::ADD, A5, A4, A5),
            Instruction::new(Opcode::SW, A5, S0, (-28i32) as u32),
            Instruction::new(Opcode::LW, A5, S0, (-28i32) as u32),
            Instruction::new(Opcode::ADDI, A0, A5, 0),
            Instruction::new(Opcode::LW, S0, SP, 28),
            Instruction::new(Opcode::ADDI, SP, SP, 32),
            // Instruction::new(Opcode::JALR, X0, RA, 0), // Commented this out because JAL is not working properly right now.
        ];
        code
    }

    #[test]
    fn SIMPLE_PROGRAM() {
        let code = get_simple_program();
        let mut runtime = Runtime::new(code);
        runtime.run();
    }

    #[test]
    fn PROVE() {
        type Val = BabyBear;
        type Domain = Val;
        type Challenge = BinomialExtensionField<Val, 4>;
        type PackedChallenge = BinomialExtensionField<<Domain as Field>::Packing, 4>;

        type MyMds = CosetMds<Val, 16>;
        let mds = MyMds::default();

        type Perm = Poseidon2<Val, MyMds, DiffusionMatrixBabybear, 16, 5>;
        let perm = Perm::new_from_rng(8, 22, mds, DiffusionMatrixBabybear, &mut thread_rng());

        type MyHash = SerializingHasher32<Keccak256Hash>;
        let hash = MyHash::new(Keccak256Hash {});

        type MyCompress = CompressionFunctionFromHasher<Val, MyHash, 2, 8>;
        let compress = MyCompress::new(hash);

        type ValMmcs = FieldMerkleTreeMmcs<Val, MyHash, MyCompress, 8>;
        let val_mmcs = ValMmcs::new(hash, compress);

        type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

        type Dft = Radix2DitParallel;
        let dft = Dft {};

        type Challenger = DuplexChallenger<Val, Perm, 16>;

        type Quotient = QuotientMmcs<Domain, Challenge, ValMmcs>;
        type MyFriConfig = FriConfigImpl<Val, Challenge, Quotient, ChallengeMmcs, Challenger>;
        let fri_config = MyFriConfig::new(40, challenge_mmcs);
        let ldt = FriLdt { config: fri_config };

        type Pcs = FriBasedPcs<MyFriConfig, ValMmcs, Dft, Challenger>;
        type MyConfig = StarkConfigImpl<Val, Challenge, PackedChallenge, Pcs, Challenger>;

        let pcs = Pcs::new(dft, val_mmcs, ldt);
        let config = StarkConfigImpl::new(pcs);
        let mut challenger = Challenger::new(perm.clone());

        // main:
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     add x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 31, 29, 9),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        runtime.prove::<_, _, MyConfig>(&config, &mut challenger);
        // assert_eq!(runtime.registers()[Register::X31 as usize], 42);
    }

    #[test]
    fn ADD() {
        // main:
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     add x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::ADD, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();

        assert_eq!(runtime.registers()[Register::X31 as usize], 42);
    }

    #[test]
    fn SUB() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sub x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SUB, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 32);
    }

    #[test]
    fn XOR() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     xor x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::XOR, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 32);
    }

    #[test]
    fn OR() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     or x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::OR, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 37);
    }

    #[test]
    fn AND() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     and x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::AND, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 5);
    }

    #[test]
    fn SLL() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sll x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SLL, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 1184);
    }

    #[test]
    fn SRL() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     srl x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SRL, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 1);
    }

    #[test]
    fn SRA() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sra x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SRA, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 1);
    }

    #[test]
    fn SLT() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     slt x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SLT, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 0);
    }

    #[test]
    fn SLTU() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sltu x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SLTU, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 0);
    }

    #[test]
    fn ADDI() {
        //     addi x29, x0, 5
        //     addi x30, x29, 37
        //     addi x31, x30, 42
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 29, 37),
            Instruction::new(Opcode::ADDI, 31, 30, 42),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 84);
    }

    #[test]
    fn ADDI_NEGATIVE() {
        //     addi x29, x0, 5
        //     addi x30, x29, -1
        //     addi x31, x30, 4
        let code = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 29, 0xffffffff),
            Instruction::new(Opcode::ADDI, 31, 30, 4),
        ];
        let mut runtime = Runtime::new(code);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 5 - 1 + 4);
    }

    #[test]
    fn XORI() {
        //     addi x29, x0, 5
        //     xori x30, x29, 37
        //     xori x31, x30, 42
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::XORI, 30, 29, 37),
            Instruction::new(Opcode::XORI, 31, 30, 42),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();

        assert_eq!(runtime.registers()[Register::X31 as usize], 10);
    }

    #[test]
    fn ORI() {
        //     addi x29, x0, 5
        //     ori x30, x29, 37
        //     ori x31, x30, 42
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ORI, 30, 29, 37),
            Instruction::new(Opcode::ORI, 31, 30, 42),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();

        assert_eq!(runtime.registers()[Register::X31 as usize], 47);
    }

    #[test]
    fn ANDI() {
        //     addi x29, x0, 5
        //     andi x30, x29, 37
        //     andi x31, x30, 42
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ANDI, 30, 29, 37),
            Instruction::new(Opcode::ANDI, 31, 30, 42),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();

        assert_eq!(runtime.registers()[Register::X31 as usize], 0);
    }

    #[test]
    fn SLLI() {
        //     addi x29, x0, 5
        //     slli x31, x29, 37
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::SLLI, 31, 29, 4),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 80);
    }

    #[test]
    fn SRLI() {
        //    addi x29, x0, 5
        //    srli x31, x29, 37
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 42),
            Instruction::new(Opcode::SRLI, 31, 29, 4),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 2);
    }

    #[test]
    fn SRAI() {
        //   addi x29, x0, 5
        //   srai x31, x29, 37
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 42),
            Instruction::new(Opcode::SRAI, 31, 29, 4),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 2);
    }

    #[test]
    fn SLTI() {
        //   addi x29, x0, 5
        //   slti x31, x29, 37
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 42),
            Instruction::new(Opcode::SLTI, 31, 29, 37),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 0);
    }

    #[test]
    fn SLTIU() {
        //   addi x29, x0, 5
        //   sltiu x31, x29, 37
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 42),
            Instruction::new(Opcode::SLTIU, 31, 29, 37),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 0);
    }

    #[test]
    fn JALR() {
        //   addi x11, x11, 100
        //   jalr x5, x11, 8
        //
        // `JALR rd offset(rs)` reads the value at rs, adds offset to it and uses it as the
        // destination address. It then stores the address of the next instruction in rd in case
        // we'd want to come back here.

        let program = vec![
            Instruction::new(Opcode::ADDI, 11, 11, 100),
            Instruction::new(Opcode::JALR, 5, 11, 8),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X5 as usize], 8);
        assert_eq!(runtime.registers()[Register::X11 as usize], 100);
        assert_eq!(runtime.pc, 108);
    }
}
