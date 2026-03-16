use crate::{
    debug, ComputeInstructions, ControlFlowInstructions, DebugFn, Debuggable, EcallHandler,
    ExternFn, JitContext, JitFunction, JitMemory, MemoryInstructions, RiscOperand, RiscRegister,
    RiscvTranspiler, SystemInstructions, TraceCollector,
};
use std::io;

pub struct DebugBackend<B: RiscvTranspiler> {
    backend: B,
}

impl<B: RiscvTranspiler> DebugBackend<B> {
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }
}

impl<B: RiscvTranspiler + Debuggable> RiscvTranspiler for DebugBackend<B> {
    fn new(
        program_size: usize,
        memory_size: usize,
        max_trace_size: u64,
        pc_start: u64,
        pc_base: u64,
        clk_bump: u64,
    ) -> Result<Self, std::io::Error> {
        let backend =
            B::new(program_size, memory_size, max_trace_size, pc_start, pc_base, clk_bump)?;

        Ok(Self::new(backend))
    }

    fn register_ecall_handler(&mut self, handler: EcallHandler) {
        self.backend.register_ecall_handler(handler);
    }

    fn start_instr(&mut self) {
        extern "C" fn print_bar(_: *mut JitContext) {
            eprintln!("--------------------------------");
        }

        extern "C" fn collect_registers(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            if let Some(sender) = &ctx.debug_sender {
                sender
                    .send(Some(debug::State {
                        pc: ctx.pc,
                        clk: ctx.clk,
                        global_clk: ctx.global_clk,
                        registers: ctx.registers,
                    }))
                    .expect("Failed to send debug state");
            }
        }

        self.backend.start_instr();
        self.backend.call_extern_fn(collect_registers);
        self.backend.call_extern_fn(print_bar);
        self.backend.print_ctx();
    }

    fn end_instr(&mut self) {
        self.backend.end_instr();
    }

    fn inspect_register(&mut self, reg: RiscRegister, handler: DebugFn) {
        self.backend.inspect_register(reg, handler);
    }

    fn inspect_immediate(&mut self, imm: u64, handler: DebugFn) {
        self.backend.inspect_immediate(imm, handler);
    }

    fn call_extern_fn(&mut self, handler: ExternFn) {
        self.backend.call_extern_fn(handler);
    }

    fn finalize<M: JitMemory>(self) -> io::Result<JitFunction<M>> {
        self.backend.finalize()
    }
}

impl<B: RiscvTranspiler> MemoryInstructions for DebugBackend<B> {
    fn lb(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64) {
        extern "C" fn lb(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = lb: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(lb);
        self.backend.lb(rd, rs1, imm);
    }

    fn lh(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64) {
        extern "C" fn lh(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = lh: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(lh);
        self.backend.lh(rd, rs1, imm);
    }

    fn lw(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64) {
        extern "C" fn lw(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = lw: pc={}", ctx.pc);
        }

        extern "C" fn lw_imm_value(imm: u64) {
            eprintln!("-- lw_imm_value: value={imm}");
        }

        extern "C" fn lw_rs1_value(rs1: u64) {
            eprintln!("-- lw_rs1_value={rs1}");
        }

        extern "C" fn lw_rs1(rs1: u64) {
            eprintln!("-- lw_rs1={rs1}");
        }

        extern "C" fn lw_rd(rd: u64) {
            eprintln!("-- lw_rd={rd}");
        }

        self.inspect_immediate(imm, lw_imm_value);
        self.inspect_immediate(rd as u8 as u64, lw_rd);
        self.inspect_immediate(rs1 as u8 as u64, lw_rs1);
        self.inspect_register(rs1, lw_rs1_value);

        self.backend.call_extern_fn(lw);
        self.backend.lw(rd, rs1, imm);
    }

    fn lbu(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64) {
        extern "C" fn lbu(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = lbu: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(lbu);
        self.backend.lbu(rd, rs1, imm);
    }

    fn lhu(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64) {
        extern "C" fn lhu(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = lhu: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(lhu);
        self.backend.lhu(rd, rs1, imm);
    }

    fn ld(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64) {
        extern "C" fn ld(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = ld: pc={}", ctx.pc);
        }

        extern "C" fn ld_imm_value(imm: u64) {
            eprintln!("-- ld_imm_value: value={imm}");
        }

        extern "C" fn ld_rs1_value(rs1: u64) {
            eprintln!("-- ld_rs1_value={rs1}");
        }

        self.backend.call_extern_fn(ld);
        self.inspect_immediate(imm, ld_imm_value);
        self.inspect_register(rs1, ld_rs1_value);
        self.backend.ld(rd, rs1, imm);
    }

    fn lwu(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64) {
        extern "C" fn lwu(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = lwu: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(lwu);
        self.backend.lwu(rd, rs1, imm);
    }

    fn sb(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64) {
        extern "C" fn sb(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = sb: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(sb);
        self.backend.sb(rs1, rs2, imm);
    }

    fn sh(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64) {
        extern "C" fn sh(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = sh: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(sh);
        self.backend.sh(rs1, rs2, imm);
    }

    fn sw(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64) {
        extern "C" fn sw(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = sw: pc={}", ctx.pc);
        }

        extern "C" fn sw_imm_value(imm: u64) {
            eprintln!("-- sw_imm_value: value={imm}");
        }

        extern "C" fn sw_rs1_value(rs1: u64) {
            eprintln!("-- sw_rs1_value={rs1}");
        }

        extern "C" fn sw_rs2_value(rs2: u64) {
            eprintln!("-- sw_rs2_value={rs2}");
        }

        extern "C" fn sw_rs2(rs2: u64) {
            eprintln!("-- sw_rs2={rs2}");
        }

        extern "C" fn sw_rs1(rs1: u64) {
            eprintln!("-- sw_rs1={rs1}");
        }

        self.inspect_immediate(rs1 as u8 as u64, sw_rs1);
        self.inspect_immediate(rs2 as u8 as u64, sw_rs2);
        self.inspect_immediate(imm, sw_imm_value);

        self.inspect_register(rs1, sw_rs1_value);
        self.inspect_register(rs2, sw_rs2_value);

        self.backend.call_extern_fn(sw);
        self.backend.sw(rs1, rs2, imm);
    }

    fn sd(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64) {
        extern "C" fn sd(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = sd: pc={}", ctx.pc);
        }

        extern "C" fn sd_imm_value(imm: u64) {
            eprintln!("-- sd_imm_value: value={imm}");
        }

        extern "C" fn sd_rs1_value(rs1: u64) {
            eprintln!("-- sd_rs1_value={rs1}");
        }

        extern "C" fn sd_rs2_value(rs2: u64) {
            eprintln!("-- sd_rs2_value={rs2}");
        }

        self.backend.call_extern_fn(sd);
        self.inspect_immediate(imm, sd_imm_value);
        self.inspect_register(rs1, sd_rs1_value);
        self.inspect_register(rs2, sd_rs2_value);
        self.backend.sd(rs1, rs2, imm);
    }
}

impl<B: RiscvTranspiler> ControlFlowInstructions for DebugBackend<B> {
    fn beq(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64) {
        extern "C" fn beq(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = beq: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(beq);
        self.backend.beq(rs1, rs2, imm);
    }

    fn bne(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64) {
        extern "C" fn bne(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = bne: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(bne);
        self.backend.bne(rs1, rs2, imm);
    }

    fn blt(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64) {
        extern "C" fn blt(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = blt: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(blt);
        self.backend.blt(rs1, rs2, imm);
    }

    fn bge(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64) {
        extern "C" fn bge(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = bge: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(bge);
        self.backend.bge(rs1, rs2, imm);
    }

    fn bltu(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64) {
        extern "C" fn bltu(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = bltu: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(bltu);
        self.backend.bltu(rs1, rs2, imm);
    }

    fn bgeu(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64) {
        extern "C" fn bgeu(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = bgeu: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(bgeu);
        self.backend.bgeu(rs1, rs2, imm);
    }

    fn jal(&mut self, rd: RiscRegister, imm: u64) {
        extern "C" fn jal(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = jal: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(jal);
        self.backend.jal(rd, imm);
    }

    fn jalr(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64) {
        extern "C" fn jalr(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = jalr: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(jalr);

        extern "C" fn jalr_reg_value(register: u64) {
            eprintln!("-- jalr_reg_value: value={register}");
        }

        extern "C" fn jalr_imm_value(imm: u64) {
            eprintln!("-- jalr_imm_value: value={imm}");
        }

        extern "C" fn jalr_rs1(rs1: u64) {
            eprintln!("-- jalr_rs1={rs1}");
        }

        extern "C" fn jalr_rd(rd: u64) {
            eprintln!("-- jalr_rd={rd}");
        }

        self.inspect_immediate(rd as u8 as u64, jalr_rd);
        self.backend.inspect_register(rs1, jalr_reg_value);
        self.backend.inspect_immediate(rs1 as u8 as u64, jalr_rs1);
        self.backend.inspect_immediate(imm, jalr_imm_value);

        self.backend.jalr(rd, rs1, imm);
    }
}

impl<B: RiscvTranspiler> SystemInstructions for DebugBackend<B> {
    fn ecall(&mut self) {
        extern "C" fn ecall(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("ecall at pc: {}", ctx.pc);
        }

        self.backend.call_extern_fn(ecall);
        self.backend.ecall();
    }

    fn unimp(&mut self) {
        extern "C" fn unimp(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("Unimplemented instruction at pc: {}", ctx.pc);
        }

        self.backend.call_extern_fn(unimp);
    }
}

impl<B: RiscvTranspiler> ComputeInstructions for DebugBackend<B> {
    fn add(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn add(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = add: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(add);
        self.backend.add(rd, rs1, rs2);
    }

    fn sub(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn sub(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = sub: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(sub);
        self.backend.sub(rd, rs1, rs2);
    }

    fn xor(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn xor(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = xor: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(xor);
        self.backend.xor(rd, rs1, rs2);
    }

    fn or(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn or(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = or: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(or);
        self.backend.or(rd, rs1, rs2);
    }

    fn and(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn and(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = and: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(and);
        self.backend.and(rd, rs1, rs2);
    }

    fn sll(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn sll(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = sll: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(sll);
        self.backend.sll(rd, rs1, rs2);
    }

    fn srl(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn srl(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = srl: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(srl);
        self.backend.srl(rd, rs1, rs2);
    }

    fn sra(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn sra(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = sra: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(sra);
        self.backend.sra(rd, rs1, rs2);
    }

    fn slt(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn slt(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = slt: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(slt);
        self.backend.slt(rd, rs1, rs2);
    }

    fn sltu(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn sltu(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = sltu: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(sltu);
        self.backend.sltu(rd, rs1, rs2);
    }

    fn mul(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn mul(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = mul: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(mul);
        self.backend.mul(rd, rs1, rs2);
    }

    fn mulh(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn mulh(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = mulh: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(mulh);
        self.backend.mulh(rd, rs1, rs2);
    }

    fn mulhu(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn mulhu(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = mulhu: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(mulhu);
        self.backend.mulhu(rd, rs1, rs2);
    }

    fn mulhsu(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn mulhsu(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = mulhsu: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(mulhsu);
        self.backend.mulhsu(rd, rs1, rs2);
    }

    fn div(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn div(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = div: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(div);
        self.backend.div(rd, rs1, rs2);
    }

    fn divu(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn divu(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = divu: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(divu);
        self.backend.divu(rd, rs1, rs2);
    }

    fn rem(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn rem(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = rem: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(rem);
        self.backend.rem(rd, rs1, rs2);
    }

    fn remu(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn remu(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = remu: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(remu);
        self.backend.remu(rd, rs1, rs2);
    }

    fn addw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn addw(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = addw: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(addw);
        self.backend.addw(rd, rs1, rs2);
    }

    fn subw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn subw(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = subw: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(subw);
        self.backend.subw(rd, rs1, rs2);
    }

    fn sllw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn sllw(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = sllw: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(sllw);
        self.backend.sllw(rd, rs1, rs2);
    }

    fn srlw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn srlw(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = srlw: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(srlw);
        self.backend.srlw(rd, rs1, rs2);
    }

    fn sraw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn sraw(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = sraw: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(sraw);
        self.backend.sraw(rd, rs1, rs2);
    }

    fn mulw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn mulw(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = mulw: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(mulw);
        self.backend.mulw(rd, rs1, rs2);
    }

    fn divw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn divw(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = divw: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(divw);
        self.backend.divw(rd, rs1, rs2);
    }

    fn divuw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn divuw(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = divuw: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(divuw);
        self.backend.divuw(rd, rs1, rs2);
    }

    fn remw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn remw(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = remw: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(remw);
        self.backend.remw(rd, rs1, rs2);
    }

    fn remuw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand) {
        extern "C" fn remuw(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = remuw: pc={}", ctx.pc);
        }

        self.backend.call_extern_fn(remuw);
        self.backend.remuw(rd, rs1, rs2);
    }

    fn auipc(&mut self, rd: RiscRegister, imm: u64) {
        extern "C" fn auipc(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = auipc: pc={}", ctx.pc);
        }

        extern "C" fn auipc_rd(rd: u64) {
            eprintln!("-- auipc_rd={rd}");
        }

        extern "C" fn auipc_imm(imm: u64) {
            eprintln!("-- auipc_imm={imm}");
        }

        self.inspect_immediate(rd as u8 as u64, auipc_rd);
        self.inspect_immediate(imm, auipc_imm);

        self.backend.call_extern_fn(auipc);
        self.backend.auipc(rd, imm);
    }

    fn lui(&mut self, rd: RiscRegister, imm: u64) {
        extern "C" fn lui(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("-- opcode = lui: pc={}", ctx.pc);
        }

        extern "C" fn lui_rd(rd: u64) {
            eprintln!("-- lui_rd={rd}");
        }

        extern "C" fn lui_imm(imm: u64) {
            eprintln!("-- lui_imm={imm}");
        }

        self.inspect_immediate(rd as u8 as u64, lui_rd);
        self.inspect_immediate(imm, lui_imm);

        self.backend.call_extern_fn(lui);
        self.backend.lui(rd, imm);
    }
}

impl<B: RiscvTranspiler> TraceCollector for DebugBackend<B> {
    fn trace_clk_end(&mut self) {
        self.backend.trace_clk_end();
    }

    fn trace_clk_start(&mut self) {
        self.backend.trace_clk_start();
    }

    fn trace_mem_value(&mut self, rs1: RiscRegister, imm: u64) {
        self.backend.trace_mem_value(rs1, imm);
    }

    fn trace_pc_start(&mut self) {
        self.backend.trace_pc_start();
    }

    fn trace_registers(&mut self) {
        self.backend.trace_registers();
    }
}
