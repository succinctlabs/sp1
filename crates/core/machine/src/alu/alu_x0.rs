use core::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};
use std::marker::PhantomData;

use hashbrown::HashMap;
use itertools::Itertools;
use slop_air::{Air, AirBuilder, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::*;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode, ExecutionRecord, Opcode, Program, CLK_INC, PC_INC,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::MachineAir;

use crate::{
    adapter::{
        register::alu_type::ALUTypeReader,
        state::{CPUState, CPUStateInput},
    },
    air::{SP1CoreAirBuilder, SP1Operation},
    eval_alu_x0_selectors, eval_untrusted_program,
    utils::next_multiple_of_32,
    AluX0OpcodeSelectors, SupervisorMode, TrustMode, UserMode,
};

/// The number of main trace columns for `AluX0Chip` in Supervisor mode.
pub const NUM_ALU_X0_COLS_SUPERVISOR: usize = size_of::<AluX0Cols<u8, SupervisorMode>>();
/// The number of main trace columns for `AluX0Chip` in User mode.
pub const NUM_ALU_X0_COLS_USER: usize = size_of::<AluX0Cols<u8, UserMode>>();

/// A chip that handles all ALU instructions with `rd = x0`.
///
/// Since `x0` is hardwired to zero in RISC-V, the arithmetic result is discarded.
/// This chip only verifies the instruction against the program table and performs
/// the register accesses (writing 0 to `op_a`, reading `op_b` and `op_c`).
#[derive(Default)]
pub struct AluX0Chip<M: TrustMode> {
    pub _phantom: PhantomData<M>,
}

/// The column layout for `AluX0Chip`.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct AluX0Cols<T, M: TrustMode> {
    /// The current shard, timestamp, program counter of the CPU.
    pub state: CPUState<T>,

    /// The adapter to read program and register information.
    pub adapter: ALUTypeReader<T>,

    /// The corresponding ALU opcode.
    pub opcode: T,

    /// Boolean to indicate whether the row is not a padding row.
    pub is_real: T,

    /// Adapter columns for trust mode specific data.
    pub adapter_cols: M::AdapterCols<T>,

    /// Opcode selectors.
    pub selector_cols: M::AluX0SelectorCols<T>,
}

impl<F, M: TrustMode> BaseAir<F> for AluX0Chip<M> {
    fn width(&self) -> usize {
        if M::IS_TRUSTED {
            NUM_ALU_X0_COLS_SUPERVISOR
        } else {
            NUM_ALU_X0_COLS_USER
        }
    }
}

impl<F: PrimeField32, M: TrustMode> MachineAir<F> for AluX0Chip<M> {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> &'static str {
        if M::IS_TRUSTED {
            "AluX0"
        } else {
            "AluX0User"
        }
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return Some(0);
        }
        let nb_rows =
            next_multiple_of_32(input.alu_x0_events.len(), input.fixed_log2_rows::<F, _>(self));
        Some(nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return;
        }

        let chunk_size = std::cmp::max(input.alu_x0_events.len() / num_cpus::get(), 1);
        let padded_nb_rows = <AluX0Chip<M> as MachineAir<F>>::num_rows(self, input).unwrap();
        let num_event_rows = input.alu_x0_events.len();
        let width = <AluX0Chip<M> as BaseAir<F>>::width(self);

        unsafe {
            let padding_start = num_event_rows * width;
            let padding_size = (padded_nb_rows - num_event_rows) * width;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * width) };

        values.chunks_mut(chunk_size * width).enumerate().par_bridge().for_each(|(i, rows)| {
            rows.chunks_mut(width).enumerate().for_each(|(j, row)| {
                let idx = i * chunk_size + j;
                let cols: &mut AluX0Cols<F, M> = row.borrow_mut();

                if idx < input.alu_x0_events.len() {
                    let mut byte_lookup_events = Vec::new();
                    let event = &input.alu_x0_events[idx];
                    cols.is_real = F::one();
                    cols.opcode = F::from_canonical_u32(event.0.opcode as u32);
                    cols.state.populate(&mut byte_lookup_events, event.0.clk, event.0.pc);
                    cols.adapter.populate(&mut byte_lookup_events, event.1);
                    if !M::IS_TRUSTED {
                        let cols: &mut AluX0Cols<F, UserMode> = row.borrow_mut();
                        cols.adapter_cols.is_trusted = F::from_bool(!event.1.is_untrusted);
                        let mut sel = AluX0OpcodeSelectors::<F>::default();
                        let op = event.0.opcode;
                        let imm_c = event.1.c.is_none();
                        let (instr_type, imm_instr_type) = op.instruction_type();
                        let (base_opcode, imm_base_opcode) = op.base_opcode();
                        if imm_c {
                            sel.instr_type = F::from_canonical_u32(imm_instr_type.unwrap() as u32);
                            sel.base_opcode =
                                F::from_canonical_u32(imm_base_opcode.unwrap() as u32);
                        } else {
                            sel.instr_type = F::from_canonical_u32(instr_type as u32);
                            sel.base_opcode = F::from_canonical_u32(base_opcode as u32);
                        };
                        sel.funct3 = F::from_canonical_u8(op.funct3().unwrap());
                        sel.funct7 = F::from_canonical_u8(op.funct7().unwrap_or(0));

                        match op {
                            Opcode::ADD => sel.is_add = F::one(),
                            Opcode::SUB => sel.is_sub = F::one(),
                            Opcode::MUL => sel.is_mul = F::one(),
                            Opcode::MULH => sel.is_mulh = F::one(),
                            Opcode::MULHSU => sel.is_mulhsu = F::one(),
                            Opcode::MULHU => sel.is_mulhu = F::one(),
                            Opcode::DIV => sel.is_div = F::one(),
                            Opcode::DIVU => sel.is_divu = F::one(),
                            Opcode::REM => sel.is_rem = F::one(),
                            Opcode::REMU => sel.is_remu = F::one(),
                            Opcode::SLL => sel.is_sll = F::one(),
                            Opcode::SRL => sel.is_srl = F::one(),
                            Opcode::SRA => sel.is_sra = F::one(),
                            Opcode::XOR => sel.is_xor = F::one(),
                            Opcode::OR => sel.is_or = F::one(),
                            Opcode::AND => sel.is_and = F::one(),
                            Opcode::SLT => sel.is_slt = F::one(),
                            Opcode::SLTU => sel.is_sltu = F::one(),
                            Opcode::ADDI => sel.is_addi = F::one(),
                            Opcode::ADDW => sel.is_addw = F::one(),
                            Opcode::SUBW => sel.is_subw = F::one(),
                            Opcode::SLLW => sel.is_sllw = F::one(),
                            Opcode::SRLW => sel.is_srlw = F::one(),
                            Opcode::SRAW => sel.is_sraw = F::one(),
                            Opcode::MULW => sel.is_mulw = F::one(),
                            Opcode::DIVW => sel.is_divw = F::one(),
                            Opcode::DIVUW => sel.is_divuw = F::one(),
                            Opcode::REMW => sel.is_remw = F::one(),
                            Opcode::REMUW => sel.is_remuw = F::one(),
                            _ => {}
                        }
                        cols.selector_cols = sel;
                    }
                }
            });
        });
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return;
        }

        let chunk_size = std::cmp::max(input.alu_x0_events.len() / num_cpus::get(), 1);
        let width = <AluX0Chip<M> as BaseAir<F>>::width(self);

        let blu_batches = input
            .alu_x0_events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = vec![F::zero(); width];
                    let cols: &mut AluX0Cols<F, M> = row.as_mut_slice().borrow_mut();
                    blu.add_byte_lookup_event(ByteLookupEvent {
                        opcode: ByteOpcode::LTU,
                        a: 1,
                        b: event.0.opcode as u8,
                        c: 29,
                    });
                    cols.state.populate(&mut blu, event.0.clk, event.0.pc);
                    cols.adapter.populate(&mut blu, event.1);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.alu_x0_events.is_empty()
                && (M::IS_TRUSTED != shard.program.enable_untrusted_programs)
        }
    }
}

impl<AB, M> Air<AB> for AluX0Chip<M>
where
    AB: SP1CoreAirBuilder,
    M: TrustMode,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &AluX0Cols<AB::Var, M> = (*local).borrow();

        // Check that `is_real` is boolean.
        builder.assert_bool(local.is_real);

        // This chip requires `op_a == x0`.
        builder.when(local.is_real).assert_one(local.adapter.op_a_0);

        // If `is_real` is false, then `op_a_0 == 0`.
        builder.when_not(local.is_real).assert_zero(local.adapter.op_a_0);

        // Constrain the state of the CPU.
        <CPUState<AB::F> as SP1Operation<AB>>::eval(
            builder,
            CPUStateInput::new(
                local.state,
                [
                    local.state.pc[0] + AB::F::from_canonical_u32(PC_INC),
                    local.state.pc[1].into(),
                    local.state.pc[2].into(),
                ],
                AB::Expr::from_canonical_u32(CLK_INC),
                local.is_real.into(),
            ),
        );

        // Check that `0 <= opcode < 29`, which is the range of ALU `Opcode`.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::LTU as u32),
            AB::Expr::one(),
            local.opcode.into(),
            AB::Expr::from_canonical_u32(29),
            local.is_real.into(),
        );

        let mut is_trusted: AB::Expr = local.is_real.into();

        #[cfg(feature = "mprotect")]
        builder.assert_eq(
            builder.extract_public_values().is_untrusted_programs_enabled,
            AB::Expr::from_bool(!M::IS_TRUSTED),
        );

        if !M::IS_TRUSTED {
            let local_user = main.row_slice(0);
            let local_user: &AluX0Cols<AB::Var, UserMode> = (*local_user).borrow();

            // For AluX0, we don't have a specific opcode constant — we use the dynamic `opcode`
            // field. We need to build the instruction for eval_untrusted_program.
            // Since AluX0 handles many opcodes, we pass the opcode field directly.
            let instruction = local_user.adapter.instruction::<AB>(local.opcode.into());

            builder.assert_bool(local_user.adapter.imm_c);

            #[cfg(not(feature = "mprotect"))]
            builder.assert_zero(local.is_real);

            eval_alu_x0_selectors(
                builder,
                local_user.selector_cols,
                local_user.adapter.imm_c.into(),
                local_user.is_real.into(),
            );

            eval_untrusted_program(
                builder,
                local.state.pc,
                instruction,
                [
                    local_user.selector_cols.instr_type.into(),
                    local_user.selector_cols.base_opcode.into(),
                    local_user.selector_cols.funct3.into(),
                    local_user.selector_cols.funct7.into(),
                ],
                [local.state.clk_high::<AB>(), local.state.clk_low::<AB>()],
                local.is_real.into(),
                local_user.adapter_cols,
            );

            is_trusted = local_user.adapter_cols.is_trusted.into();
        }

        // Constrain the program and register accesses.
        ALUTypeReader::<AB::F>::eval_op_a_immutable(
            builder,
            local.state.clk_high::<AB>(),
            local.state.clk_low::<AB>(),
            local.state.pc,
            local.opcode,
            local.adapter,
            local.is_real.into(),
            is_trusted,
        );
    }
}
