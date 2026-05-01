use crate::{
    adapter::state::CPUStateInput,
    air::{SP1CoreAirBuilder, SP1Operation},
    eval_untrusted_program,
    operations::AddwOperationInput,
};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};
use std::marker::PhantomData;

use hashbrown::HashMap;
use itertools::Itertools;
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField, PrimeField32};
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::{ParallelBridge, ParallelIterator};
use sp1_core_executor::{
    events::{AluEvent, ByteLookupEvent, ByteRecord},
    ExecutionRecord, Opcode, Program, CLK_INC, PC_INC,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{air::MachineAir, Word};
use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::{
    adapter::{
        register::alu_type::{ALUTypeReader, ALUTypeReaderInput},
        state::CPUState,
    },
    operations::AddwOperation,
    utils::next_multiple_of_32,
    SupervisorMode, TrustMode, UserMode,
};

/// The number of main trace columns for `AddwChip` in Supervisor mode.
pub const NUM_ADDW_COLS_SUPERVISOR: usize = size_of::<AddwCols<u8, SupervisorMode>>();
/// The number of main trace columns for `AddwChip` in User mode.
pub const NUM_ADDW_COLS_USER: usize = size_of::<AddwCols<u8, UserMode>>();

/// A chip that implements addition for the opcode ADD.
#[derive(Default)]
pub struct AddwChip<M: TrustMode> {
    pub _phantom: PhantomData<M>,
}

/// The column layout for the `AddwChip`.
#[derive(AlignedBorrow, StructReflection, Default, Clone, Copy)]
#[repr(C)]
pub struct AddwCols<T, M: TrustMode> {
    /// The current shard, timestamp, program counter of the CPU.
    pub state: CPUState<T>,

    /// The adapter to read program and register information.
    pub adapter: ALUTypeReader<T>,

    /// Instance of `AddwOperation` to handle addition logic in `AddChip`'s ALU operations.
    pub addw_operation: AddwOperation<T>,

    /// Boolean to indicate whether the row is not a padding row.
    pub is_real: T,

    /// Adapter columns for trust mode specific data.
    pub adapter_cols: M::AdapterCols<T>,
}

impl<F: PrimeField32, M: TrustMode> MachineAir<F> for AddwChip<M> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        if M::IS_TRUSTED {
            "Addw"
        } else {
            "AddwUser"
        }
    }

    fn column_names(&self) -> Vec<String> {
        AddwCols::<F, M>::struct_reflection().unwrap()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return Some(0);
        }
        let nb_rows =
            next_multiple_of_32(input.addw_events.len(), input.fixed_log2_rows::<F, _>(self));
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

        // Generate the rows for the trace.
        let chunk_size = std::cmp::max(input.addw_events.len() / num_cpus::get(), 1);
        let padded_nb_rows = <AddwChip<M> as MachineAir<F>>::num_rows(self, input).unwrap();
        let num_event_rows = input.addw_events.len();
        let width = <AddwChip<M> as BaseAir<F>>::width(self);

        unsafe {
            let padding_start = num_event_rows * width;
            let padding_size = (padded_nb_rows - num_event_rows) * width;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let values = unsafe {
            core::slice::from_raw_parts_mut(buffer.as_mut_ptr() as *mut F, num_event_rows * width)
        };

        values.chunks_mut(chunk_size * width).enumerate().par_bridge().for_each(|(i, rows)| {
            rows.chunks_mut(width).enumerate().for_each(|(j, row)| {
                let idx = i * chunk_size + j;
                let cols: &mut AddwCols<F, M> = row.borrow_mut();

                if idx < input.addw_events.len() {
                    let mut byte_lookup_events = Vec::new();
                    let event = input.addw_events[idx];
                    cols.adapter.populate(&mut byte_lookup_events, event.1);
                    cols.state.populate(&mut byte_lookup_events, event.0.clk, event.0.pc);
                    self.event_to_row(&event.0, cols, &mut byte_lookup_events);
                    if !M::IS_TRUSTED {
                        let cols: &mut AddwCols<F, UserMode> = row.borrow_mut();
                        cols.adapter_cols.is_trusted = F::from_bool(!event.1.is_untrusted);
                    }
                }
            });
        });
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return;
        }

        let chunk_size = std::cmp::max(input.addw_events.len() / num_cpus::get(), 1);
        let event_iter = input.addw_events.chunks(chunk_size);
        let width = <AddwChip<M> as BaseAir<F>>::width(self);

        let blu_batches = event_iter
            .par_bridge()
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = vec![F::zero(); width];
                    let cols: &mut AddwCols<F, M> = row.as_mut_slice().borrow_mut();
                    cols.adapter.populate(&mut blu, event.1);
                    self.event_to_row(&event.0, cols, &mut blu);
                    cols.state.populate(&mut blu, event.0.clk, event.0.pc);
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
            !shard.addw_events.is_empty()
                && (M::IS_TRUSTED != shard.program.enable_untrusted_programs)
        }
    }
}

impl<M: TrustMode> AddwChip<M> {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField>(
        &self,
        event: &AluEvent,
        cols: &mut AddwCols<F, M>,
        blu: &mut impl ByteRecord,
    ) {
        cols.is_real = F::one();
        cols.addw_operation.populate(blu, event.b, event.c);
    }
}

impl<F, M: TrustMode> BaseAir<F> for AddwChip<M> {
    fn width(&self) -> usize {
        if M::IS_TRUSTED {
            NUM_ADDW_COLS_SUPERVISOR
        } else {
            NUM_ADDW_COLS_USER
        }
    }
}

impl<AB, M> Air<AB> for AddwChip<M>
where
    AB: SP1CoreAirBuilder,
    M: TrustMode,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &AddwCols<AB::Var, M> = (*local).borrow();

        // Assert boolean constraints
        builder.assert_bool(local.is_real);

        // Get the instruction type for ADDW
        let instr_type = Opcode::ADDW.instruction_type().0 as u32;
        let instr_type_imm =
            Opcode::ADDW.instruction_type().1.expect("ADDW immediate instruction type not found")
                as u32;
        let calculated_instr_type = AB::Expr::from_canonical_u32(instr_type)
            - AB::Expr::from_canonical_u32(instr_type.checked_sub(instr_type_imm).unwrap())
                * local.adapter.imm_c;

        // Get base opcode variants for ADDW
        let (addw_base, addw_imm) = Opcode::ADDW.base_opcode();
        let addw_imm = addw_imm.expect("ADDW immediate opcode not found");

        // Constrain that base_op_code is either addw_base or addw_imm
        let addw_base_expr = AB::Expr::from_canonical_u32(addw_base);

        // If imm_c is set, base_op_code must be addw_imm; otherwise it must be addw_base
        let calculated_base_opcode = addw_base_expr
            - AB::Expr::from_canonical_u32(addw_base.checked_sub(addw_imm).unwrap())
                * local.adapter.imm_c;

        // The opcode is always ADDW (both for immediate and non-immediate variants)
        let opcode = AB::Expr::from_f(Opcode::ADDW.as_field());

        // ADDW always has the same funct3 and funct7
        let funct3 = AB::Expr::from_canonical_u8(Opcode::ADDW.funct3().unwrap());
        let funct7 = AB::Expr::from_canonical_u8(Opcode::ADDW.funct7().unwrap());

        // This chip is for the case `rd != x0`.
        builder.assert_zero(local.adapter.op_a_0);

        // Constrain the add operation over `op_b` and `op_c`.
        <AddwOperation<AB::F> as SP1Operation<AB>>::eval(
            builder,
            AddwOperationInput::new(
                local.adapter.b().map(|x| x.into()),
                local.adapter.c().map(|x| x.into()),
                local.addw_operation,
                local.is_real.into(),
            ),
        );

        // Constrain the state of the CPU.
        // The program counter and timestamp increment by `4` and `8`.
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

        let u16_max = AB::F::from_canonical_u32((1 << 16) - 1);

        let word: Word<AB::Expr> = Word([
            local.addw_operation.value[0].into(),
            local.addw_operation.value[1].into(),
            local.addw_operation.msb.msb * u16_max,
            local.addw_operation.msb.msb * u16_max,
        ]);

        let mut is_trusted: AB::Expr = local.is_real.into();

        #[cfg(feature = "mprotect")]
        builder.assert_eq(
            builder.extract_public_values().is_untrusted_programs_enabled,
            AB::Expr::from_bool(!M::IS_TRUSTED),
        );

        if !M::IS_TRUSTED {
            let local = main.row_slice(0);
            let local: &AddwCols<AB::Var, UserMode> = (*local).borrow();

            let instruction = local.adapter.instruction::<AB>(opcode.clone());

            #[cfg(not(feature = "mprotect"))]
            builder.assert_zero(local.is_real);

            eval_untrusted_program(
                builder,
                local.state.pc,
                instruction,
                [
                    calculated_instr_type.clone(),
                    calculated_base_opcode.clone(),
                    funct3.clone(),
                    funct7.clone(),
                ],
                [local.state.clk_high::<AB>(), local.state.clk_low::<AB>()],
                local.is_real.into(),
                local.adapter_cols,
            );

            is_trusted = local.adapter_cols.is_trusted.into();
        }

        // Constrain the program and register reads.
        let alu_reader_input = ALUTypeReaderInput::<AB, AB::Expr>::new(
            local.state.clk_high::<AB>(),
            local.state.clk_low::<AB>(),
            local.state.pc,
            opcode,
            word,
            local.adapter,
            local.is_real.into(),
            is_trusted,
        );
        ALUTypeReader::<AB::F>::eval(builder, alu_reader_input);
    }
}
