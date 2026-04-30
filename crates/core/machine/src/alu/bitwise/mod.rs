use crate::{
    adapter::{
        register::alu_type::{ALUTypeReader, ALUTypeReaderInput},
        state::{CPUState, CPUStateInput},
    },
    air::{SP1CoreAirBuilder, SP1Operation},
    eval_untrusted_program,
    operations::{BitwiseU16Operation, BitwiseU16OperationInput},
    utils::next_multiple_of_32,
    SupervisorMode, TrustMode, UserMode,
};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};
use std::marker::PhantomData;

use hashbrown::HashMap;
use itertools::Itertools;
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefIterator},
    slice::ParallelSliceMut,
};
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField, PrimeField32};
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::{ParallelIterator, ParallelSlice};
use sp1_core_executor::{
    events::{AluEvent, ByteLookupEvent, ByteRecord},
    ByteOpcode, ExecutionRecord, Opcode, Program, CLK_INC, PC_INC,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::MachineAir;
use struct_reflection::{StructReflection, StructReflectionHelper};

/// The number of main trace columns for `BitwiseChip` in Supervisor mode.
pub const NUM_BITWISE_COLS_SUPERVISOR: usize = size_of::<BitwiseCols<u8, SupervisorMode>>();
/// The number of main trace columns for `BitwiseChip` in User mode.
pub const NUM_BITWISE_COLS_USER: usize = size_of::<BitwiseCols<u8, UserMode>>();

/// A chip that implements bitwise operations for the opcodes XOR, OR, and AND.
#[derive(Default)]
pub struct BitwiseChip<M: TrustMode> {
    pub _phantom: PhantomData<M>,
}

/// The column layout for the chip.
#[derive(AlignedBorrow, StructReflection, Default, Clone, Copy)]
#[repr(C)]
pub struct BitwiseCols<T, M: TrustMode> {
    /// The current shard, timestamp, program counter of the CPU.
    pub state: CPUState<T>,

    /// The adapter to read program and register information.
    pub adapter: ALUTypeReader<T>,

    /// Instance of `BitwiseOperation` to handle bitwise logic in `BitwiseChip`'s ALU operations.
    pub bitwise_operation: BitwiseU16Operation<T>,

    /// If the opcode is XOR.
    pub is_xor: T,

    // If the opcode is OR.
    pub is_or: T,

    /// If the opcode is AND.
    pub is_and: T,

    /// Adapter columns for trust mode specific data.
    pub adapter_cols: M::AdapterCols<T>,
}

impl<F: PrimeField32, M: TrustMode> MachineAir<F> for BitwiseChip<M> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        if M::IS_TRUSTED {
            "Bitwise"
        } else {
            "BitwiseUser"
        }
    }

    fn column_names(&self) -> Vec<String> {
        BitwiseCols::<F, M>::struct_reflection().unwrap()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return Some(0);
        }
        let nb_rows =
            next_multiple_of_32(input.bitwise_events.len(), input.fixed_log2_rows::<F, _>(self));
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

        let padded_nb_rows = <BitwiseChip<M> as MachineAir<F>>::num_rows(self, input).unwrap();
        let nb_rows = input.bitwise_events.len();
        let width = <BitwiseChip<M> as BaseAir<F>>::width(self);

        unsafe {
            let padding_start = nb_rows * width;
            let padding_size = (padded_nb_rows - nb_rows) * width;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, padded_nb_rows * width) };

        values[..nb_rows * width]
            .par_chunks_exact_mut(width)
            .zip(input.bitwise_events.par_iter())
            .for_each(|(row, event)| {
                let cols: &mut BitwiseCols<F, M> = row.borrow_mut();

                let mut blu = Vec::new();
                cols.adapter.populate(&mut blu, event.1);
                self.event_to_row(&event.0, cols, &mut blu);
                cols.state.populate(&mut blu, event.0.clk, event.0.pc);
                if !M::IS_TRUSTED {
                    let cols: &mut BitwiseCols<F, UserMode> = row.borrow_mut();
                    cols.adapter_cols.is_trusted = F::from_bool(!event.1.is_untrusted);
                }
            });
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return;
        }

        let chunk_size = std::cmp::max(input.bitwise_events.len() / num_cpus::get(), 1);
        let width = <BitwiseChip<M> as BaseAir<F>>::width(self);

        let blu_batches = input
            .bitwise_events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = vec![F::zero(); width];
                    let cols: &mut BitwiseCols<F, M> = row.as_mut_slice().borrow_mut();
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
            !shard.bitwise_events.is_empty()
                && (M::IS_TRUSTED != shard.program.enable_untrusted_programs)
        }
    }
}

impl<M: TrustMode> BitwiseChip<M> {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField>(
        &self,
        event: &AluEvent,
        cols: &mut BitwiseCols<F, M>,
        blu: &mut impl ByteRecord,
    ) {
        cols.bitwise_operation.populate_bitwise(blu, event.a, event.b, event.c, event.opcode);

        cols.is_xor = F::from_bool(event.opcode == Opcode::XOR);
        cols.is_or = F::from_bool(event.opcode == Opcode::OR);
        cols.is_and = F::from_bool(event.opcode == Opcode::AND);
    }
}

impl<F, M: TrustMode> BaseAir<F> for BitwiseChip<M> {
    fn width(&self) -> usize {
        if M::IS_TRUSTED {
            NUM_BITWISE_COLS_SUPERVISOR
        } else {
            NUM_BITWISE_COLS_USER
        }
    }
}

impl<AB, M> Air<AB> for BitwiseChip<M>
where
    AB: SP1CoreAirBuilder,
    M: TrustMode,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &BitwiseCols<AB::Var, M> = (*local).borrow();

        // SAFETY: All selectors `is_xor`, `is_or`, `is_and` are checked to be boolean.
        // Each "real" row has exactly one selector turned on, as `is_real`, the sum of the three
        // selectors, is boolean. Therefore, the `opcode` and `cpu_opcode` matches the
        // corresponding opcode.
        let is_real = local.is_xor + local.is_or + local.is_and;
        builder.assert_bool(local.is_xor);
        builder.assert_bool(local.is_or);
        builder.assert_bool(local.is_and);
        builder.assert_bool(is_real.clone());

        // Get the opcode for the operation.
        let byte_opcode = local.is_xor * ByteOpcode::XOR.as_field::<AB::F>()
            + local.is_or * ByteOpcode::OR.as_field::<AB::F>()
            + local.is_and * ByteOpcode::AND.as_field::<AB::F>();

        // Get the cpu opcode, which corresponds to the opcode being sent in the CPU table.
        let cpu_opcode = local.is_xor * Opcode::XOR.as_field::<AB::F>()
            + local.is_or * Opcode::OR.as_field::<AB::F>()
            + local.is_and * Opcode::AND.as_field::<AB::F>();

        // Compute instruction field constants for each opcode
        let funct3 = local.is_xor * AB::Expr::from_canonical_u8(Opcode::XOR.funct3().unwrap())
            + local.is_or * AB::Expr::from_canonical_u8(Opcode::OR.funct3().unwrap())
            + local.is_and * AB::Expr::from_canonical_u8(Opcode::AND.funct3().unwrap());
        let funct7 = local.is_xor * AB::Expr::from_canonical_u8(Opcode::XOR.funct7().unwrap_or(0))
            + local.is_or * AB::Expr::from_canonical_u8(Opcode::OR.funct7().unwrap_or(0))
            + local.is_and * AB::Expr::from_canonical_u8(Opcode::AND.funct7().unwrap_or(0));

        let (xor_base, xor_imm) = Opcode::XOR.base_opcode();
        let xor_imm = xor_imm.expect("XOR immediate opcode not found");
        let (or_base, or_imm) = Opcode::OR.base_opcode();
        let or_imm = or_imm.expect("OR immediate opcode not found");
        let (and_base, and_imm) = Opcode::AND.base_opcode();
        let and_imm = and_imm.expect("AND immediate opcode not found");

        let xor_base_expr = AB::Expr::from_canonical_u32(xor_base);
        let or_base_expr = AB::Expr::from_canonical_u32(or_base);
        let and_base_expr = AB::Expr::from_canonical_u32(and_base);

        let imm_base_difference = xor_base.checked_sub(xor_imm).unwrap();
        assert_eq!(imm_base_difference, or_base.checked_sub(or_imm).unwrap());
        assert_eq!(imm_base_difference, and_base.checked_sub(and_imm).unwrap());

        let calculated_base_opcode = local.is_xor * xor_base_expr
            + local.is_or * or_base_expr
            + local.is_and * and_base_expr
            - AB::Expr::from_canonical_u32(imm_base_difference) * local.adapter.imm_c;

        let xor_instr_type = Opcode::XOR.instruction_type().0 as u32;
        let xor_instr_type_imm =
            Opcode::XOR.instruction_type().1.expect("XOR immediate instruction type not found")
                as u32;
        let or_instr_type = Opcode::OR.instruction_type().0 as u32;
        let or_instr_type_imm =
            Opcode::OR.instruction_type().1.expect("OR immediate instruction type not found")
                as u32;
        let and_instr_type = Opcode::AND.instruction_type().0 as u32;
        let and_instr_type_imm =
            Opcode::AND.instruction_type().1.expect("AND immediate instruction type not found")
                as u32;

        let instr_type_difference = xor_instr_type.checked_sub(xor_instr_type_imm).unwrap();
        assert_eq!(instr_type_difference, or_instr_type.checked_sub(or_instr_type_imm).unwrap());
        assert_eq!(instr_type_difference, and_instr_type.checked_sub(and_instr_type_imm).unwrap());

        let calculated_instr_type = local.is_xor * AB::Expr::from_canonical_u32(xor_instr_type)
            + local.is_or * AB::Expr::from_canonical_u32(or_instr_type)
            + local.is_and * AB::Expr::from_canonical_u32(and_instr_type)
            - AB::Expr::from_canonical_u32(instr_type_difference) * local.adapter.imm_c;

        // This chip is for the case `rd != x0`.
        builder.assert_zero(local.adapter.op_a_0);

        // Constrain the bitwise operation over `op_b` and `op_c`.
        let bitwise_u16_input = BitwiseU16OperationInput::<AB>::new(
            local.adapter.b().map(Into::into),
            local.adapter.c().map(Into::into),
            local.bitwise_operation,
            byte_opcode,
            is_real.clone(),
        );
        let result =
            <BitwiseU16Operation<AB::F> as SP1Operation<AB>>::eval(builder, bitwise_u16_input);

        // Constrain the state of the CPU.
        // The program counter and timestamp increment by `4` and `8`.
        let cpu_state_input = CPUStateInput::<AB>::new(
            local.state,
            [
                local.state.pc[0] + AB::F::from_canonical_u32(PC_INC),
                local.state.pc[1].into(),
                local.state.pc[2].into(),
            ],
            AB::Expr::from_canonical_u32(CLK_INC),
            is_real.clone(),
        );
        <CPUState<AB::F> as SP1Operation<AB>>::eval(builder, cpu_state_input);

        let mut is_trusted: AB::Expr = is_real.clone();

        #[cfg(feature = "mprotect")]
        builder.assert_eq(
            builder.extract_public_values().is_untrusted_programs_enabled,
            AB::Expr::from_bool(!M::IS_TRUSTED),
        );

        if !M::IS_TRUSTED {
            let local = main.row_slice(0);
            let local: &BitwiseCols<AB::Var, UserMode> = (*local).borrow();

            let instruction = local.adapter.instruction::<AB>(cpu_opcode.clone());

            #[cfg(not(feature = "mprotect"))]
            builder.assert_zero(is_real.clone());

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
                is_real.clone(),
                local.adapter_cols,
            );

            is_trusted = local.adapter_cols.is_trusted.into();
        }

        // Constrain the program and register reads.
        let alu_reader_input = ALUTypeReaderInput::<AB, AB::Expr>::new(
            local.state.clk_high::<AB>(),
            local.state.clk_low::<AB>(),
            local.state.pc,
            cpu_opcode,
            result,
            local.adapter,
            is_real,
            is_trusted,
        );
        <ALUTypeReader<AB::F> as SP1Operation<AB>>::eval(builder, alu_reader_input);
    }
}
