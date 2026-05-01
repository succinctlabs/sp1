use slop_air::{Air, AirBuilder, BaseAir};
use slop_matrix::Matrix;
use sp1_derive::AlignedBorrow;
use sp1_primitives::consts::{u64_to_u16_limbs, PROT_READ};
use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    mem::{size_of, MaybeUninit},
};

use crate::{
    adapter::{
        register::i_type::{ITypeReader, ITypeReaderInput},
        state::{CPUState, CPUStateInput},
    },
    air::{SP1CoreAirBuilder, SP1Operation},
    eval_untrusted_program,
    memory::MemoryAccessCols,
    operations::{AddressOperation, AddressOperationInput, U16MSBOperation, U16MSBOperationInput},
    utils::next_multiple_of_32,
    SupervisorMode, TrustMode, UserMode,
};
use hashbrown::HashMap;
use itertools::Itertools;
use rayon::iter::{ParallelBridge, ParallelIterator};
use slop_algebra::{AbstractField, PrimeField32};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, MemInstrEvent, MemoryAccessPosition},
    ExecutionRecord, Opcode, Program, CLK_INC, PC_INC,
};

use sp1_hypercube::{air::MachineAir, Word};
use struct_reflection::{StructReflection, StructReflectionHelper};

#[derive(Default)]
pub struct LoadWordChip<M: TrustMode> {
    pub _phantom: PhantomData<M>,
}

pub const NUM_LOAD_WORD_COLS_SUPERVISOR: usize = size_of::<LoadWordColumns<u8, SupervisorMode>>();
pub const NUM_LOAD_WORD_COLS_USER: usize = size_of::<LoadWordColumns<u8, UserMode>>();

/// The column layout for memory load word instructions.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy, StructReflection)]
#[repr(C)]
pub struct LoadWordColumns<T, M: TrustMode> {
    /// The current shard, timestamp, program counter of the CPU.
    pub state: CPUState<T>,

    /// The adapter to read program and register information.
    pub adapter: ITypeReader<T>,

    /// Instance of `AddressOperation` to constrain the memory address.
    pub address_operation: AddressOperation<T>,

    /// Memory consistency columns for the memory access.
    pub memory_access: MemoryAccessCols<T>,

    /// Whether the offset is `0` or `4`.
    pub offset_bit: T,

    /// The selected word of the memory access.
    pub selected_word: [T; 2],

    /// The `MSB` of the word, if the opcode is `LW`.
    pub msb: U16MSBOperation<T>,

    /// Whether this is a load half instruction.
    pub is_lw: T,

    /// Whether this is a load half unsigned instruction.
    pub is_lwu: T,

    /// Adapter columns for trust mode specific data.
    pub adapter_cols: M::AdapterCols<T>,
}

impl<F, M: TrustMode> BaseAir<F> for LoadWordChip<M> {
    fn width(&self) -> usize {
        if M::IS_TRUSTED {
            NUM_LOAD_WORD_COLS_SUPERVISOR
        } else {
            NUM_LOAD_WORD_COLS_USER
        }
    }
}

impl<F: PrimeField32, M: TrustMode> MachineAir<F> for LoadWordChip<M> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        if M::IS_TRUSTED {
            "LoadWord"
        } else {
            "LoadWordUser"
        }
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return Some(0);
        }
        let nb_rows = next_multiple_of_32(
            input.memory_load_word_events.len(),
            input.fixed_log2_rows::<F, _>(self),
        );
        Some(nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return;
        }
        let chunk_size = std::cmp::max((input.memory_load_word_events.len()) / num_cpus::get(), 1);
        let padded_nb_rows = <LoadWordChip<M> as MachineAir<F>>::num_rows(self, input).unwrap();
        let num_event_rows = input.memory_load_word_events.len();

        let width = <LoadWordChip<M> as BaseAir<F>>::width(self);
        unsafe {
            let padding_start = num_event_rows * width;
            let padding_size = (padded_nb_rows - num_event_rows) * width;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, padded_nb_rows * width) };

        let blu_events = values
            .chunks_mut(chunk_size * width)
            .enumerate()
            .par_bridge()
            .map(|(i, rows)| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                rows.chunks_mut(width).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut LoadWordColumns<F, M> = row.borrow_mut();

                    if idx < input.memory_load_word_events.len() {
                        let event = &input.memory_load_word_events[idx];
                        self.event_to_row(&event.0, cols, &mut blu);
                        cols.state.populate(&mut blu, event.0.clk, event.0.pc);
                        cols.adapter.populate(&mut blu, event.1);
                        if !M::IS_TRUSTED {
                            let cols: &mut LoadWordColumns<F, UserMode> = row.borrow_mut();
                            cols.adapter_cols.is_trusted = F::from_bool(!event.1.is_untrusted);
                        }
                    }
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_events.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.memory_load_word_events.is_empty()
                && (M::IS_TRUSTED != shard.program.enable_untrusted_programs)
        }
    }

    fn column_names(&self) -> Vec<String> {
        LoadWordColumns::<F, M>::struct_reflection().unwrap()
    }
}

impl<M: TrustMode> LoadWordChip<M> {
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &MemInstrEvent,
        cols: &mut LoadWordColumns<F, M>,
        blu: &mut HashMap<ByteLookupEvent, usize>,
    ) {
        // Populate memory accesses for reading from memory.
        cols.memory_access.populate(event.mem_access, blu);

        let memory_addr = cols.address_operation.populate(blu, event.b, event.c);
        let bit_2 = ((memory_addr >> 2) & 1) as u16;
        cols.offset_bit = F::from_canonical_u16(bit_2);
        let limb_number = 2 * bit_2;
        let limb_0 = u64_to_u16_limbs(event.mem_access.value())[limb_number as usize];
        let limb_1 = u64_to_u16_limbs(event.mem_access.value())[limb_number as usize + 1];

        cols.selected_word = [F::from_canonical_u16(limb_0), F::from_canonical_u16(limb_1)];

        if event.opcode == Opcode::LW {
            cols.is_lw = F::one();
            cols.is_lwu = F::zero();
            cols.msb.populate_msb(blu, limb_1);
        } else {
            cols.is_lw = F::zero();
            cols.is_lwu = F::one();
            cols.msb.msb = F::zero();
        }
    }
}

impl<AB, M> Air<AB> for LoadWordChip<M>
where
    AB: SP1CoreAirBuilder,
    AB::Var: Sized,
    M: TrustMode,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &LoadWordColumns<AB::Var, M> = (*local).borrow();

        let clk_high = local.state.clk_high::<AB>();
        let clk_low = local.state.clk_low::<AB>();

        let opcode = local.is_lw.into() * AB::Expr::from_canonical_u32(Opcode::LW as u32)
            + local.is_lwu.into() * AB::Expr::from_canonical_u32(Opcode::LWU as u32);

        // Compute instruction field constants
        let funct3 = local.is_lw * AB::Expr::from_canonical_u8(Opcode::LW.funct3().unwrap())
            + local.is_lwu * AB::Expr::from_canonical_u8(Opcode::LWU.funct3().unwrap());
        let funct7 = local.is_lw * AB::Expr::from_canonical_u8(Opcode::LW.funct7().unwrap_or(0))
            + local.is_lwu * AB::Expr::from_canonical_u8(Opcode::LWU.funct7().unwrap_or(0));
        let base_opcode = local.is_lw * AB::Expr::from_canonical_u32(Opcode::LW.base_opcode().0)
            + local.is_lwu * AB::Expr::from_canonical_u32(Opcode::LWU.base_opcode().0);
        let instr_type = local.is_lw
            * AB::Expr::from_canonical_u32(Opcode::LW.instruction_type().0 as u32)
            + local.is_lwu * AB::Expr::from_canonical_u32(Opcode::LWU.instruction_type().0 as u32);

        let is_real = local.is_lw + local.is_lwu;
        builder.assert_bool(local.is_lw);
        builder.assert_bool(local.is_lwu);
        builder.assert_bool(is_real.clone());

        // Step 1. Compute the address, and check offsets and address bounds.
        let aligned_addr = <AddressOperation<AB::F> as SP1Operation<AB>>::eval(
            builder,
            AddressOperationInput::new(
                local.adapter.b().map(Into::into),
                local.adapter.c().map(Into::into),
                AB::Expr::zero(),
                AB::Expr::zero(),
                local.offset_bit.into(),
                is_real.clone(),
                local.address_operation,
            ),
        );

        // Step 2. Read the memory address and check page prot access.
        builder.eval_memory_access_read(
            clk_high.clone(),
            clk_low.clone() + AB::Expr::from_canonical_u32(MemoryAccessPosition::Memory as u32),
            &aligned_addr.clone().map(Into::into),
            local.memory_access,
            is_real.clone(),
        );

        // This chip requires `op_a != x0`.
        builder.assert_zero(local.adapter.op_a_0);

        builder
            .when_not(local.offset_bit)
            .assert_eq(local.selected_word[0], local.memory_access.prev_value[0]);
        builder
            .when_not(local.offset_bit)
            .assert_eq(local.selected_word[1], local.memory_access.prev_value[1]);
        builder
            .when(local.offset_bit)
            .assert_eq(local.selected_word[0], local.memory_access.prev_value[2]);
        builder
            .when(local.offset_bit)
            .assert_eq(local.selected_word[1], local.memory_access.prev_value[3]);

        <U16MSBOperation<AB::F> as SP1Operation<AB>>::eval(
            builder,
            U16MSBOperationInput::<AB>::new(
                local.selected_word[1].into(),
                local.msb,
                local.is_lw.into(),
            ),
        );
        builder.when_not(local.is_lw).assert_zero(local.msb.msb);

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
                is_real.clone(),
            ),
        );

        let mut is_trusted: AB::Expr = is_real.clone();

        #[cfg(feature = "mprotect")]
        builder.assert_eq(
            builder.extract_public_values().is_untrusted_programs_enabled,
            AB::Expr::from_bool(!M::IS_TRUSTED),
        );

        if !M::IS_TRUSTED {
            let local = main.row_slice(0);
            let local: &LoadWordColumns<AB::Var, UserMode> = (*local).borrow();

            let instruction = local.adapter.instruction::<AB>(opcode.clone());

            #[cfg(not(feature = "mprotect"))]
            builder.assert_zero(is_real.clone());

            eval_untrusted_program(
                builder,
                local.state.pc,
                instruction,
                [instr_type, base_opcode, funct3, funct7],
                [local.state.clk_high::<AB>(), local.state.clk_low::<AB>()],
                is_real.clone(),
                local.adapter_cols,
            );

            builder.send_page_prot(
                clk_high.clone(),
                clk_low.clone() + AB::Expr::from_canonical_u32(MemoryAccessPosition::Memory as u32),
                &aligned_addr.map(Into::into),
                AB::Expr::from_canonical_u8(PROT_READ),
                is_real.clone(),
            );

            is_trusted = local.adapter_cols.is_trusted.into();
        }

        // Constrain the program and register reads.
        <ITypeReader<AB::F> as SP1Operation<AB>>::eval(
            builder,
            ITypeReaderInput::new(
                clk_high.clone(),
                clk_low.clone(),
                local.state.pc,
                opcode,
                Word([
                    local.selected_word[0].into(),
                    local.selected_word[1].into(),
                    AB::Expr::from_canonical_u16(u16::MAX) * local.msb.msb,
                    AB::Expr::from_canonical_u16(u16::MAX) * local.msb.msb,
                ]),
                local.adapter,
                is_real.clone(),
                is_trusted,
            ),
        );
    }
}
