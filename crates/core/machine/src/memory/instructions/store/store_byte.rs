use crate::{
    adapter::{
        register::i_type::{ITypeReader, ITypeReaderImmutable, ITypeReaderImmutableInput},
        state::{CPUState, CPUStateInput},
    },
    air::{SP1CoreAirBuilder, SP1Operation},
    eval_untrusted_program,
    memory::MemoryAccessCols,
    operations::{AddressOperation, AddressOperationInput},
    utils::next_multiple_of_32,
    SupervisorMode, TrustMode, UserMode,
};
use hashbrown::HashMap;
use itertools::Itertools;
use rayon::iter::{ParallelBridge, ParallelIterator};
use slop_air::{Air, AirBuilder, BaseAir};
use slop_algebra::{AbstractField, Field, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, MemInstrEvent, MemoryAccessPosition},
    ExecutionRecord, Opcode, Program, CLK_INC, PC_INC,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{BaseAirBuilder, MachineAir},
    Word,
};
use sp1_primitives::consts::{u64_to_u16_limbs, PROT_WRITE};
use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    mem::{size_of, MaybeUninit},
};
use struct_reflection::{StructReflection, StructReflectionHelper};

#[derive(Default)]
pub struct StoreByteChip<M: TrustMode> {
    pub _phantom: PhantomData<M>,
}

pub const NUM_STORE_BYTE_COLS_SUPERVISOR: usize = size_of::<StoreByteColumns<u8, SupervisorMode>>();
pub const NUM_STORE_BYTE_COLS_USER: usize = size_of::<StoreByteColumns<u8, UserMode>>();

/// The column layout for memory store byte instructions.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy, StructReflection)]
#[repr(C)]
pub struct StoreByteColumns<T, M: TrustMode> {
    /// The current shard, timestamp, program counter of the CPU.
    pub state: CPUState<T>,

    /// The adapter to read program and register information.
    pub adapter: ITypeReader<T>,

    /// Instance of `AddressOperation` to constrain the memory address.
    pub address_operation: AddressOperation<T>,

    /// Memory consistency columns for the memory access.
    pub memory_access: MemoryAccessCols<T>,

    /// The bit decomposition of the offset.
    pub offset_bit: [T; 3],

    /// The selected memory limb value.
    pub mem_limb: T,

    /// The lower byte of the selected memory limb.
    pub mem_limb_low_byte: T,

    /// The low byte value of `op_a[0]`.
    pub register_low_byte: T,

    /// The increment value for the correct offset.
    pub increment: T,

    /// The value to store at memory.
    pub store_value: Word<T>,

    /// Whether this is a store byte instruction.
    pub is_real: T,

    /// Adapter columns for trust mode specific data.
    pub adapter_cols: M::AdapterCols<T>,
}

impl<F, M: TrustMode> BaseAir<F> for StoreByteChip<M> {
    fn width(&self) -> usize {
        if M::IS_TRUSTED {
            NUM_STORE_BYTE_COLS_SUPERVISOR
        } else {
            NUM_STORE_BYTE_COLS_USER
        }
    }
}

impl<F: PrimeField32, M: TrustMode> MachineAir<F> for StoreByteChip<M> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        if M::IS_TRUSTED {
            "StoreByte"
        } else {
            "StoreByteUser"
        }
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return Some(0);
        }
        let nb_rows = next_multiple_of_32(
            input.memory_store_byte_events.len(),
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
        let chunk_size = std::cmp::max((input.memory_store_byte_events.len()) / num_cpus::get(), 1);
        let padded_nb_rows = <StoreByteChip<M> as MachineAir<F>>::num_rows(self, input).unwrap();
        let num_event_rows = input.memory_store_byte_events.len();
        let width = <Self as BaseAir<F>>::width(self);

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
                    let cols: &mut StoreByteColumns<F, M> = row.borrow_mut();

                    if idx < input.memory_store_byte_events.len() {
                        let event = &input.memory_store_byte_events[idx];
                        self.event_to_row(&event.0, cols, &mut blu);
                        cols.state.populate(&mut blu, event.0.clk, event.0.pc);
                        cols.adapter.populate(&mut blu, event.1);
                        if !M::IS_TRUSTED {
                            let cols: &mut StoreByteColumns<F, UserMode> = row.borrow_mut();
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
            !shard.memory_store_byte_events.is_empty()
                && (M::IS_TRUSTED != shard.program.enable_untrusted_programs)
        }
    }

    fn column_names(&self) -> Vec<String> {
        StoreByteColumns::<F, M>::struct_reflection().unwrap()
    }
}

impl<M: TrustMode> StoreByteChip<M> {
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &MemInstrEvent,
        cols: &mut StoreByteColumns<F, M>,
        blu: &mut HashMap<ByteLookupEvent, usize>,
    ) {
        // Populate memory accesses for reading from memory.
        cols.memory_access.populate(event.mem_access, blu);

        let memory_addr = cols.address_operation.populate(blu, event.b, event.c);

        let bit0 = (memory_addr & 1) as u16;
        let bit1 = ((memory_addr >> 1) & 1) as u16;
        let bit2 = ((memory_addr >> 2) & 1) as u16;
        cols.offset_bit[0] = F::from_canonical_u16(bit0);
        cols.offset_bit[1] = F::from_canonical_u16(bit1);
        cols.offset_bit[2] = F::from_canonical_u16(bit2);

        let limb_number = 2 * bit2 + bit1;
        let limb = u64_to_u16_limbs(event.mem_access.prev_value())[limb_number as usize];
        let limb_a = (event.a & ((1 << 16) - 1)) as u16;
        blu.add_u8_range_checks(&limb.to_le_bytes());
        blu.add_u8_range_checks(&limb_a.to_le_bytes());

        cols.mem_limb = F::from_canonical_u16(limb);
        cols.mem_limb_low_byte = F::from_canonical_u16(limb & 0xFF);
        cols.register_low_byte = F::from_canonical_u64(event.a & 0xFF);
        cols.store_value = Word::from(event.mem_access.value());
        cols.increment =
            (cols.register_low_byte - cols.mem_limb_low_byte) * (F::one() - cols.offset_bit[0]);
        cols.increment += (F::from_canonical_u16(1 << 8) * cols.register_low_byte - cols.mem_limb
            + cols.mem_limb_low_byte)
            * cols.offset_bit[0];

        cols.is_real = F::one();
    }
}

impl<AB, M> Air<AB> for StoreByteChip<M>
where
    AB: SP1CoreAirBuilder,
    AB::Var: Sized,
    M: TrustMode,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &StoreByteColumns<AB::Var, M> = (*local).borrow();

        let clk_high = local.state.clk_high::<AB>();
        let clk_low = local.state.clk_low::<AB>();

        let opcode = AB::Expr::from_canonical_u32(Opcode::SB as u32);
        let funct3 = AB::Expr::from_canonical_u8(Opcode::SB.funct3().unwrap());
        let funct7 = AB::Expr::from_canonical_u8(Opcode::SB.funct7().unwrap_or(0));
        let base_opcode = AB::Expr::from_canonical_u32(Opcode::SB.base_opcode().0);
        let instr_type = AB::Expr::from_canonical_u32(Opcode::SB.instruction_type().0 as u32);
        builder.assert_bool(local.is_real);

        // Step 1. Compute the address, and check offsets and address bounds.
        let aligned_addr = <AddressOperation<AB::F> as SP1Operation<AB>>::eval(
            builder,
            AddressOperationInput::new(
                local.adapter.b().map(Into::into),
                local.adapter.c().map(Into::into),
                local.offset_bit[0].into(),
                local.offset_bit[1].into(),
                local.offset_bit[2].into(),
                local.is_real.into(),
                local.address_operation,
            ),
        );

        // Step 2. Write the memory address and check page prot access.
        // The `store_value` will be constrained in Step 3.
        builder.eval_memory_access_write(
            clk_high.clone(),
            clk_low.clone() + AB::Expr::from_canonical_u32(MemoryAccessPosition::Memory as u32),
            &aligned_addr.clone().map(Into::into),
            local.memory_access,
            local.store_value,
            local.is_real.into(),
        );

        // Step 3. Use the memory value to compute the write value for `op_a`.
        // Select the u16 limb corresponding to the offset.
        builder
            .when_not(local.offset_bit[1])
            .when_not(local.offset_bit[2])
            .assert_eq(local.mem_limb, local.memory_access.prev_value[0]);
        builder
            .when(local.offset_bit[1])
            .when_not(local.offset_bit[2])
            .assert_eq(local.mem_limb, local.memory_access.prev_value[1]);
        builder
            .when_not(local.offset_bit[1])
            .when(local.offset_bit[2])
            .assert_eq(local.mem_limb, local.memory_access.prev_value[2]);
        builder
            .when(local.offset_bit[1])
            .when(local.offset_bit[2])
            .assert_eq(local.mem_limb, local.memory_access.prev_value[3]);

        // Split the u16 register limb into two bytes.
        let byte0 = local.register_low_byte;
        let byte1 =
            (local.adapter.prev_a().0[0] - byte0) * AB::F::from_canonical_u32(1 << 8).inverse();
        builder.slice_range_check_u8(&[byte0.into(), byte1.clone()], local.is_real);

        // Split the u16 memory limb into two bytes.
        let byte0 = local.mem_limb_low_byte;
        let byte1 = (local.mem_limb - byte0) * AB::F::from_canonical_u32(1 << 8).inverse();
        builder.slice_range_check_u8(&[byte0.into(), byte1.clone()], local.is_real);

        builder.assert_eq(
            local.increment,
            (local.register_low_byte - local.mem_limb_low_byte)
                * (AB::Expr::one() - local.offset_bit[0])
                + AB::Expr::from_canonical_u16(1 << 8)
                    * (local.register_low_byte - byte1)
                    * local.offset_bit[0],
        );

        builder.assert_eq(
            local.store_value.0[0],
            local.increment
                * (AB::Expr::one() - local.offset_bit[1])
                * (AB::Expr::one() - local.offset_bit[2])
                + local.memory_access.prev_value.0[0],
        );
        builder.assert_eq(
            local.store_value.0[1],
            local.increment * local.offset_bit[1] * (AB::Expr::one() - local.offset_bit[2])
                + local.memory_access.prev_value.0[1],
        );
        builder.assert_eq(
            local.store_value.0[2],
            local.increment * (AB::Expr::one() - local.offset_bit[1]) * local.offset_bit[2]
                + local.memory_access.prev_value.0[2],
        );
        builder.assert_eq(
            local.store_value.0[3],
            local.increment * local.offset_bit[1] * local.offset_bit[2]
                + local.memory_access.prev_value.0[3],
        );

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

        let mut is_trusted: AB::Expr = local.is_real.into();

        #[cfg(feature = "mprotect")]
        builder.assert_eq(
            builder.extract_public_values().is_untrusted_programs_enabled,
            AB::Expr::from_bool(!M::IS_TRUSTED),
        );

        if !M::IS_TRUSTED {
            let local = main.row_slice(0);
            let local: &StoreByteColumns<AB::Var, UserMode> = (*local).borrow();

            let instruction = local.adapter.instruction::<AB>(opcode.clone());

            #[cfg(not(feature = "mprotect"))]
            builder.assert_zero(local.is_real);

            eval_untrusted_program(
                builder,
                local.state.pc,
                instruction,
                [instr_type, base_opcode, funct3, funct7],
                [local.state.clk_high::<AB>(), local.state.clk_low::<AB>()],
                local.is_real.into(),
                local.adapter_cols,
            );

            builder.send_page_prot(
                clk_high.clone(),
                clk_low.clone() + AB::Expr::from_canonical_u32(MemoryAccessPosition::Memory as u32),
                &aligned_addr.map(Into::into),
                AB::Expr::from_canonical_u8(PROT_WRITE),
                local.is_real.into(),
            );

            is_trusted = local.adapter_cols.is_trusted.into();
        }

        // Constrain the program and register reads.
        <ITypeReaderImmutable as SP1Operation<AB>>::eval(
            builder,
            ITypeReaderImmutableInput::new(
                clk_high.clone(),
                clk_low.clone(),
                local.state.pc,
                opcode,
                local.adapter,
                local.is_real.into(),
                is_trusted,
            ),
        );
    }
}
