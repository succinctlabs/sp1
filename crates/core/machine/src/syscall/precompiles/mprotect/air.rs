use crate::{
    air::{SP1CoreAirBuilder, SP1Operation},
    memory::PageProtAccessCols,
    operations::{LtOperationUnsigned, LtOperationUnsignedInput},
    utils::next_multiple_of_32,
};
use core::borrow::Borrow;
use slop_air::{Air, AirBuilder, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, PrecompileEvent},
    ByteOpcode, ExecutionRecord, Program, SyscallCode,
};
use sp1_derive::AlignedBorrow;
#[cfg(feature = "mprotect")]
use sp1_hypercube::{addr_to_limbs, air::BaseAirBuilder};
use sp1_hypercube::{
    air::{InteractionScope, MachineAir},
    Word,
};
use sp1_primitives::consts::{PROT_EXEC, PROT_READ, PROT_WRITE};
use std::{borrow::BorrowMut, mem::MaybeUninit};

/// The number of columns in the MProtectCols.
const NUM_COLS: usize = size_of::<MProtectCols<u8>>();

#[derive(Default)]
pub struct MProtectChip;

impl MProtectChip {
    pub const fn new() -> Self {
        Self
    }
}

/// A set of columns for the MProtect operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct MProtectCols<T> {
    /// Clock cycle of the syscall (split into high and low parts)
    pub clk_high: T,
    pub clk_low: T,

    /// Address being protected (page-aligned) - 48 bits split into 3x16-bit limbs
    pub addr: [T; 3],

    /// Split the least significant limb: 4 MSBs and 12 LSBs for page alignment
    pub addr_4_bits: T,
    pub addr_12_bits: T,

    /// Protection flags (8 bits)
    pub prot: T,

    /// Individual protection flag bits
    pub prot_read: T,
    pub prot_write: T,
    pub prot_exec: T,

    /// Whether this row is real
    pub is_real: T,

    /// Interaction with page protection table
    pub page_prot_access: PageProtAccessCols<T>,

    /// The untrusted memory region from public values.
    pub untrusted_memory: [[T; 3]; 2],

    /// Comparison with untrusted memory.
    pub addr_range_check: [LtOperationUnsigned<T>; 2],
}

impl<F> BaseAir<F> for MProtectChip {
    fn width(&self) -> usize {
        NUM_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for MProtectChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> &'static str {
        "Mprotect"
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = input.get_precompile_events(SyscallCode::MPROTECT).len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let padded_nb_rows = <MProtectChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let mut blu_events = Vec::new();

        let mprotect_events = input.get_precompile_events(SyscallCode::MPROTECT);
        let num_event_rows = mprotect_events.len();
        if input.public_values.is_untrusted_programs_enabled == 0 {
            assert!(
                mprotect_events.is_empty(),
                "Page protect is disabled, but mprotect events are present"
            );
        }

        unsafe {
            let padding_start = num_event_rows * NUM_COLS;
            let padding_size = (padded_nb_rows - num_event_rows) * NUM_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values =
            unsafe { core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * NUM_COLS) };

        values.chunks_mut(NUM_COLS).enumerate().for_each(|(idx, row)| {
            let event = &mprotect_events[idx].1;
            let event =
                if let PrecompileEvent::Mprotect(event) = event { event } else { unreachable!() };

            let cols: &mut MProtectCols<F> = row.borrow_mut();
            // Set clock
            assert!(event.local_page_prot_access.len() == 1);
            let clk = event.local_page_prot_access[0].final_page_prot_access.timestamp;
            cols.clk_high = F::from_canonical_u32((clk >> 24) as u32);
            cols.clk_low = F::from_canonical_u32((clk & 0xFFFFFF) as u32);

            // Set address (split into 3x16-bit limbs)
            cols.addr[0] = F::from_canonical_u32((event.addr & 0xFFFF) as u32);
            cols.addr[1] = F::from_canonical_u32(((event.addr >> 16) & 0xFFFF) as u32);
            cols.addr[2] = F::from_canonical_u32(((event.addr >> 32) & 0xFFFF) as u32);

            // Split least significant limb: 4 MSBs and 12 LSBs
            let addr_12_bits = (event.addr & 0xFFF) as u16; // bits [11:0]
            let addr_4_bits = ((event.addr >> 12) & 0xF) as u16; // bits [15:12]

            cols.addr_12_bits = F::from_canonical_u16(addr_12_bits);
            cols.addr_4_bits = F::from_canonical_u16(addr_4_bits);

            // Add range check events for addr_4_bits (log₂(16)=4) and addr_12_bits (log₂(4096)=12)
            blu_events.push(ByteLookupEvent {
                opcode: ByteOpcode::Range,
                a: addr_4_bits,
                b: 4,
                c: 0,
            });

            blu_events.push(ByteLookupEvent {
                opcode: ByteOpcode::Range,
                a: addr_12_bits,
                b: 12, // log₂(4096) = 12
                c: 0,
            });

            // Set protection flags
            let page_prot = event.local_page_prot_access[0].final_page_prot_access.page_prot;
            cols.prot = F::from_canonical_u8(page_prot);
            cols.prot_read = if page_prot & PROT_READ != 0 { F::one() } else { F::zero() };
            cols.prot_write = if page_prot & PROT_WRITE != 0 { F::one() } else { F::zero() };
            cols.prot_exec = if page_prot & PROT_EXEC != 0 { F::one() } else { F::zero() };

            cols.page_prot_access.populate(
                &event.local_page_prot_access[0].initial_page_prot_access,
                clk,
                &mut blu_events,
            );

            cols.is_real = F::one();
            #[cfg(feature = "mprotect")]
            {
                cols.untrusted_memory[0] = addr_to_limbs(input.public_values.untrusted_memory[0]);
                cols.untrusted_memory[1] = addr_to_limbs(input.public_values.untrusted_memory[1]);

                // Check that `addr < mem[0]` is false.
                cols.addr_range_check[0].populate_unsigned(
                    &mut blu_events,
                    0,
                    event.addr,
                    input.public_values.untrusted_memory[0],
                );
                // Check that `addr < mem[1]` is true.
                cols.addr_range_check[1].populate_unsigned(
                    &mut blu_events,
                    1,
                    event.addr,
                    input.public_values.untrusted_memory[1],
                );
            }
        });

        // Add byte lookup events to output
        output.add_byte_lookup_events(blu_events);
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::MPROTECT).is_empty()
        }
    }
}

impl<AB> Air<AB> for MProtectChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MProtectCols<AB::Var> = (*local).borrow();

        let public_values = builder.extract_public_values();

        builder.assert_bool(local.is_real);
        builder.assert_eq(public_values.is_untrusted_programs_enabled, AB::Expr::one());
        #[cfg(feature = "mprotect")]
        {
            builder
                .when(local.is_real)
                .assert_all_eq(public_values.untrusted_memory[0], local.untrusted_memory[0]);
            builder
                .when(local.is_real)
                .assert_all_eq(public_values.untrusted_memory[1], local.untrusted_memory[1]);
        }
        #[cfg(not(feature = "mprotect"))]
        builder.assert_zero(local.is_real);

        // Check that `addr < untrusted_memory[0]` is false, so `addr >= untrusted_memory[0]`.
        <LtOperationUnsigned<AB::F> as SP1Operation<AB>>::eval(
            builder,
            LtOperationUnsignedInput::<AB>::new(
                Word([
                    local.addr[0].into(),
                    local.addr[1].into(),
                    local.addr[2].into(),
                    AB::Expr::zero(),
                ]),
                Word([
                    local.untrusted_memory[0][0].into(),
                    local.untrusted_memory[0][1].into(),
                    local.untrusted_memory[0][2].into(),
                    AB::Expr::zero(),
                ]),
                local.addr_range_check[0],
                local.is_real.into(),
            ),
        );
        builder
            .when(local.is_real)
            .assert_zero(local.addr_range_check[0].u16_compare_operation.bit);

        // Check that `addr < untrusted_memory[1]` is true.
        <LtOperationUnsigned<AB::F> as SP1Operation<AB>>::eval(
            builder,
            LtOperationUnsignedInput::<AB>::new(
                Word([
                    local.addr[0].into(),
                    local.addr[1].into(),
                    local.addr[2].into(),
                    AB::Expr::zero(),
                ]),
                Word([
                    local.untrusted_memory[1][0].into(),
                    local.untrusted_memory[1][1].into(),
                    local.untrusted_memory[1][2].into(),
                    AB::Expr::zero(),
                ]),
                local.addr_range_check[1],
                local.is_real.into(),
            ),
        );
        builder.when(local.is_real).assert_one(local.addr_range_check[1].u16_compare_operation.bit);

        // Constrain address decomposition - addr[0] should equal addr_12_bits + addr_4_bits * 4096
        builder.when(local.is_real).assert_eq(
            local.addr[0],
            local.addr_12_bits + local.addr_4_bits * AB::Expr::from_canonical_u32(4096),
        );

        // Range check addr_4_bits and addr_12_bits using byte interactions
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            local.addr_4_bits.into(),
            AB::Expr::from_canonical_u32(4), // log₂(16) = 4
            AB::Expr::zero(),
            local.is_real,
        );

        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            local.addr_12_bits.into(),
            AB::Expr::from_canonical_u32(12), // log₂(4096) = 12
            AB::Expr::zero(),
            local.is_real,
        );

        // Address must be page-aligned (addr_12_bits should be 0 since PAGE_SIZE = 4096)
        builder.when(local.is_real).assert_zero(local.addr_12_bits);

        // Constrain protection flag decomposition
        builder.assert_bool(local.prot_read);
        builder.assert_bool(local.prot_write);
        builder.assert_bool(local.prot_exec);

        // Create expected bitmap from individual flag bits
        let expected_prot = local.prot_read * AB::Expr::from_canonical_u8(PROT_READ)
            + local.prot_write * AB::Expr::from_canonical_u8(PROT_WRITE)
            + local.prot_exec * AB::Expr::from_canonical_u8(PROT_EXEC);

        // Ensure the reconstructed prot matches the original
        builder.when(local.is_real).assert_eq(local.prot, expected_prot.clone());

        // Receive the syscall interaction
        builder.receive_syscall(
            local.clk_high,
            local.clk_low,
            AB::F::from_canonical_u32(SyscallCode::MPROTECT.syscall_id()),
            AB::Expr::zero(),
            local.addr.map(Into::into),
            [local.prot.into(), AB::Expr::zero(), AB::Expr::zero()],
            local.is_real,
            InteractionScope::Local,
        );

        // Update page protection using the write function
        builder.eval_page_prot_access_write(
            local.clk_high,
            local.clk_low,
            &[local.addr_4_bits, local.addr[1], local.addr[2]],
            local.page_prot_access,
            expected_prot,
            local.is_real,
        );
    }
}
