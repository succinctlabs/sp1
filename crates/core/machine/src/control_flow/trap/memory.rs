use crate::{
    adapter::{
        register::i_type::{ITypeReader, ITypeReaderImmutable, ITypeReaderImmutableInput},
        state::{CPUState, CPUStateInput},
    },
    air::{SP1CoreAirBuilder, SP1Operation},
    eval_untrusted_program,
    operations::{AddrAddOperation, AddrAddOperationInput, PageProtOperation, TrapOperation},
    utils::next_multiple_of_32,
    UserModeReaderCols,
};
use hashbrown::HashMap;
use itertools::Itertools;
use rayon::iter::{ParallelBridge, ParallelIterator};
use rrs_lib::instruction_formats::{OPCODE_LOAD, OPCODE_STORE};
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, MemoryAccessPosition, TrapMemInstrEvent},
    ByteOpcode, ExecutionRecord, Opcode, Program, CLK_INC,
};
use sp1_derive::AlignedBorrow;
#[cfg(feature = "mprotect")]
use sp1_hypercube::addr_to_limbs;
use sp1_hypercube::air::MachineAir;
use sp1_primitives::consts::{PROT_FAILURE_READ, PROT_FAILURE_WRITE, PROT_READ, PROT_WRITE};
use std::borrow::{Borrow, BorrowMut};
use std::mem::{size_of, MaybeUninit};

/// The number of main trace columns for `TrapMemChip`.
pub const NUM_TRAP_MEM_COLS: usize = size_of::<TrapMemColumns<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct TrapMemColumns<T> {
    /// The current shard, timestamp, program counter of the CPU.
    pub state: CPUState<T>,

    /// The adapter to read program and register information.
    pub adapter: ITypeReader<T>,

    /// Instance of `AddOperation` for addr.
    pub addr_operation: AddrAddOperation<T>,

    /// The operation to get the page permission.
    pub page_prot_operation: PageProtOperation<T>,

    /// The operation to handle the trap.
    pub trap_operation: TrapOperation<T>,

    /// Addresses for the trap context. Should be removed after GKR supports public values.
    pub addresses: [[T; 3]; 3],

    /// Whether this is a load byte instruction.
    pub is_lb: T,

    /// Whether this is a load byte unsigned instruction.
    pub is_lbu: T,

    /// Whether this is a load half instruction.
    pub is_lh: T,

    /// Whether this is a load half unsigned instruction.
    pub is_lhu: T,

    /// Whether this is a load word instruction.
    pub is_lw: T,

    /// Whether this is a load word unsigned instruction.
    pub is_lwu: T,

    /// Whether this is a load double word instruction.
    pub is_ld: T,

    /// Whether this is a store byte instruction.
    pub is_sb: T,

    /// Whether this is a store half instruction.
    pub is_sh: T,

    /// Whether this is a store word instruction.
    pub is_sw: T,

    /// Whether this is a store double instruction.
    pub is_sd: T,

    /// Whether this is an untrusted instruction or not.
    pub user_mode_reader_cols: UserModeReaderCols<T>,
}

#[derive(Default)]
pub struct TrapMemChip;

impl<F> BaseAir<F> for TrapMemChip {
    fn width(&self) -> usize {
        NUM_TRAP_MEM_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for TrapMemChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "TrapMem"
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = next_multiple_of_32(
            input.trap_load_store_events.len(),
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
        let chunk_size = std::cmp::max((input.trap_load_store_events.len()) / num_cpus::get(), 1);
        let padded_nb_rows = <TrapMemChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let width = <TrapMemChip as BaseAir<F>>::width(self);
        let num_event_rows = input.trap_load_store_events.len();

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
                    let cols: &mut TrapMemColumns<F> = row.borrow_mut();

                    if idx < input.trap_load_store_events.len() {
                        let event = &input.trap_load_store_events[idx];
                        cols.state.populate(&mut blu, event.0.clk, event.0.pc);
                        cols.adapter.populate(&mut blu, event.1);
                        #[cfg(feature = "mprotect")]
                        for i in 0..3 {
                            cols.addresses[i] = addr_to_limbs(input.public_values.trap_context[i]);
                        }
                        cols.user_mode_reader_cols.is_trusted = F::from_bool(!event.1.is_untrusted);
                        self.event_to_row(&event.0, cols, &mut blu);
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
            !shard.trap_load_store_events.is_empty()
        }
    }
}

impl TrapMemChip {
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &TrapMemInstrEvent,
        cols: &mut TrapMemColumns<F>,
        blu: &mut impl ByteRecord,
    ) {
        let addr = cols.addr_operation.populate(blu, event.b, event.c);
        cols.page_prot_operation.populate(blu, addr, event.clk + 1, &event.page_prot_access);
        cols.trap_operation.populate(blu, event.trap_result);
        let perm = event.page_prot_access.page_prot;
        cols.is_lb = F::from_bool(event.opcode == Opcode::LB);
        cols.is_lbu = F::from_bool(event.opcode == Opcode::LBU);
        cols.is_lh = F::from_bool(event.opcode == Opcode::LH);
        cols.is_lhu = F::from_bool(event.opcode == Opcode::LHU);
        cols.is_lw = F::from_bool(event.opcode == Opcode::LW);
        cols.is_lwu = F::from_bool(event.opcode == Opcode::LWU);
        cols.is_ld = F::from_bool(event.opcode == Opcode::LD);
        cols.is_sb = F::from_bool(event.opcode == Opcode::SB);
        cols.is_sh = F::from_bool(event.opcode == Opcode::SH);
        cols.is_sw = F::from_bool(event.opcode == Opcode::SW);
        cols.is_sd = F::from_bool(event.opcode == Opcode::SD);

        let target_code = if event.opcode.base_opcode().0 == OPCODE_LOAD {
            PROT_READ
        } else {
            assert_eq!(event.opcode.base_opcode().0, OPCODE_STORE);
            PROT_WRITE
        };

        blu.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::AND,
            a: 0,
            b: perm,
            c: target_code,
        });
    }
}
impl<AB> Air<AB> for TrapMemChip
where
    AB: SP1CoreAirBuilder,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &TrapMemColumns<AB::Var> = (*local).borrow();

        let clk_high = local.state.clk_high::<AB>();
        let clk_low = local.state.clk_low::<AB>();

        let opcode = AB::Expr::from_canonical_u32(Opcode::LB as u32) * local.is_lb
            + AB::Expr::from_canonical_u32(Opcode::LBU as u32) * local.is_lbu
            + AB::Expr::from_canonical_u32(Opcode::LH as u32) * local.is_lh
            + AB::Expr::from_canonical_u32(Opcode::LHU as u32) * local.is_lhu
            + AB::Expr::from_canonical_u32(Opcode::LW as u32) * local.is_lw
            + AB::Expr::from_canonical_u32(Opcode::LWU as u32) * local.is_lwu
            + AB::Expr::from_canonical_u32(Opcode::LD as u32) * local.is_ld
            + AB::Expr::from_canonical_u32(Opcode::SB as u32) * local.is_sb
            + AB::Expr::from_canonical_u32(Opcode::SH as u32) * local.is_sh
            + AB::Expr::from_canonical_u32(Opcode::SW as u32) * local.is_sw
            + AB::Expr::from_canonical_u32(Opcode::SD as u32) * local.is_sd;

        // Compute instruction field constants
        let funct3 = local.is_lb * AB::Expr::from_canonical_u8(Opcode::LB.funct3().unwrap())
            + local.is_lbu * AB::Expr::from_canonical_u8(Opcode::LBU.funct3().unwrap())
            + local.is_lh * AB::Expr::from_canonical_u8(Opcode::LH.funct3().unwrap())
            + local.is_lhu * AB::Expr::from_canonical_u8(Opcode::LHU.funct3().unwrap())
            + local.is_lw * AB::Expr::from_canonical_u8(Opcode::LW.funct3().unwrap())
            + local.is_lwu * AB::Expr::from_canonical_u8(Opcode::LWU.funct3().unwrap())
            + local.is_ld * AB::Expr::from_canonical_u8(Opcode::LD.funct3().unwrap())
            + local.is_sb * AB::Expr::from_canonical_u8(Opcode::SB.funct3().unwrap())
            + local.is_sh * AB::Expr::from_canonical_u8(Opcode::SH.funct3().unwrap())
            + local.is_sw * AB::Expr::from_canonical_u8(Opcode::SW.funct3().unwrap())
            + local.is_sd * AB::Expr::from_canonical_u8(Opcode::SD.funct3().unwrap());

        let funct7 = local.is_lb * AB::Expr::from_canonical_u8(Opcode::LB.funct7().unwrap_or(0))
            + local.is_lbu * AB::Expr::from_canonical_u8(Opcode::LBU.funct7().unwrap_or(0))
            + local.is_lh * AB::Expr::from_canonical_u8(Opcode::LH.funct7().unwrap_or(0))
            + local.is_lhu * AB::Expr::from_canonical_u8(Opcode::LHU.funct7().unwrap_or(0))
            + local.is_lw * AB::Expr::from_canonical_u8(Opcode::LW.funct7().unwrap_or(0))
            + local.is_lwu * AB::Expr::from_canonical_u8(Opcode::LWU.funct7().unwrap_or(0))
            + local.is_ld * AB::Expr::from_canonical_u8(Opcode::LD.funct7().unwrap_or(0))
            + local.is_sb * AB::Expr::from_canonical_u8(Opcode::SB.funct7().unwrap_or(0))
            + local.is_sh * AB::Expr::from_canonical_u8(Opcode::SH.funct7().unwrap_or(0))
            + local.is_sw * AB::Expr::from_canonical_u8(Opcode::SW.funct7().unwrap_or(0))
            + local.is_sd * AB::Expr::from_canonical_u8(Opcode::SD.funct7().unwrap_or(0));

        let base_opcode = local.is_lb * AB::Expr::from_canonical_u32(Opcode::LB.base_opcode().0)
            + local.is_lbu * AB::Expr::from_canonical_u32(Opcode::LBU.base_opcode().0)
            + local.is_lh * AB::Expr::from_canonical_u32(Opcode::LH.base_opcode().0)
            + local.is_lhu * AB::Expr::from_canonical_u32(Opcode::LHU.base_opcode().0)
            + local.is_lw * AB::Expr::from_canonical_u32(Opcode::LW.base_opcode().0)
            + local.is_lwu * AB::Expr::from_canonical_u32(Opcode::LWU.base_opcode().0)
            + local.is_ld * AB::Expr::from_canonical_u32(Opcode::LD.base_opcode().0)
            + local.is_sb * AB::Expr::from_canonical_u32(Opcode::SB.base_opcode().0)
            + local.is_sh * AB::Expr::from_canonical_u32(Opcode::SH.base_opcode().0)
            + local.is_sw * AB::Expr::from_canonical_u32(Opcode::SW.base_opcode().0)
            + local.is_sd * AB::Expr::from_canonical_u32(Opcode::SD.base_opcode().0);

        let instr_type = local.is_lb
            * AB::Expr::from_canonical_u32(Opcode::LB.instruction_type().0 as u32)
            + local.is_lbu * AB::Expr::from_canonical_u32(Opcode::LBU.instruction_type().0 as u32)
            + local.is_lh * AB::Expr::from_canonical_u32(Opcode::LH.instruction_type().0 as u32)
            + local.is_lhu * AB::Expr::from_canonical_u32(Opcode::LHU.instruction_type().0 as u32)
            + local.is_lw * AB::Expr::from_canonical_u32(Opcode::LW.instruction_type().0 as u32)
            + local.is_lwu * AB::Expr::from_canonical_u32(Opcode::LWU.instruction_type().0 as u32)
            + local.is_ld * AB::Expr::from_canonical_u32(Opcode::LD.instruction_type().0 as u32)
            + local.is_sb * AB::Expr::from_canonical_u32(Opcode::SB.instruction_type().0 as u32)
            + local.is_sh * AB::Expr::from_canonical_u32(Opcode::SH.instruction_type().0 as u32)
            + local.is_sw * AB::Expr::from_canonical_u32(Opcode::SW.instruction_type().0 as u32)
            + local.is_sd * AB::Expr::from_canonical_u32(Opcode::SD.instruction_type().0 as u32);

        let is_load = local.is_lb
            + local.is_lbu
            + local.is_lh
            + local.is_lhu
            + local.is_lw
            + local.is_lwu
            + local.is_ld;
        let is_store = local.is_sb + local.is_sh + local.is_sw + local.is_sd;
        let is_real = is_load.clone() + is_store.clone();

        // Read the currently set page permissions.
        PageProtOperation::<AB::F>::eval(
            builder,
            local.state.clk_high::<AB>(),
            local.state.clk_low::<AB>()
                + AB::Expr::from_canonical_u32(MemoryAccessPosition::Memory as u32),
            &local.addr_operation.value.map(Into::into),
            local.page_prot_operation,
            is_real.clone(),
        );

        builder.assert_bool(local.is_lb);
        builder.assert_bool(local.is_lbu);
        builder.assert_bool(local.is_lh);
        builder.assert_bool(local.is_lhu);
        builder.assert_bool(local.is_lw);
        builder.assert_bool(local.is_lwu);
        builder.assert_bool(local.is_ld);
        builder.assert_bool(local.is_sb);
        builder.assert_bool(local.is_sh);
        builder.assert_bool(local.is_sw);
        builder.assert_bool(local.is_sd);
        builder.assert_bool(is_load.clone());
        builder.assert_bool(is_store.clone());
        builder.assert_bool(is_real.clone());

        #[cfg(not(feature = "mprotect"))]
        builder.assert_zero(is_real.clone());

        // Add the `op_b` and `op_c` result to get the address.
        // Notably, it's not a requirement to find the aligned address.
        <AddrAddOperation<AB::F> as SP1Operation<AB>>::eval(
            builder,
            AddrAddOperationInput::new(
                local.adapter.b().map(Into::into),
                local.adapter.c().map(Into::into),
                local.addr_operation,
                is_real.clone(),
            ),
        );

        // Check the flags with an `OR` lookup.
        builder.send_byte(
            AB::Expr::from_canonical_u8(ByteOpcode::AND as u8),
            AB::Expr::zero(),
            local.page_prot_operation.page_prot_access.prev_prot_bitmap.into(),
            is_load.clone() * AB::Expr::from_canonical_u8(PROT_READ)
                + is_store.clone() * AB::Expr::from_canonical_u8(PROT_WRITE),
            is_real.clone(),
        );

        let next_pc = TrapOperation::<AB::F>::eval(
            builder,
            local.trap_operation,
            local.state.clk_high::<AB>(),
            local.state.clk_low::<AB>(),
            is_load.clone() * AB::Expr::from_canonical_u64(PROT_FAILURE_READ)
                + is_store * AB::Expr::from_canonical_u64(PROT_FAILURE_WRITE),
            local.state.pc.map(Into::into),
            local.addresses,
            is_real.clone(),
        );

        // Constrain the state of the CPU.
        // The `next_pc` is constrained by the AIR.
        // The clock is incremented by `8`.
        <CPUState<AB::F> as SP1Operation<AB>>::eval(
            builder,
            CPUStateInput::new(
                local.state,
                [next_pc[0].into(), next_pc[1].into(), next_pc[2].into()],
                AB::Expr::from_canonical_u32(CLK_INC),
                is_real.clone(),
            ),
        );

        // Constrain the program and register reads.
        // Since there is a trap, `op_a` will be immutable.
        <ITypeReaderImmutable as SP1Operation<AB>>::eval(
            builder,
            ITypeReaderImmutableInput::new(
                clk_high,
                clk_low,
                local.state.pc,
                opcode.clone(),
                local.adapter,
                is_real.clone(),
                local.user_mode_reader_cols.is_trusted.into(),
            ),
        );

        let instruction = local.adapter.instruction::<AB>(opcode.clone());

        eval_untrusted_program(
            builder,
            local.state.pc,
            instruction,
            [instr_type, base_opcode, funct3, funct7],
            [local.state.clk_high::<AB>(), local.state.clk_low::<AB>()],
            is_real.clone(),
            local.user_mode_reader_cols,
        );
    }
}
