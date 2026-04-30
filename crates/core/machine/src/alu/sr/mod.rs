use core::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};
use std::marker::PhantomData;

use hashbrown::HashMap;
use itertools::Itertools;
use slop_air::{Air, AirBuilder, BaseAir};
use slop_algebra::{AbstractField, Field, PrimeField, PrimeField32};
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::{ParallelBridge, ParallelIterator, ParallelSlice};
use sp1_core_executor::{
    events::{AluEvent, ByteLookupEvent, ByteRecord},
    ByteOpcode, ExecutionRecord, Opcode, Program, CLK_INC, PC_INC,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{air::MachineAir, Word};
use sp1_primitives::consts::{u64_to_u16_limbs, WORD_SIZE};
use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::{
    adapter::{
        register::alu_type::{ALUTypeReader, ALUTypeReaderInput},
        state::{CPUState, CPUStateInput},
    },
    air::{SP1CoreAirBuilder, SP1Operation},
    eval_untrusted_program,
    operations::{U16MSBOperation, U16MSBOperationInput},
    utils::next_multiple_of_32,
    SupervisorMode, TrustMode, UserMode,
};

/// The number of main trace columns for `ShiftRightChip` in Supervisor mode.
pub const NUM_SHIFT_RIGHT_COLS_SUPERVISOR: usize = size_of::<ShiftRightCols<u8, SupervisorMode>>();
/// The number of main trace columns for `ShiftRightChip` in User mode.
pub const NUM_SHIFT_RIGHT_COLS_USER: usize = size_of::<ShiftRightCols<u8, UserMode>>();

/// A chip that implements bitwise operations for the opcodes SRL and SRA.
#[derive(Default)]
pub struct ShiftRightChip<M: TrustMode> {
    pub _phantom: PhantomData<M>,
}

/// The column layout for the chip.
#[derive(AlignedBorrow, StructReflection, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ShiftRightCols<T, M: TrustMode> {
    /// The current shard, timestamp, program counter of the CPU.
    pub state: CPUState<T>,

    /// The adapter to read program and register information.
    pub adapter: ALUTypeReader<T>,

    /// The output operand.
    pub a: Word<T>,

    /// The most significant bit of `b`.
    pub b_msb: U16MSBOperation<T>,

    /// The most significant byte of the result of SRLW/SRAW/SRLIW/SRAIW
    pub srw_msb: U16MSBOperation<T>,

    /// The bottom 8 bits of `c`.
    pub c_bits: [T; 6],

    /// SRA msb * v0123
    pub sra_msb_v0123: T,

    /// v0123
    pub v_0123: T,

    /// v012
    pub v_012: T,

    /// v01
    pub v_01: T,

    /// The lower bits of each limb.
    pub lower_limb: Word<T>,

    /// The higher bits of each limb.
    pub higher_limb: Word<T>,

    /// The result of the byte-shift.
    pub limb_result: [T; WORD_SIZE],

    /// The shift amount.
    pub shift_u16: [T; 4],

    /// If the opcode is SRL.
    pub is_srl: T,

    /// If the opcode is SRA.
    pub is_sra: T,

    /// If the opcode is SRLW.
    pub is_srlw: T,

    /// If the opcode is SRAW.
    pub is_sraw: T,

    /// If the opcode is W and immediate.
    pub is_w_imm: T,

    /// Adapter columns for trust mode specific data.
    pub adapter_cols: M::AdapterCols<T>,
}

impl<F: PrimeField32, M: TrustMode> MachineAir<F> for ShiftRightChip<M> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        if M::IS_TRUSTED {
            "ShiftRight"
        } else {
            "ShiftRightUser"
        }
    }

    fn column_names(&self) -> Vec<String> {
        ShiftRightCols::<F, M>::struct_reflection().unwrap()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return Some(0);
        }
        let nb_rows = next_multiple_of_32(
            input.shift_right_events.len(),
            input.fixed_log2_rows::<F, _>(self),
        );
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

        // Generate the trace rows for each event.
        let nb_rows = input.shift_right_events.len();
        let padded_nb_rows = <ShiftRightChip<M> as MachineAir<F>>::num_rows(self, input).unwrap();
        let chunk_size = std::cmp::max((nb_rows + 1) / num_cpus::get(), 1);
        let width = <ShiftRightChip<M> as BaseAir<F>>::width(self);

        unsafe {
            let padding_start = nb_rows * width;
            let padding_size = (padded_nb_rows - nb_rows) * width;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, padded_nb_rows * width) };

        let padded_row_template = {
            let mut row = vec![F::zero(); width];
            let cols: &mut ShiftRightCols<F, M> = row.as_mut_slice().borrow_mut();
            cols.v_01 = F::from_canonical_u32(16);
            cols.v_012 = F::from_canonical_u32(256);
            cols.v_0123 = F::from_canonical_u32(65536);
            row
        };

        values.chunks_mut(chunk_size * width).enumerate().par_bridge().for_each(|(i, rows)| {
            rows.chunks_mut(width).enumerate().for_each(|(j, row)| {
                let idx = i * chunk_size + j;
                let cols: &mut ShiftRightCols<F, M> = row.borrow_mut();

                if idx < nb_rows {
                    let mut byte_lookup_events = Vec::new();
                    let event = &input.shift_right_events[idx];
                    cols.adapter.populate(&mut byte_lookup_events, event.1);
                    self.event_to_row(&event.0, cols, &mut byte_lookup_events);
                    cols.state.populate(&mut byte_lookup_events, event.0.clk, event.0.pc);
                    cols.is_w_imm = F::from_bool(
                        (event.0.opcode == Opcode::SRLW || event.0.opcode == Opcode::SRAW)
                            && event.1.is_imm,
                    );
                    if !M::IS_TRUSTED {
                        let cols: &mut ShiftRightCols<F, UserMode> = row.borrow_mut();
                        cols.adapter_cols.is_trusted = F::from_bool(!event.1.is_untrusted);
                    }
                } else {
                    row.copy_from_slice(&padded_row_template);
                }
            });
        });
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return;
        }

        let chunk_size = std::cmp::max(input.shift_right_events.len() / num_cpus::get(), 1);
        let width = <ShiftRightChip<M> as BaseAir<F>>::width(self);

        let blu_batches = input
            .shift_right_events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = vec![F::zero(); width];
                    let cols: &mut ShiftRightCols<F, M> = row.as_mut_slice().borrow_mut();
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
            !shard.shift_right_events.is_empty()
                && (M::IS_TRUSTED != shard.program.enable_untrusted_programs)
        }
    }
}

impl<M: TrustMode> ShiftRightChip<M> {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField>(
        &self,
        event: &AluEvent,
        cols: &mut ShiftRightCols<F, M>,
        blu: &mut impl ByteRecord,
    ) {
        let mut b = u64_to_u16_limbs(event.b);
        let c = u64_to_u16_limbs(event.c)[0];
        cols.a = Word::from(event.a);

        cols.is_srl = F::from_bool(event.opcode == Opcode::SRL);
        cols.is_sra = F::from_bool(event.opcode == Opcode::SRA);
        cols.is_srlw = F::from_bool(event.opcode == Opcode::SRLW);
        cols.is_sraw = F::from_bool(event.opcode == Opcode::SRAW);

        for i in 0..6 {
            cols.c_bits[i] = F::from_canonical_u16((c >> i) & 1);
        }
        blu.add_bit_range_check(c >> 6, 10);

        cols.v_01 = F::from_canonical_u32(1 << (4 - (c & 3)));
        cols.v_012 = F::from_canonical_u32(1 << (8 - (c & 7)));
        cols.v_0123 = F::from_canonical_u32(1 << (16 - (c & 15)));

        if event.opcode == Opcode::SRA {
            cols.b_msb.populate_msb(blu, b[3]);
        } else if event.opcode == Opcode::SRAW {
            cols.b_msb.populate_msb(blu, b[1]);
        } else {
            cols.b_msb.msb = F::zero();
        }
        cols.sra_msb_v0123 = cols.b_msb.msb * cols.v_0123;

        let is_word = event.opcode == Opcode::SRLW || event.opcode == Opcode::SRAW;
        let not_word = !is_word;

        if is_word {
            b[2] = 0;
            b[3] = 0;
            cols.srw_msb.populate_msb(blu, u64_to_u16_limbs(event.a)[1]);
        } else {
            cols.srw_msb.msb = F::zero();
        }

        let bit_shift = (c & 0xF) as u8;
        for i in 0..WORD_SIZE {
            let limb = b[i] as u32;
            let lower_limb = (limb & ((1 << bit_shift) - 1)) as u16;
            let higher_limb = (limb >> bit_shift) as u16;
            cols.lower_limb[i] = F::from_canonical_u16(lower_limb);
            cols.higher_limb[i] = F::from_canonical_u16(higher_limb);
            blu.add_bit_range_check(lower_limb, bit_shift);
            blu.add_bit_range_check(higher_limb, 16 - bit_shift);
        }

        for i in 0..WORD_SIZE {
            cols.limb_result[i] = cols.higher_limb[i];
            if i != WORD_SIZE - 1 {
                cols.limb_result[i] +=
                    cols.lower_limb[i + 1] * F::from_canonical_u32(1 << (16 - bit_shift));
            }
        }

        let shift_amount = ((c >> 4) & 1) + 2 * ((c >> 5) & 1) * (not_word as u16);

        let mut shift = [0u16; 4];
        for i in 0..4 {
            if i == shift_amount as usize {
                shift[i] = 1;
            }
        }

        cols.shift_u16 = shift.map(|x| F::from_canonical_u16(x));
    }
}

impl<F, M: TrustMode> BaseAir<F> for ShiftRightChip<M> {
    fn width(&self) -> usize {
        if M::IS_TRUSTED {
            NUM_SHIFT_RIGHT_COLS_SUPERVISOR
        } else {
            NUM_SHIFT_RIGHT_COLS_USER
        }
    }
}

impl<AB, M> Air<AB> for ShiftRightChip<M>
where
    AB: SP1CoreAirBuilder,
    M: TrustMode,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &ShiftRightCols<AB::Var, M> = (*local).borrow();

        let is_real = local.is_srl + local.is_sra + local.is_srlw + local.is_sraw;

        // SAFETY: All selectors `is_srl`, `is_sra`, `is_srlw`, `is_sraw` are checked to be boolean.
        // Each "real" row has exactly one selector turned on, as `is_real`, their sum, is boolean.
        // All interactions are done with multiplicity `is_real`.
        // Therefore, the `opcode` matches the corresponding opcode.

        // Check that the operation flags are boolean.
        builder.assert_bool(local.is_srl);
        builder.assert_bool(local.is_sra);
        builder.assert_bool(local.is_srlw);
        builder.assert_bool(local.is_sraw);
        builder.assert_bool(is_real.clone());

        let one = AB::Expr::one();

        let is_word = local.is_srlw + local.is_sraw;
        let not_word = local.is_srl + local.is_sra;

        let opcode = local.is_srl * AB::F::from_canonical_u32(Opcode::SRL as u32)
            + local.is_sra * AB::F::from_canonical_u32(Opcode::SRA as u32)
            + local.is_srlw * AB::F::from_canonical_u32(Opcode::SRLW as u32)
            + local.is_sraw * AB::F::from_canonical_u32(Opcode::SRAW as u32);

        // Compute instruction field constants for each opcode
        let funct3 = local.is_srl * AB::Expr::from_canonical_u8(Opcode::SRL.funct3().unwrap())
            + local.is_sra * AB::Expr::from_canonical_u8(Opcode::SRA.funct3().unwrap())
            + local.is_srlw * AB::Expr::from_canonical_u8(Opcode::SRLW.funct3().unwrap())
            + local.is_sraw * AB::Expr::from_canonical_u8(Opcode::SRAW.funct3().unwrap());
        let funct7 = local.is_srl * AB::Expr::from_canonical_u8(Opcode::SRL.funct7().unwrap_or(0))
            + local.is_sra * AB::Expr::from_canonical_u8(Opcode::SRA.funct7().unwrap())
            + local.is_srlw * AB::Expr::from_canonical_u8(Opcode::SRLW.funct7().unwrap_or(0))
            + local.is_sraw * AB::Expr::from_canonical_u8(Opcode::SRAW.funct7().unwrap());

        let (srl_base, srl_imm) = Opcode::SRL.base_opcode();
        let srl_imm = srl_imm.expect("SRL immediate opcode not found");
        let (sra_base, sra_imm) = Opcode::SRA.base_opcode();
        let sra_imm = sra_imm.expect("SRA immediate opcode not found");
        let (srlw_base, srlw_imm) = Opcode::SRLW.base_opcode();
        let srlw_imm = srlw_imm.expect("SRLW immediate opcode not found");
        let (sraw_base, sraw_imm) = Opcode::SRAW.base_opcode();
        let sraw_imm = sraw_imm.expect("SRAW immediate opcode not found");

        let imm_base_difference = srl_base.checked_sub(srl_imm).unwrap();
        assert_eq!(imm_base_difference, sra_base.checked_sub(sra_imm).unwrap());
        assert_eq!(imm_base_difference, srlw_base.checked_sub(srlw_imm).unwrap());
        assert_eq!(imm_base_difference, sraw_base.checked_sub(sraw_imm).unwrap());

        let srl_base_expr = AB::Expr::from_canonical_u32(srl_base);
        let sra_base_expr = AB::Expr::from_canonical_u32(sra_base);
        let srlw_base_expr = AB::Expr::from_canonical_u32(srlw_base);
        let sraw_base_expr = AB::Expr::from_canonical_u32(sraw_base);

        let calculated_base_opcode = local.is_srl * srl_base_expr
            + local.is_sra * sra_base_expr
            + local.is_srlw * srlw_base_expr
            + local.is_sraw * sraw_base_expr
            - AB::Expr::from_canonical_u32(imm_base_difference) * local.adapter.imm_c;

        let srl_instr_type = Opcode::SRL.instruction_type().0 as u32;
        let srl_instr_type_imm =
            Opcode::SRL.instruction_type().1.expect("SRL immediate instruction type not found")
                as u32;
        let sra_instr_type = Opcode::SRA.instruction_type().0 as u32;
        let sra_instr_type_imm =
            Opcode::SRA.instruction_type().1.expect("SRA immediate instruction type not found")
                as u32;
        let srlw_instr_type = Opcode::SRLW.instruction_type().0 as u32;
        let srlw_instr_type_imm =
            Opcode::SRLW.instruction_type().1.expect("SRLW immediate instruction type not found")
                as u32;
        let sraw_instr_type = Opcode::SRAW.instruction_type().0 as u32;
        let sraw_instr_type_imm =
            Opcode::SRAW.instruction_type().1.expect("SRAW immediate instruction type not found")
                as u32;

        let instr_type_difference = srl_instr_type.checked_sub(srl_instr_type_imm).unwrap();
        let sra_instr_type_difference = sra_instr_type.checked_sub(sra_instr_type_imm).unwrap();
        let srlw_instr_type_difference = srlw_instr_type.checked_sub(srlw_instr_type_imm).unwrap();
        let sraw_instr_type_difference = sraw_instr_type.checked_sub(sraw_instr_type_imm).unwrap();
        let w_instr_imm_adjustment = srl_instr_type_imm.checked_sub(srlw_instr_type_imm).unwrap();

        assert_eq!(instr_type_difference, sra_instr_type_difference);
        assert_eq!(srlw_instr_type_difference, instr_type_difference + w_instr_imm_adjustment);
        assert_eq!(sraw_instr_type_difference, instr_type_difference + w_instr_imm_adjustment);

        builder.assert_eq(local.is_w_imm, (local.is_srlw + local.is_sraw) * local.adapter.imm_c);

        let calculated_instr_type = local.is_srl * AB::Expr::from_canonical_u32(srl_instr_type)
            + local.is_sra * AB::Expr::from_canonical_u32(sra_instr_type)
            + local.is_srlw * AB::Expr::from_canonical_u32(srlw_instr_type)
            + local.is_sraw * AB::Expr::from_canonical_u32(sraw_instr_type)
            - (AB::Expr::from_canonical_u32(instr_type_difference) * local.adapter.imm_c
                + AB::Expr::from_canonical_u32(w_instr_imm_adjustment) * local.is_w_imm);

        // Check that `local.c_bits` are the 6 lowest bits of `c`.
        for i in 0..6 {
            builder.assert_bool(local.c_bits[i]);
        }
        let mut c_lower_bits = AB::Expr::zero();
        let mut bit_shift = AB::Expr::zero();
        for i in 0..6 {
            c_lower_bits = c_lower_bits + local.c_bits[i] * AB::F::from_canonical_u32(1 << i);
            if i == 3 {
                bit_shift = c_lower_bits.clone();
            }
        }
        let inverse_64 = AB::F::from_canonical_u32(64).inverse();
        builder.send_byte(
            AB::F::from_canonical_u32(ByteOpcode::Range as u32),
            (local.adapter.c()[0] - c_lower_bits) * inverse_64,
            AB::Expr::from_canonical_u32(10),
            AB::Expr::zero(),
            is_real.clone(),
        );

        // Check that `shift_u16` represents the boolean flag for the u16 limb shifts.
        for i in 0..WORD_SIZE {
            builder.when(local.shift_u16[i]).assert_eq(
                local.c_bits[4] + local.c_bits[5] * AB::F::from_canonical_u32(2) * not_word.clone(),
                AB::Expr::from_canonical_u32(i as u32),
            );
            builder.assert_bool(local.shift_u16[i]);
        }

        builder.when(is_real.clone()).assert_eq(
            local.shift_u16[0] + local.shift_u16[1] + local.shift_u16[2] + local.shift_u16[3],
            AB::Expr::from_canonical_u32(1),
        );

        let two = AB::F::from_canonical_u32(2);
        let three = AB::F::from_canonical_u32(3);
        let fifteen = AB::F::from_canonical_u32(15);
        let two_fifty_five = AB::F::from_canonical_u32(255);
        builder.assert_eq(
            local.v_01,
            (((one.clone() - local.c_bits[0]) + one.clone()) * two)
                * ((one.clone() - local.c_bits[1]) * three + one.clone()),
        );
        builder.assert_eq(
            local.v_012,
            local.v_01 * ((one.clone() - local.c_bits[2]) * fifteen + one.clone()),
        );
        builder.assert_eq(
            local.v_0123,
            local.v_012 * ((one.clone() - local.c_bits[3]) * two_fifty_five + one.clone()),
        );

        for i in 0..WORD_SIZE {
            let limb = local.adapter.b()[i];
            // Check that `lower_limb < 2^(bit_shift)`
            builder.send_byte(
                AB::F::from_canonical_u32(ByteOpcode::Range as u32),
                local.lower_limb[i],
                bit_shift.clone(),
                AB::Expr::zero(),
                is_real.clone(),
            );
            // Check that `higher_limb < 2^(16 - bit_shift)`
            builder.send_byte(
                AB::F::from_canonical_u32(ByteOpcode::Range as u32),
                local.higher_limb[i],
                AB::Expr::from_canonical_u32(16) - bit_shift.clone(),
                AB::Expr::zero(),
                is_real.clone(),
            );
            // Check that `limb == higher_limb * 2^bit_shift + lower_limb`
            // Multiply `2^(16 - bit_shift)` to the equation to avoid populating `2^(bit_shift)`.
            // This is possible, since `2^(16 - bit_shift)` is not zero.
            // When it's a word operation, use `0` in the place of the limb for the top two limbs.
            if i < WORD_SIZE / 2 {
                builder.assert_eq(
                    limb * local.v_0123,
                    local.higher_limb[i] * AB::Expr::from_canonical_u32(1 << 16)
                        + local.lower_limb[i] * local.v_0123,
                );
            } else {
                builder.assert_eq(
                    limb * local.v_0123 * not_word.clone(),
                    local.higher_limb[i] * AB::Expr::from_canonical_u32(1 << 16)
                        + local.lower_limb[i] * local.v_0123,
                );
            }
        }

        // Compute the limb result based on the lower limbs and higher limbs.
        for i in 0..WORD_SIZE {
            let mut limb_result = local.higher_limb[i].into();
            if i != WORD_SIZE - 1 {
                limb_result = limb_result.clone() + local.lower_limb[i + 1] * local.v_0123;
            }
            builder.assert_eq(local.limb_result[i], limb_result);
        }

        // TODO(gzgz): they don't need casts because `U16MSBOperation` doesn't have a `eval`
        // function.
        <U16MSBOperation<AB::F> as SP1Operation<AB>>::eval(
            builder,
            U16MSBOperationInput::<AB>::new(
                local.adapter.b().0[3].into(),
                local.b_msb,
                local.is_sra.into(),
            ),
        );
        <U16MSBOperation<AB::F> as SP1Operation<AB>>::eval(
            builder,
            U16MSBOperationInput::<AB>::new(
                local.adapter.b().0[1].into(),
                local.b_msb,
                local.is_sraw.into(),
            ),
        );
        builder.when(local.is_srl + local.is_srlw).assert_zero(local.b_msb.msb);
        builder.assert_eq(local.sra_msb_v0123, local.b_msb.msb * local.v_0123);

        <U16MSBOperation<AB::F> as SP1Operation<AB>>::eval(
            builder,
            U16MSBOperationInput::<AB>::new(local.a.0[1].into(), local.srw_msb, is_word.clone()),
        );
        builder.when_not(is_word.clone()).assert_zero(local.srw_msb.msb);

        let base = AB::F::from_canonical_u32(1 << 16);
        let base_minus_one = AB::F::from_canonical_u16(u16::MAX);

        // Perform the limb shift for the case where the opcode is SRL/SRA.
        for i in 0..WORD_SIZE {
            for j in 0..(WORD_SIZE - 1 - i) {
                builder
                    .when(not_word.clone())
                    .when(local.shift_u16[i])
                    .assert_eq(local.a[j], local.limb_result[i + j]);
            }

            builder.when(not_word.clone()).when(local.shift_u16[i]).assert_eq(
                local.a[WORD_SIZE - 1 - i],
                local.limb_result[WORD_SIZE - 1] + (local.b_msb.msb * base - local.sra_msb_v0123),
            );

            for j in (WORD_SIZE - i)..WORD_SIZE {
                builder
                    .when(not_word.clone())
                    .when(local.shift_u16[i])
                    .assert_eq(local.a[j], local.b_msb.msb * base_minus_one);
            }
        }

        // Perform the limb shift for the case where the opcode is SRLW/SRAW.
        builder
            .when(is_word.clone())
            .when(local.shift_u16[0])
            .assert_eq(local.a[0], local.limb_result[0]);
        builder.when(is_word.clone()).when(local.shift_u16[0]).assert_eq(
            local.a[1],
            local.limb_result[1] + (local.b_msb.msb * base - local.sra_msb_v0123),
        );
        builder.when(is_word.clone()).when(local.shift_u16[1]).assert_eq(
            local.a[0],
            local.limb_result[1] + (local.b_msb.msb * base - local.sra_msb_v0123),
        );
        builder
            .when(is_word.clone())
            .when(local.shift_u16[1])
            .assert_eq(local.a[1], local.b_msb.msb * base_minus_one);

        for i in WORD_SIZE / 2..WORD_SIZE {
            builder.when(is_word.clone()).assert_eq(local.a[i], local.srw_msb.msb * base_minus_one);
        }

        // Constrain the CPU state.
        // The program counter and timestamp increment by `4` and `8`.
        <CPUState<AB::F> as SP1Operation<AB>>::eval(
            builder,
            CPUStateInput {
                cols: local.state,
                next_pc: [
                    local.state.pc[0] + AB::F::from_canonical_u32(PC_INC),
                    local.state.pc[1].into(),
                    local.state.pc[2].into(),
                ],
                clk_increment: AB::Expr::from_canonical_u32(CLK_INC),
                is_real: is_real.clone(),
            },
        );

        let mut is_trusted: AB::Expr = is_real.clone();

        #[cfg(feature = "mprotect")]
        builder.assert_eq(
            builder.extract_public_values().is_untrusted_programs_enabled,
            AB::Expr::from_bool(!M::IS_TRUSTED),
        );

        if !M::IS_TRUSTED {
            let local = main.row_slice(0);
            let local: &ShiftRightCols<AB::Var, UserMode> = (*local).borrow();

            let instruction = local.adapter.instruction::<AB>(opcode.clone());

            #[cfg(not(feature = "mprotect"))]
            builder.assert_zero(is_real.clone());

            eval_untrusted_program(
                builder,
                local.state.pc,
                instruction,
                [calculated_instr_type, calculated_base_opcode, funct3, funct7],
                [local.state.clk_high::<AB>(), local.state.clk_low::<AB>()],
                is_real.clone(),
                local.adapter_cols,
            );

            is_trusted = local.adapter_cols.is_trusted.into();
        }

        // This chip is for the case `rd != x0`.
        builder.assert_zero(local.adapter.op_a_0);

        // Constrain the program and register reads.
        let alu_reader_input = ALUTypeReaderInput::<AB, AB::Expr>::new(
            local.state.clk_high::<AB>(),
            local.state.clk_low::<AB>(),
            local.state.pc,
            opcode,
            local.a.map(|x| x.into()),
            local.adapter,
            is_real,
            is_trusted,
        );
        ALUTypeReader::<AB::F>::eval(builder, alu_reader_input);
    }
}

// #[cfg(test)]
// mod tests {
//     #![allow(clippy::print_stdout)]

//     use std::borrow::BorrowMut;

//     use crate::{
//         alu::ShiftRightCols,
//         io::SP1Stdin,
//         riscv::RiscvAir,
//         utils::{run_malicious_test, run_test_machine, setup_test_machine},
//     };
//     use sp1_primitives::SP1Field;
//     use slop_matrix::dense::RowMajorMatrix;
//     use rand::{thread_rng, Rng};
//     use sp1_core_executor::{
//         events::{AluEvent, MemoryRecordEnum},
//         ExecutionRecord, Instruction, Opcode, Program,
//     };
//     use sp1_hypercube::{
//         air::{MachineAir, SP1_PROOF_NUM_PV_ELTS},
//         koala_bear_poseidon2::SP1InnerPcs,
//         chip_name, Chip, CpuProver, MachineProver, StarkMachine, Val,
//     };

//     use super::ShiftRightChip;

//     #[test]
//     fn generate_trace() {
//         let mut shard = ExecutionRecord::default();
//         shard.shift_right_events = vec![AluEvent::new(0, Opcode::SRL, 6, 12, 1, false)];
//         let chip = ShiftRightChip::default();
//         let trace: RowMajorMatrix<SP1Field> =
//             chip.generate_trace(&shard, &mut ExecutionRecord::default());
//         println!("{:?}", trace.values)
//     }

//     #[test]
//     fn prove_koalabear() {
//         let shifts = vec![
//             (Opcode::SRL, 0xffff8000, 0xffff8000, 0),
//             (Opcode::SRL, 0x7fffc000, 0xffff8000, 1),
//             (Opcode::SRL, 0x01ffff00, 0xffff8000, 7),
//             (Opcode::SRL, 0x0003fffe, 0xffff8000, 14),
//             (Opcode::SRL, 0x0001ffff, 0xffff8001, 15),
//             (Opcode::SRL, 0xffffffff, 0xffffffff, 0),
//             (Opcode::SRL, 0x7fffffff, 0xffffffff, 1),
//             (Opcode::SRL, 0x01ffffff, 0xffffffff, 7),
//             (Opcode::SRL, 0x0003ffff, 0xffffffff, 14),
//             (Opcode::SRL, 0x00000001, 0xffffffff, 31),
//             (Opcode::SRL, 0x21212121, 0x21212121, 0),
//             (Opcode::SRL, 0x10909090, 0x21212121, 1),
//             (Opcode::SRL, 0x00424242, 0x21212121, 7),
//             (Opcode::SRL, 0x00008484, 0x21212121, 14),
//             (Opcode::SRL, 0x00000000, 0x21212121, 31),
//             (Opcode::SRL, 0x21212121, 0x21212121, 0xffffffe0),
//             (Opcode::SRL, 0x10909090, 0x21212121, 0xffffffe1),
//             (Opcode::SRL, 0x00424242, 0x21212121, 0xffffffe7),
//             (Opcode::SRL, 0x00008484, 0x21212121, 0xffffffee),
//             (Opcode::SRL, 0x00000000, 0x21212121, 0xffffffff),
//             (Opcode::SRA, 0x00000000, 0x00000000, 0),
//             (Opcode::SRA, 0xc0000000, 0x80000000, 1),
//             (Opcode::SRA, 0xff000000, 0x80000000, 7),
//             (Opcode::SRA, 0xfffe0000, 0x80000000, 14),
//             (Opcode::SRA, 0xffffffff, 0x80000001, 31),
//             (Opcode::SRA, 0x7fffffff, 0x7fffffff, 0),
//             (Opcode::SRA, 0x3fffffff, 0x7fffffff, 1),
//             (Opcode::SRA, 0x00ffffff, 0x7fffffff, 7),
//             (Opcode::SRA, 0x0001ffff, 0x7fffffff, 14),
//             (Opcode::SRA, 0x00000000, 0x7fffffff, 31),
//             (Opcode::SRA, 0x81818181, 0x81818181, 0),
//             (Opcode::SRA, 0xc0c0c0c0, 0x81818181, 1),
//             (Opcode::SRA, 0xff030303, 0x81818181, 7),
//             (Opcode::SRA, 0xfffe0606, 0x81818181, 14),
//             (Opcode::SRA, 0xffffffff, 0x81818181, 31),
//         ];
//         let mut shift_events: Vec<AluEvent> = Vec::new();
//         for t in shifts.iter() {
//             shift_events.push(AluEvent::new(0, t.0, t.1, t.2, t.3, false));
//         }
//         let mut shard = ExecutionRecord::default();
//         shard.shift_right_events = shift_events;

//         // Run setup.
//         let air = ShiftRightChip::default();
//         let config = SP1InnerPcs::new();
//         let chip = Chip::new(air);
//         let (pk, vk) = setup_test_machine(StarkMachine::new(
//             config.clone(),
//             vec![chip],
//             SP1_PROOF_NUM_PV_ELTS,
//             true,
//         ));

//         // Run the test.
//         let air = ShiftRightChip::default();
//         let chip: Chip<SP1Field, ShiftRightChip> = Chip::new(air);
//         let machine = StarkMachine::new(config.clone(), vec![chip], SP1_PROOF_NUM_PV_ELTS, true);
//         run_test_machine::<SP1InnerPcs, ShiftRightChip>(vec![shard], machine, pk, vk)
//             .unwrap();
//     }

//     #[test]
//     fn test_malicious_sr() {
//         const NUM_TESTS: usize = 5;

//         for opcode in [Opcode::SRL, Opcode::SRA] {
//             for _ in 0..NUM_TESTS {
//                 let (correct_op_a, op_b, op_c) = if opcode == Opcode::SRL {
//                     let op_b = thread_rng().gen_range(0..u32::MAX);
//                     let op_c = thread_rng().gen_range(0..u32::MAX);
//                     (op_b >> (op_c & 0x1F), op_b, op_c)
//                 } else if opcode == Opcode::SRA {
//                     let op_b = thread_rng().gen_range(0..i32::MAX);
//                     let op_c = thread_rng().gen_range(0..u32::MAX);
//                     ((op_b >> (op_c & 0x1F)) as u32, op_b as u32, op_c)
//                 } else {
//                     unreachable!()
//                 };

//                 let op_a = thread_rng().gen_range(0..u32::MAX);
//                 assert!(op_a != correct_op_a);

//                 let instructions = vec![
//                     Instruction::new(opcode, 5, op_b, op_c, true, true),
//                     Instruction::new(Opcode::ADD, 10, 0, 0, false, false),
//                 ];

//                 let program = Program::new(instructions, 0, 0);
//                 let stdin = SP1Stdin::new();

//                 type P = CpuProver<SP1InnerPcs, RiscvAir<SP1Field>>;

//                 let malicious_trace_pv_generator = move |prover: &P,
//                                                          record: &mut ExecutionRecord|
//                       -> Vec<(
//                     String,
//                     RowMajorMatrix<Val<SP1InnerPcs>>,
//                 )> {
//                     let mut malicious_record = record.clone();
//                     malicious_record.cpu_events[0].a = op_a as u32;
//                     if let Some(MemoryRecordEnum::Write(mut write_record)) =
//                         malicious_record.cpu_events[0].a_record
//                     {
//                         write_record.value = op_a as u32;
//                     }
//                     let mut traces = prover.generate_traces(&malicious_record);
//                     let shift_right_chip_name = chip_name!(ShiftRightChip, SP1Field);
//                     for (name, trace) in traces.iter_mut() {
//                         if *name == shift_right_chip_name {
//                             let first_row = trace.row_mut(0);
//                             let first_row: &mut ShiftRightCols<SP1Field> =
// first_row.borrow_mut();                             first_row.a = op_a.into();
//                         }
//                     }
//                     traces
//                 };

//                 let result =
//                     run_malicious_test::<P>(program, stdin,
// Box::new(malicious_trace_pv_generator));                 assert!(result.is_err() &&
// result.unwrap_err().is_constraints_failing());             }
//         }
//     }
// }
