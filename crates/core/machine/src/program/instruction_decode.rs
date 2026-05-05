use core::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};

use crate::{
    air::{SP1CoreAirBuilder, SP1Operation, WordAirBuilder},
    operations::{IsZeroOperation, IsZeroOperationInput},
    program::InstructionCols,
    utils::next_multiple_of_32,
};
use slop_air::{Air, AirBuilder, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{ExecutionRecord, InstructionType, Opcode, Program};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{MachineAir, SP1AirBuilder},
    Word,
};

use rrs_lib::instruction_formats::{
    OPCODE_AUIPC, OPCODE_BRANCH, OPCODE_JAL, OPCODE_JALR, OPCODE_LOAD, OPCODE_LUI, OPCODE_OP,
    OPCODE_OP_32, OPCODE_OP_IMM, OPCODE_OP_IMM_32, OPCODE_STORE,
};

/// The number of program columns.
pub const NUM_INSTRUCTION_DECODE_COLS: usize = size_of::<InstructionDecodeCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct InstructionDecodeCols<T> {
    pub multiplicity: T,
    pub instruction: InstructionCols<T>,
    pub instr_type: T,
    pub funct3: T,
    pub funct7: T,
    pub is_r_type: T,
    pub is_i_type: T,
    pub is_i_type_shamt: T,
    pub is_i_type_shamt_32: T,
    pub is_j_type: T,
    pub is_b_type: T,
    pub is_s_type: T,
    pub is_u_type: T,
    pub is_a_0: IsZeroOperation<T>,
    pub encoded_instruction: [T; 2],
    pub encoded_instruction_bits: [T; 32],
}

/// A chip that implements instruction decoding.
#[derive(Default)]
pub struct InstructionDecodeChip;

impl InstructionDecodeChip {
    pub const fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField32> MachineAir<F> for InstructionDecodeChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "InstructionDecode"
    }

    fn generate_dependencies(&self, _input: &ExecutionRecord, _output: &mut ExecutionRecord) {
        // Do nothing since this chip has no dependencies.
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let padded_nb_rows =
            <InstructionDecodeChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let num_event_rows = input.instruction_decode_events.len();

        unsafe {
            let total_size = padded_nb_rows * NUM_INSTRUCTION_DECODE_COLS;
            if total_size > 0 {
                core::ptr::write_bytes(buffer.as_mut_ptr(), 0, total_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(
                buffer_ptr,
                num_event_rows * NUM_INSTRUCTION_DECODE_COLS,
            )
        };

        values.chunks_mut(NUM_INSTRUCTION_DECODE_COLS).enumerate().for_each(|(idx, row)| {
            let cols: &mut InstructionDecodeCols<F> = row.borrow_mut();
            let event = &input.instruction_decode_events[idx];

            let instruction = event.instruction;
            cols.instruction.populate(&instruction);
            cols.is_a_0.populate(instruction.op_a.into());

            // Check that the encoded instruction is correct
            let encoding_check = instruction.encode();
            assert_eq!(event.encoded_instruction, encoding_check);

            cols.encoded_instruction[0] = F::from_canonical_u32(event.encoded_instruction & 0xFFFF);
            cols.encoded_instruction[1] =
                F::from_canonical_u32((event.encoded_instruction >> 16) & 0xFFFF);

            for (i, bit) in event
                .encoded_instruction
                .to_le_bytes()
                .iter()
                .flat_map(|byte| {
                    let mut bits = [0u8; 8];
                    for j in 0..8 {
                        bits[j] = (byte >> j) & 1;
                    }
                    bits
                })
                .enumerate()
            {
                cols.encoded_instruction_bits[i] = F::from_canonical_u8(bit);
            }

            if instruction.opcode != Opcode::UNIMP {
                let (instr_type, instr_type_imm) = instruction.opcode.instruction_type();
                let instr_type = if instr_type_imm.is_some() && instruction.imm_c {
                    instr_type_imm.unwrap()
                } else {
                    instr_type
                };
                cols.instr_type = F::from_canonical_u32(instr_type as u32);

                let (base_opcode, base_imm_opcode) = instruction.opcode.base_opcode();
                let base_opcode = if base_imm_opcode.is_some() && instruction.imm_c {
                    base_imm_opcode.unwrap()
                } else {
                    base_opcode
                };
                let funct3 = instruction.opcode.funct3().unwrap_or(0);
                let funct7 = instruction.opcode.funct7().unwrap_or(0);
                cols.funct3 = F::from_canonical_u8(funct3);
                cols.funct7 = F::from_canonical_u8(funct7);

                cols.is_r_type =
                    F::from_bool(base_opcode == OPCODE_OP || base_opcode == OPCODE_OP_32);

                let is_i_type = matches!(
                    base_opcode,
                    OPCODE_OP_IMM | OPCODE_OP_IMM_32 | OPCODE_LOAD | OPCODE_JALR
                );
                if is_i_type {
                    if matches!(funct3, 0b001 | 0b101) && base_opcode == OPCODE_OP_IMM {
                        cols.is_i_type_shamt = F::one();
                    } else if matches!(funct3, 0b001 | 0b101) && base_opcode == OPCODE_OP_IMM_32 {
                        cols.is_i_type_shamt_32 = F::one();
                    } else {
                        cols.is_i_type = F::one();
                    }
                }

                cols.is_j_type = F::from_bool(base_opcode == OPCODE_JAL);
                cols.is_b_type = F::from_bool(base_opcode == OPCODE_BRANCH);
                cols.is_s_type = F::from_bool(base_opcode == OPCODE_STORE);
                cols.is_u_type =
                    F::from_bool(base_opcode == OPCODE_AUIPC || base_opcode == OPCODE_LUI);
            }

            cols.multiplicity = F::from_canonical_usize(event.multiplicity);
        });
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.instruction_decode_events.is_empty()
        }
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = next_multiple_of_32(
            input.instruction_decode_events.len(),
            input.fixed_log2_rows::<F, _>(self),
        );
        Some(nb_rows)
    }
}

impl<F> BaseAir<F> for InstructionDecodeChip {
    fn width(&self) -> usize {
        NUM_INSTRUCTION_DECODE_COLS
    }
}

impl<AB> Air<AB> for InstructionDecodeChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &InstructionDecodeCols<AB::Var> = (*local).borrow();

        // We do not allow untrusted instructions to make ecalls.
        builder.assert_bool(local.is_r_type);
        builder.assert_bool(local.is_i_type);
        builder.assert_bool(local.is_i_type_shamt);
        builder.assert_bool(local.is_i_type_shamt_32);
        builder.assert_bool(local.is_j_type);
        builder.assert_bool(local.is_b_type);
        builder.assert_bool(local.is_s_type);
        builder.assert_bool(local.is_u_type);

        let is_real: AB::Expr = local.is_r_type
            + local.is_i_type
            + local.is_i_type_shamt
            + local.is_i_type_shamt_32
            + local.is_j_type
            + local.is_b_type
            + local.is_s_type
            + local.is_u_type;

        // Assert that at most one of the instruction selectors is set.
        builder.assert_bool(is_real.clone());
        builder.assert_eq(
            builder.extract_public_values().is_untrusted_programs_enabled,
            AB::Expr::one(),
        );

        #[cfg(not(feature = "mprotect"))]
        builder.assert_zero(is_real.clone());
        #[cfg(not(feature = "mprotect"))]
        builder.assert_zero(local.multiplicity);

        // Assert that the right instruction selector is set.
        builder.assert_eq(
            local.instr_type,
            local.is_r_type * AB::Expr::from_canonical_u32(InstructionType::RType as u32)
                + local.is_i_type * AB::Expr::from_canonical_u32(InstructionType::IType as u32)
                + local.is_i_type_shamt
                    * AB::Expr::from_canonical_u32(InstructionType::ITypeShamt as u32)
                + local.is_i_type_shamt_32
                    * AB::Expr::from_canonical_u32(InstructionType::ITypeShamt32 as u32)
                + local.is_j_type * AB::Expr::from_canonical_u32(InstructionType::JType as u32)
                + local.is_b_type * AB::Expr::from_canonical_u32(InstructionType::BType as u32)
                + local.is_s_type * AB::Expr::from_canonical_u32(InstructionType::SType as u32)
                + local.is_u_type * AB::Expr::from_canonical_u32(InstructionType::UType as u32),
        );

        let (
            decoded_base_opcode,
            decoded_funct3,
            decoded_funct7_rtype,
            decoded_funct7_i_type_shamt,
            decoded_rd,
            decoded_rs1,
            decoded_rs2,
        ) = self.decode_instruction(builder, local);

        self.r_type_eval(
            builder,
            local,
            decoded_funct3.clone(),
            decoded_funct7_rtype.clone(),
            decoded_rd.clone(),
            decoded_rs1.clone(),
            decoded_rs2.clone(),
        );
        self.i_type_eval(
            builder,
            local,
            decoded_funct3.clone(),
            decoded_rd.clone(),
            decoded_rs1.clone(),
        );
        self.i_type_shamt_eval(
            builder,
            local,
            decoded_funct3.clone(),
            decoded_funct7_i_type_shamt.clone(),
            decoded_rd.clone(),
            decoded_rs1.clone(),
        );
        self.i_type_shamt_32_eval(
            builder,
            local,
            decoded_funct3.clone(),
            decoded_funct7_i_type_shamt.clone(),
            decoded_rd.clone(),
            decoded_rs1.clone(),
        );
        self.j_type_eval(builder, local, decoded_rd.clone());
        self.b_type_eval(
            builder,
            local,
            decoded_funct3.clone(),
            decoded_rs1.clone(),
            decoded_rs2.clone(),
        );
        self.s_type_eval(
            builder,
            local,
            decoded_funct3.clone(),
            decoded_rs1.clone(),
            decoded_rs2.clone(),
        );
        self.u_type_eval(builder, local, decoded_rd.clone());

        // Check the op_a_0 column.
        IsZeroOperation::<AB::F>::eval(
            builder,
            IsZeroOperationInput::new(local.instruction.op_a.into(), local.is_a_0, is_real.clone()),
        );
        builder.when(is_real.clone()).assert_eq(local.is_a_0.result, local.instruction.op_a_0);

        // Constrain the interaction with instruction decode table
        let untrusted_instruction_const_fields = [
            local.instr_type.into(),
            decoded_base_opcode,
            local.funct3.into(),
            local.funct7.into(),
        ];

        builder.when_not(is_real).assert_zero(local.multiplicity);

        builder.receive_instruction_decode(
            [local.encoded_instruction[0].into(), local.encoded_instruction[1].into()],
            local.instruction,
            untrusted_instruction_const_fields,
            local.multiplicity.into(),
        );
    }
}

impl InstructionDecodeChip {
    fn decode_instruction<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &InstructionDecodeCols<AB::Var>,
    ) -> (AB::Expr, AB::Expr, AB::Expr, AB::Expr, AB::Expr, Word<AB::Expr>, Word<AB::Expr>) {
        let mut reconstructed_first_limb = AB::Expr::zero();
        for (i, bit) in local.encoded_instruction_bits[0..16].iter().enumerate() {
            builder.assert_bool(*bit);
            reconstructed_first_limb =
                reconstructed_first_limb.clone() + AB::Expr::from_wrapped_u32(1 << i) * *bit;
        }

        let mut reconstructed_second_limb = AB::Expr::zero();
        for (i, bit) in local.encoded_instruction_bits[16..32].iter().enumerate() {
            builder.assert_bool(*bit);
            reconstructed_second_limb =
                reconstructed_second_limb.clone() + AB::Expr::from_wrapped_u32(1 << i) * *bit;
        }

        builder.assert_eq(local.encoded_instruction[0].into(), reconstructed_first_limb);
        builder.assert_eq(local.encoded_instruction[1].into(), reconstructed_second_limb);

        // True for all instruction types
        let mut reconstructed_base_opcode = AB::Expr::zero();
        for (i, bit) in local.encoded_instruction_bits[0..7].iter().enumerate() {
            reconstructed_base_opcode =
                reconstructed_base_opcode.clone() + AB::Expr::from_wrapped_u32(1 << i) * *bit;
        }

        // True for R, I, U, J, Not right for S, B
        let mut reconstructed_rd = AB::Expr::zero();
        for (i, bit) in local.encoded_instruction_bits[7..12].iter().enumerate() {
            reconstructed_rd = reconstructed_rd.clone() + AB::Expr::from_wrapped_u32(1 << i) * *bit;
        }

        // True for R, I, S, B, Not right for U, J
        let mut reconstructed_funct3 = AB::Expr::zero();
        for (i, bit) in local.encoded_instruction_bits[12..15].iter().enumerate() {
            reconstructed_funct3 =
                reconstructed_funct3.clone() + AB::Expr::from_wrapped_u32(1 << i) * *bit;
        }

        // True for R, I, S, B, Not right for U, J
        let reconstructed_rs1 =
            Word::from_le_bits::<AB>(&local.encoded_instruction_bits[15..20], false);

        // True for R, S, B, Not right for I, U, J
        let reconstructed_rs2 =
            Word::from_le_bits::<AB>(&local.encoded_instruction_bits[20..25], false);

        let mut reconstructed_funct7_rtype = AB::Expr::zero();
        for (i, bit) in local.encoded_instruction_bits[25..32].iter().enumerate() {
            reconstructed_funct7_rtype =
                reconstructed_funct7_rtype.clone() + AB::Expr::from_wrapped_u32(1 << i) * *bit;
        }

        let mut reconstructed_funct7_i_type_shamt = AB::Expr::zero();
        for (i, bit) in local.encoded_instruction_bits[26..32].iter().enumerate() {
            reconstructed_funct7_i_type_shamt = reconstructed_funct7_i_type_shamt.clone()
                + AB::Expr::from_wrapped_u32(1 << i) * *bit;
        }
        reconstructed_funct7_i_type_shamt =
            reconstructed_funct7_i_type_shamt.clone() * AB::Expr::from_wrapped_u32(2);

        (
            reconstructed_base_opcode,
            reconstructed_funct3,
            reconstructed_funct7_rtype,
            reconstructed_funct7_i_type_shamt,
            reconstructed_rd,
            reconstructed_rs1,
            reconstructed_rs2,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn r_type_eval<AB: SP1CoreAirBuilder>(
        &self,
        builder: &mut AB,
        local: &InstructionDecodeCols<AB::Var>,
        decoded_funct3: AB::Expr,
        decoded_funct7: AB::Expr,
        decoded_rd: AB::Expr,
        decoded_rs1: Word<AB::Expr>,
        decoded_rs2: Word<AB::Expr>,
    ) {
        let mut r_type_builder = builder.when(local.is_r_type);

        r_type_builder.assert_eq(local.funct3, decoded_funct3);
        r_type_builder.assert_eq(local.funct7, decoded_funct7);

        r_type_builder.assert_eq(local.instruction.op_a, decoded_rd);
        r_type_builder.assert_word_eq(local.instruction.op_b, decoded_rs1);
        r_type_builder.assert_word_eq(local.instruction.op_c, decoded_rs2);

        r_type_builder.assert_zero(local.instruction.imm_b);
        r_type_builder.assert_zero(local.instruction.imm_c);
    }

    fn i_type_eval<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &InstructionDecodeCols<AB::Var>,
        decoded_funct3: AB::Expr,
        decoded_rd: AB::Expr,
        decoded_rs1: Word<AB::Expr>,
    ) {
        let mut i_type_builder = builder.when(local.is_i_type);

        i_type_builder.assert_eq(local.funct3, decoded_funct3);
        i_type_builder.assert_eq(local.funct7, AB::Expr::zero());

        i_type_builder.assert_eq(local.instruction.op_a, decoded_rd);
        i_type_builder.assert_word_eq(local.instruction.op_b, decoded_rs1);

        let mut imm_le_bits = Vec::new();
        imm_le_bits.extend(local.encoded_instruction_bits[20..32].iter().map(|x| (*x).into()));
        let sign_extended_imm = Word::from_le_bits::<AB>(&imm_le_bits, true);

        i_type_builder.assert_word_eq(local.instruction.op_c, sign_extended_imm);

        i_type_builder.assert_zero(local.instruction.imm_b);
        i_type_builder.assert_one(local.instruction.imm_c);
    }

    fn i_type_shamt_eval<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &InstructionDecodeCols<AB::Var>,
        decoded_funct3: AB::Expr,
        decoded_funct7: AB::Expr,
        decoded_rd: AB::Expr,
        decoded_rs1: Word<AB::Expr>,
    ) {
        let mut i_type_shamt_builder = builder.when(local.is_i_type_shamt);

        i_type_shamt_builder.assert_eq(local.funct3, decoded_funct3);
        i_type_shamt_builder.assert_eq(local.funct7, decoded_funct7);

        i_type_shamt_builder.assert_eq(local.instruction.op_a, decoded_rd);
        i_type_shamt_builder.assert_word_eq(local.instruction.op_b, decoded_rs1);

        let shamt = Word::from_le_bits::<AB>(&local.encoded_instruction_bits[20..26], false);
        i_type_shamt_builder.assert_word_eq(local.instruction.op_c, shamt);

        i_type_shamt_builder.assert_zero(local.instruction.imm_b);
        i_type_shamt_builder.assert_one(local.instruction.imm_c);
    }

    fn i_type_shamt_32_eval<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &InstructionDecodeCols<AB::Var>,
        decoded_funct3: AB::Expr,
        decoded_funct7: AB::Expr,
        decoded_rd: AB::Expr,
        decoded_rs1: Word<AB::Expr>,
    ) {
        let mut i_type_shamt_32_builder = builder.when(local.is_i_type_shamt_32);

        i_type_shamt_32_builder.assert_eq(local.funct3, decoded_funct3);
        i_type_shamt_32_builder.assert_eq(local.funct7, decoded_funct7);

        i_type_shamt_32_builder.assert_eq(local.instruction.op_a, decoded_rd);
        i_type_shamt_32_builder.assert_word_eq(local.instruction.op_b, decoded_rs1);

        let shamt = Word::from_le_bits::<AB>(&local.encoded_instruction_bits[20..25], false);
        i_type_shamt_32_builder.assert_word_eq(local.instruction.op_c, shamt);

        i_type_shamt_32_builder.assert_zero(local.encoded_instruction_bits[25]);

        i_type_shamt_32_builder.assert_zero(local.instruction.imm_b);
        i_type_shamt_32_builder.assert_one(local.instruction.imm_c);
    }

    fn j_type_eval<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &InstructionDecodeCols<AB::Var>,
        decoded_rd: AB::Expr,
    ) {
        {
            let mut imm_le_bits = Vec::new();

            // The least significant bit (bit 0) is always 0.
            imm_le_bits.push(AB::Expr::zero());
            imm_le_bits.extend(local.encoded_instruction_bits[21..31].iter().map(|x| (*x).into()));
            imm_le_bits.push(local.encoded_instruction_bits[20].into());
            imm_le_bits.extend(local.encoded_instruction_bits[12..20].iter().map(|x| (*x).into()));
            imm_le_bits.push(local.encoded_instruction_bits[31].into());

            let sign_extended_word = Word::from_le_bits::<AB>(&imm_le_bits, true);

            let mut j_type_builder = builder.when(local.is_j_type);

            j_type_builder.assert_eq(local.funct3, AB::Expr::zero());
            j_type_builder.assert_eq(local.funct7, AB::Expr::zero());

            j_type_builder.assert_eq(local.instruction.op_a, decoded_rd);
            j_type_builder.assert_word_eq(local.instruction.op_b, sign_extended_word);
            j_type_builder.assert_word_zero(local.instruction.op_c);

            j_type_builder.assert_one(local.instruction.imm_b);
            j_type_builder.assert_one(local.instruction.imm_c);
        }
    }

    fn b_type_eval<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &InstructionDecodeCols<AB::Var>,
        decoded_funct3: AB::Expr,
        decoded_rs1: Word<AB::Expr>,
        decoded_rs2: Word<AB::Expr>,
    ) {
        let mut b_type_builder = builder.when(local.is_b_type);

        b_type_builder.assert_eq(local.funct3, decoded_funct3);
        b_type_builder.assert_eq(local.funct7, AB::Expr::zero());

        let op_a_word = Word::extend_expr::<AB>(local.instruction.op_a.into());
        b_type_builder.assert_word_eq(op_a_word, decoded_rs1);
        b_type_builder.assert_word_eq(local.instruction.op_b, decoded_rs2);

        let mut imm_le_bits = Vec::new();
        imm_le_bits.push(AB::Expr::zero());
        imm_le_bits.extend(local.encoded_instruction_bits[8..12].iter().map(|x| (*x).into()));
        imm_le_bits.extend(local.encoded_instruction_bits[25..31].iter().map(|x| (*x).into()));
        imm_le_bits.push(local.encoded_instruction_bits[7].into());
        imm_le_bits.push(local.encoded_instruction_bits[31].into());

        let signed_extended_imm = Word::from_le_bits::<AB>(&imm_le_bits, true);
        b_type_builder.assert_word_eq(local.instruction.op_c, signed_extended_imm);

        b_type_builder.assert_zero(local.instruction.imm_b);
        b_type_builder.assert_one(local.instruction.imm_c);
    }

    fn s_type_eval<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &InstructionDecodeCols<AB::Var>,
        decoded_funct3: AB::Expr,
        decoded_rs1: Word<AB::Expr>,
        decoded_rs2: Word<AB::Expr>,
    ) {
        let mut s_type_builder = builder.when(local.is_s_type);

        s_type_builder.assert_eq(local.funct3, decoded_funct3);
        s_type_builder.assert_eq(local.funct7, AB::Expr::zero());

        let op_a_word = Word::extend_expr::<AB>(local.instruction.op_a.into());
        s_type_builder.assert_word_eq(op_a_word, decoded_rs2);
        s_type_builder.assert_word_eq(local.instruction.op_b, decoded_rs1);

        let mut imm_le_bits = Vec::new();
        imm_le_bits.extend(local.encoded_instruction_bits[7..12].iter().map(|x| (*x).into()));
        imm_le_bits.extend(local.encoded_instruction_bits[25..32].iter().map(|x| (*x).into()));
        let signed_extended_imm = Word::from_le_bits::<AB>(&imm_le_bits, true);

        s_type_builder.assert_word_eq(local.instruction.op_c, signed_extended_imm);

        s_type_builder.assert_zero(local.instruction.imm_b);
        s_type_builder.assert_one(local.instruction.imm_c);
    }

    fn u_type_eval<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &InstructionDecodeCols<AB::Var>,
        decoded_rd: AB::Expr,
    ) {
        let mut imm_le_bits = Vec::new();
        // The first 12 bits are all 0.
        for _ in 0..12 {
            imm_le_bits.push(AB::Expr::zero());
        }
        imm_le_bits.extend(local.encoded_instruction_bits[12..32].iter().map(|x| (*x).into()));

        let reconstructed_imm = Word::from_le_bits::<AB>(&imm_le_bits, true);

        let mut utype_builder = builder.when(local.is_u_type);

        utype_builder.assert_eq(local.funct3, AB::Expr::zero());
        utype_builder.assert_eq(local.funct7, AB::Expr::zero());

        utype_builder.assert_eq(local.instruction.op_a, decoded_rd);
        utype_builder.assert_word_eq(local.instruction.op_b, reconstructed_imm.clone());
        utype_builder.assert_word_eq(local.instruction.op_c, reconstructed_imm);

        utype_builder.assert_one(local.instruction.imm_b);
        utype_builder.assert_one(local.instruction.imm_c);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::print_stdout)]

    use std::sync::Arc;

    use sp1_primitives::SP1Field;

    use slop_matrix::dense::RowMajorMatrix;
    use sp1_core_executor::{ExecutionRecord, Instruction, Opcode, Program};
    use sp1_hypercube::air::MachineAir;

    use crate::program::InstructionDecodeChip;

    #[test]
    fn generate_trace() {
        // main:
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     add x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADDI, 30, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];
        let shard = ExecutionRecord {
            program: Arc::new(Program::new(instructions, 0, 0)),
            ..Default::default()
        };
        let chip = InstructionDecodeChip::new();
        let trace: RowMajorMatrix<SP1Field> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }
}
