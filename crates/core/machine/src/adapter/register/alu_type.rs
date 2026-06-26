use serde::{Deserialize, Serialize};
use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field, PrimeField32};
use sp1_core_executor::{
    events::{ByteRecord, MemoryAccessPosition},
    ALUTypeRecord,
};
use sp1_derive::{AlignedBorrow, InputExpr, InputParams, IntoShape, SP1OperationBuilder};

use sp1_hypercube::{air::SP1AirBuilder, Word};
use sp1_primitives::consts::WORD_SIZE;
use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::{
    air::{MemoryAirBuilder, ProgramAirBuilder, SP1Operation, WitnessBuilder, WordAirBuilder},
    memory::RegisterAccessCols,
    program::instruction::InstructionCols,
};

/// A set of columns to read operations with op_a and op_b being registers and op_c being a register
/// or immediate.
#[derive(
    AlignedBorrow,
    StructReflection,
    Default,
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    IntoShape,
    SP1OperationBuilder,
)]
#[repr(C)]
pub struct ALUTypeReader<T> {
    pub op_a: T,
    pub op_a_memory: RegisterAccessCols<T>,
    pub op_a_0: T,
    pub op_b: T,
    pub op_b_memory: RegisterAccessCols<T>,
    pub op_c: Word<T>,
    pub op_c_memory: RegisterAccessCols<T>,
    pub imm_c: T,
}

impl<T> ALUTypeReader<T> {
    pub fn prev_a(&self) -> &Word<T> {
        &self.op_a_memory.prev_value
    }

    pub fn b(&self) -> &Word<T> {
        &self.op_b_memory.prev_value
    }

    pub fn c(&self) -> &Word<T> {
        &self.op_c_memory.prev_value
    }
}

impl<T: Copy> ALUTypeReader<T> {
    pub fn instruction<AB>(&self, opcode: impl Into<AB::Expr> + Clone) -> InstructionCols<AB::Expr>
    where
        AB: SP1AirBuilder<Var = T>,
        T: Into<AB::Expr>,
    {
        InstructionCols {
            opcode: opcode.clone().into(),
            op_a: self.op_a.into(),
            op_b: Word::extend_expr::<AB>(self.op_b.into()),
            op_c: self.op_c.map(Into::into),
            op_a_0: self.op_a_0.into(),
            imm_b: AB::Expr::zero(),
            imm_c: self.imm_c.into(),
        }
    }
}

impl<F: PrimeField32> ALUTypeReader<F> {
    pub fn populate(&mut self, blu_events: &mut impl ByteRecord, record: ALUTypeRecord) {
        self.op_a = F::from_canonical_u8(record.op_a);
        self.op_a_memory.populate(record.a, blu_events);
        self.op_a_0 = F::from_bool(record.op_a == 0);
        self.op_b = F::from_canonical_u64(record.op_b);
        self.op_b_memory.populate(record.b, blu_events);
        self.op_c = Word::from(record.op_c);
        let imm_c = record.c.is_none();
        self.imm_c = F::from_bool(imm_c);
        if imm_c {
            self.op_c_memory.prev_value = self.op_c;
            self.op_c_memory.access_timestamp.diff_low_limb = F::zero();
            self.op_c_memory.access_timestamp.prev_low = F::zero();
        } else {
            self.op_c_memory.populate(record.c.unwrap(), blu_events);
        }
    }
}

// Witgen in an unconstrained `impl<T>` (column type is the builder's `Field`).
impl<T> ALUTypeReader<T> {
    /// Backend-agnostic witgen for the REGISTER-register case (`op_c` is a register,
    /// `imm_c = 0`), used by device tracegen for register-register ALU chips (Addw,
    /// …). The immediate case (`imm_c = 1`) is a per-row branch that the row-
    /// independent op-DAG can't express, so immediate-capable chips are not device-
    /// ported through this path. Mirrors the `imm_c = false` branch of [`Self::populate`].
    #[allow(clippy::too_many_arguments)]
    pub fn witgen<WB: WitnessBuilder>(
        wb: &mut WB,
        cols: &mut ALUTypeReader<WB::Field>,
        op_a: WB::Nat,
        a_prev_value: WB::Nat,
        a_prev_ts: WB::Nat,
        a_cur_ts: WB::Nat,
        op_b: WB::Nat,
        b_prev_value: WB::Nat,
        b_prev_ts: WB::Nat,
        b_cur_ts: WB::Nat,
        op_c: WB::Nat,
        c_prev_value: WB::Nat,
        c_prev_ts: WB::Nat,
        c_cur_ts: WB::Nat,
    ) {
        cols.op_a = wb.nat_to_field(op_a);
        RegisterAccessCols::<WB::Field>::witgen(
            wb,
            &mut cols.op_a_memory,
            a_prev_value,
            a_prev_ts,
            a_cur_ts,
        );
        let zero = wb.const_nat(0);
        let a_is_zero = wb.eq(op_a, zero);
        cols.op_a_0 = wb.nat_to_field(a_is_zero);
        cols.op_b = wb.nat_to_field(op_b);
        RegisterAccessCols::<WB::Field>::witgen(
            wb,
            &mut cols.op_b_memory,
            b_prev_value,
            b_prev_ts,
            b_cur_ts,
        );
        // `op_c` is the instruction's op_c field as a Word (4 u16 limbs); for a
        // register operand this is the register index. No range checks (cf. populate).
        for i in 0..WORD_SIZE {
            let limb = wb.bits(op_c, (i as u32) * 16, 16);
            cols.op_c[i] = wb.nat_to_field(limb);
        }
        // Register operand: imm_c = 0, and op_c_memory is a real register read.
        cols.imm_c = wb.nat_to_field(zero);
        RegisterAccessCols::<WB::Field>::witgen(
            wb,
            &mut cols.op_c_memory,
            c_prev_value,
            c_prev_ts,
            c_cur_ts,
        );
    }
}

impl<F: Field> ALUTypeReader<F> {
    #[allow(clippy::too_many_arguments)]
    fn eval_alu_reader<AB: SP1AirBuilder + MemoryAirBuilder + ProgramAirBuilder>(
        builder: &mut AB,
        clk_high: AB::Expr,
        clk_low: AB::Expr,
        pc: [AB::Var; 3],
        opcode: impl Into<AB::Expr> + Clone,
        op_a_write_value: Word<impl Into<AB::Expr> + Clone>,
        cols: ALUTypeReader<AB::Var>,
        is_real: AB::Expr,
        is_trusted: AB::Expr,
    ) {
        builder.assert_bool(is_real.clone());

        // Assert that `imm_c` is zero if the operation is not real.
        // This is to ensure that the `op_c` read multiplicity is zero on padding rows.
        builder.when_not(is_real.clone()).assert_eq(cols.imm_c, AB::Expr::zero());

        let instruction = cols.instruction::<AB>(opcode.clone());
        builder.send_program(pc, instruction.clone(), is_trusted);

        // Assert that `op_a` is zero if `op_a_0` is true.
        builder.when(cols.op_a_0).assert_word_eq(op_a_write_value.clone(), Word::zero::<AB>());
        builder.eval_register_access_write(
            clk_high.clone(),
            clk_low.clone() + AB::Expr::from_canonical_u32(MemoryAccessPosition::A as u32),
            [cols.op_a.into(), AB::Expr::zero(), AB::Expr::zero()],
            cols.op_a_memory,
            op_a_write_value,
            is_real.clone(),
        );
        builder.eval_register_access_read(
            clk_high.clone(),
            clk_low.clone() + AB::Expr::from_canonical_u32(MemoryAccessPosition::B as u32),
            [cols.op_b.into(), AB::Expr::zero(), AB::Expr::zero()],
            cols.op_b_memory,
            is_real.clone(),
        );
        // Read the `op_c[0]` register only when `imm_c` is zero and `is_real` is true.
        builder.eval_register_access_read(
            clk_high.clone(),
            clk_low.clone() + AB::Expr::from_canonical_u32(MemoryAccessPosition::C as u32),
            [cols.op_c[0].into(), AB::Expr::zero(), AB::Expr::zero()],
            cols.op_c_memory,
            is_real - cols.imm_c,
        );
        // If `op_c` is an immediate, assert that `op_c` value is copied into
        // `op_c_memory.prev_value`.
        builder.when(cols.imm_c).assert_word_eq(cols.op_c_memory.prev_value, cols.op_c);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_op_a_immutable<AB: SP1AirBuilder + MemoryAirBuilder + ProgramAirBuilder>(
        builder: &mut AB,
        clk_high: AB::Expr,
        clk_low: AB::Expr,
        pc: [AB::Var; 3],
        opcode: impl Into<AB::Expr> + Clone,
        cols: ALUTypeReader<AB::Var>,
        is_real: AB::Expr,
        is_trusted: AB::Expr,
    ) {
        Self::eval_alu_reader(
            builder,
            clk_high,
            clk_low,
            pc,
            opcode,
            cols.op_a_memory.prev_value,
            cols,
            is_real,
            is_trusted,
        );
    }
}

#[derive(Clone, InputParams, InputExpr)]
pub struct ALUTypeReaderInput<AB: SP1AirBuilder, T: Into<AB::Expr> + Clone> {
    pub clk_high: AB::Expr,
    pub clk_low: AB::Expr,
    pub pc: [AB::Var; 3],
    pub opcode: AB::Expr,
    pub op_a_write_value: Word<T>,
    pub cols: ALUTypeReader<AB::Var>,
    pub is_real: AB::Expr,
    pub is_trusted: AB::Expr,
}

impl<AB: SP1AirBuilder> SP1Operation<AB> for ALUTypeReader<AB::F> {
    type Input = ALUTypeReaderInput<AB, AB::Expr>;
    type Output = ();

    fn lower(builder: &mut AB, input: Self::Input) -> Self::Output {
        Self::eval_alu_reader(
            builder,
            input.clk_high,
            input.clk_low,
            input.pc,
            input.opcode,
            input.op_a_write_value,
            input.cols,
            input.is_real,
            input.is_trusted,
        )
    }
}
