use slop_algebra::{AbstractField, Field, PrimeField32};
use sp1_core_executor::{
    events::{ByteRecord, MemoryAccessPosition},
    JTypeRecord,
};
use sp1_derive::{AlignedBorrow, InputExpr, InputParams, IntoShape, SP1OperationBuilder};
use struct_reflection::{StructReflection, StructReflectionHelper};

use sp1_hypercube::{air::SP1AirBuilder, Word};

use crate::{
    air::{MemoryAirBuilder, ProgramAirBuilder, SP1Operation, WordAirBuilder},
    memory::{MemoryAccessWitgenInput, RegisterAccessCols},
    program::instruction::InstructionCols,
};

/// A set of columns to read operations with op_a being a register and op_b and op_c being
/// immediates.
#[derive(
    AlignedBorrow, Default, Debug, Clone, Copy, IntoShape, SP1OperationBuilder, StructReflection,
)]
#[repr(C)]
pub struct JTypeReader<T> {
    pub op_a: T,
    pub op_a_memory: RegisterAccessCols<T>,
    pub op_a_0: T,
    pub op_b_imm: Word<T>,
    pub op_c_imm: Word<T>,
}

impl<F: PrimeField32> JTypeReader<F> {
    /// Host-side populate DELEGATES to [`Self::witgen`] via `HostWitnessBuilder`
    /// (canonicalization stage 1): one witness implementation, two backends — the
    /// same motion as `RTypeReader`/`ITypeReader`. Equivalence (identical trace
    /// columns AND identical `ByteRecord` events) is pinned by the device==CPU
    /// full-trace equality tests of the J-type chips, whose CPU reference is this
    /// method.
    pub fn populate(&mut self, blu_events: &mut impl ByteRecord, record: JTypeRecord) {
        let mut wb = crate::air::HostWitnessBuilder::<F, _>::new(blu_events);
        Self::witgen(&mut wb, self, &JTypeReaderWitgenInput::from_record(&record));
    }
}

/// Witgen inputs of [`JTypeReader::witgen`], for nesting inside chip-level
/// witgen-input structs (see `record_witgen_inputs`). Field order IS the packed
/// input layout.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct JTypeReaderWitgenInput<T> {
    pub op_a: T,
    pub a: MemoryAccessWitgenInput<T>,
    pub op_b: T,
    pub op_c: T,
}

impl JTypeReaderWitgenInput<u64> {
    /// Pack an executor [`JTypeRecord`] into witgen-input form (`op_a` is a register
    /// access; `op_b`/`op_c` are immediates).
    pub fn from_record(record: &JTypeRecord) -> Self {
        Self {
            op_a: record.op_a as u64,
            a: MemoryAccessWitgenInput::from_record(record.a),
            op_b: record.op_b,
            op_c: record.op_c,
        }
    }
}

impl<T> JTypeReader<T> {
    /// Backend-agnostic witgen dual of [`Self::populate`]: the single op_a register
    /// access (write target), the `op_a == 0` flag, and the two immediate words.
    pub fn witgen<WB: crate::air::WitnessBuilder>(
        wb: &mut WB,
        cols: &mut JTypeReader<WB::Field>,
        input: &JTypeReaderWitgenInput<WB::Nat>,
    ) {
        cols.op_a = wb.nat_to_field(input.op_a);
        crate::memory::RegisterAccessCols::<WB::Field>::witgen(
            wb,
            &mut cols.op_a_memory,
            input.a.prev_value,
            input.a.prev_ts,
            input.a.cur_ts,
        );
        let zero = wb.const_nat(0);
        let is_zero = wb.eq(input.op_a, zero);
        cols.op_a_0 = wb.nat_to_field(is_zero);
        for i in 0..sp1_primitives::consts::WORD_SIZE {
            let l = wb.bits(input.op_b, (i as u32) * 16, 16);
            cols.op_b_imm[i] = wb.nat_to_field(l);
        }
        for i in 0..sp1_primitives::consts::WORD_SIZE {
            let l = wb.bits(input.op_c, (i as u32) * 16, 16);
            cols.op_c_imm[i] = wb.nat_to_field(l);
        }
    }

    pub fn prev_a(&self) -> &Word<T> {
        &self.op_a_memory.prev_value
    }

    pub fn b(&self) -> &Word<T> {
        &self.op_b_imm
    }

    pub fn c(&self) -> &Word<T> {
        &self.op_c_imm
    }
}

impl<T: Copy> JTypeReader<T> {
    pub fn instruction<AB>(&self, opcode: impl Into<AB::Expr> + Clone) -> InstructionCols<AB::Expr>
    where
        AB: SP1AirBuilder<Var = T>,
        T: Into<AB::Expr>,
    {
        InstructionCols {
            opcode: opcode.clone().into(),
            op_a: self.op_a.into(),
            op_b: self.op_b_imm.map(Into::into),
            op_c: self.op_c_imm.map(Into::into),
            op_a_0: self.op_a_0.into(),
            imm_b: AB::Expr::one(),
            imm_c: AB::Expr::one(),
        }
    }
}

impl<F: Field> JTypeReader<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn eval<AB: SP1AirBuilder + MemoryAirBuilder + ProgramAirBuilder>(
        builder: &mut AB,
        clk_high: AB::Expr,
        clk_low: AB::Expr,
        pc: [AB::Var; 3],
        opcode: impl Into<AB::Expr> + Clone,
        op_a_write_value: Word<impl Into<AB::Expr> + Clone>,
        cols: JTypeReader<AB::Var>,
        is_real: AB::Expr,
        is_trusted: AB::Expr,
    ) {
        builder.assert_bool(is_real.clone());

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
            is_real,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_op_a_immutable<AB: SP1AirBuilder + MemoryAirBuilder + ProgramAirBuilder>(
        builder: &mut AB,
        clk_high: AB::Expr,
        clk_low: AB::Expr,
        pc: [AB::Var; 3],
        opcode: impl Into<AB::Expr> + Clone,
        cols: JTypeReader<AB::Var>,
        is_real: AB::Expr,
        is_trusted: AB::Expr,
    ) {
        Self::eval(
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

#[allow(clippy::too_many_arguments)]
#[derive(Debug, Clone, InputParams, InputExpr)]
pub struct JTypeReaderInput<AB: SP1AirBuilder, T: Into<AB::Expr> + Clone> {
    clk_high: AB::Expr,
    clk_low: AB::Expr,
    pc: [AB::Var; 3],
    opcode: AB::Expr,
    op_a_write_value: Word<T>,
    cols: JTypeReader<AB::Var>,
    is_real: AB::Expr,
    is_trusted: AB::Expr,
}

impl<AB: SP1AirBuilder> SP1Operation<AB> for JTypeReader<AB::F> {
    type Input = JTypeReaderInput<AB, AB::Expr>;
    type Output = ();

    fn lower(builder: &mut AB, input: Self::Input) -> Self::Output {
        Self::eval(
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
