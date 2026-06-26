use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractField, Field, PrimeField32};
use sp1_core_executor::{
    events::{ByteRecord, MemoryAccessPosition},
    RTypeRecord,
};
use sp1_derive::{AlignedBorrow, InputExpr, InputParams, IntoShape, SP1OperationBuilder};

use sp1_hypercube::{air::SP1AirBuilder, Word};

use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::{
    air::{MemoryAirBuilder, ProgramAirBuilder, SP1Operation, WordAirBuilder},
    memory::RegisterAccessCols,
    program::instruction::InstructionCols,
};

/// A set of columns to read operations with op_a, op_b, op_c being registers.
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
pub struct RTypeReader<T> {
    pub op_a: T,
    pub op_a_memory: RegisterAccessCols<T>,
    pub op_a_0: T,
    pub op_b: T,
    pub op_b_memory: RegisterAccessCols<T>,
    pub op_c: T,
    pub op_c_memory: RegisterAccessCols<T>,
}

// Witgen in an unconstrained `impl<T>` (column type is the builder's `Field`).
impl<T> RTypeReader<T> {
    /// Backend-agnostic witgen: the three register indices (`op_a`/`op_b`/`op_c`),
    /// the `op_a == 0` flag, and the three register reads (each composing
    /// [`RegisterAccessCols::witgen`]). Inputs are grouped per operand: the index
    /// then the read's `(prev_value, prev_timestamp, current_timestamp)`.
    #[allow(clippy::too_many_arguments)]
    pub fn witgen<WB: crate::air::WitnessBuilder>(
        wb: &mut WB,
        cols: &mut RTypeReader<WB::Field>,
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
        cols.op_c = wb.nat_to_field(op_c);
        RegisterAccessCols::<WB::Field>::witgen(
            wb,
            &mut cols.op_c_memory,
            c_prev_value,
            c_prev_ts,
            c_cur_ts,
        );
    }
}

impl<F: PrimeField32> RTypeReader<F> {
    pub fn populate(&mut self, blu_events: &mut impl ByteRecord, record: RTypeRecord) {
        let a = record.a;
        let b = record.b;
        let c = record.c;
        let mut wb = crate::air::HostWitnessBuilder::<F, _>::new(blu_events);
        Self::witgen(
            &mut wb,
            self,
            record.op_a as u64,
            a.previous_record().value,
            a.previous_record().timestamp,
            a.current_record().timestamp,
            record.op_b,
            b.previous_record().value,
            b.previous_record().timestamp,
            b.current_record().timestamp,
            record.op_c,
            c.previous_record().value,
            c.previous_record().timestamp,
            c.current_record().timestamp,
        );
    }
}

impl<T> RTypeReader<T> {
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

impl<T: Copy> RTypeReader<T> {
    pub fn instruction<AB>(&self, opcode: impl Into<AB::Expr> + Clone) -> InstructionCols<AB::Expr>
    where
        AB: SP1AirBuilder<Var = T>,
        T: Into<AB::Expr>,
    {
        InstructionCols {
            opcode: opcode.clone().into(),
            op_a: self.op_a.into(),
            op_b: Word::extend_expr::<AB>(self.op_b.into()),
            op_c: Word::extend_expr::<AB>(self.op_c.into()),
            op_a_0: self.op_a_0.into(),
            imm_b: AB::Expr::zero(),
            imm_c: AB::Expr::zero(),
        }
    }
}

impl<F: Field> RTypeReader<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn eval<AB: SP1AirBuilder + MemoryAirBuilder + ProgramAirBuilder>(
        builder: &mut AB,
        clk_high: AB::Expr,
        clk_low: AB::Expr,
        pc: [AB::Var; 3],
        opcode: impl Into<AB::Expr> + Clone,
        op_a_write_value: Word<impl Into<AB::Expr> + Clone>,
        cols: RTypeReader<AB::Var>,
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
            is_real.clone(),
        );
        builder.eval_register_access_read(
            clk_high.clone(),
            clk_low.clone() + AB::Expr::from_canonical_u32(MemoryAccessPosition::B as u32),
            [cols.op_b.into(), AB::Expr::zero(), AB::Expr::zero()],
            cols.op_b_memory,
            is_real.clone(),
        );
        builder.eval_register_access_read(
            clk_high.clone(),
            clk_low.clone() + AB::Expr::from_canonical_u32(MemoryAccessPosition::C as u32),
            [cols.op_c.into(), AB::Expr::zero(), AB::Expr::zero()],
            cols.op_c_memory,
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
        cols: RTypeReader<AB::Var>,
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

#[derive(Clone, InputParams, InputExpr)]
pub struct RTypeReaderInput<AB: SP1AirBuilder, T: Into<AB::Expr> + Clone> {
    pub clk_high: AB::Expr,
    pub clk_low: AB::Expr,
    pub pc: [AB::Var; 3],
    pub opcode: AB::Expr,
    pub op_a_write_value: Word<T>,
    pub cols: RTypeReader<AB::Var>,
    pub is_real: AB::Expr,
    pub is_trusted: AB::Expr,
}

impl<AB: SP1AirBuilder> SP1Operation<AB> for RTypeReader<AB::F> {
    type Input = RTypeReaderInput<AB, AB::Expr>;
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

#[derive(Debug, Clone, SP1OperationBuilder)]
pub struct RTypeReaderImmutable;

#[allow(clippy::too_many_arguments)]
#[derive(Debug, Clone, InputParams, InputExpr)]
pub struct RTypeReaderImmutableInput<AB: SP1AirBuilder> {
    pub clk_high: AB::Expr,
    pub clk_low: AB::Expr,
    pub pc: [AB::Var; 3],
    pub opcode: AB::Expr,
    pub cols: RTypeReader<AB::Var>,
    pub is_real: AB::Expr,
    pub is_trusted: AB::Expr,
}

impl<AB: SP1AirBuilder> SP1Operation<AB> for RTypeReaderImmutable {
    type Input = RTypeReaderImmutableInput<AB>;
    type Output = ();

    fn lower(builder: &mut AB, input: Self::Input) -> Self::Output {
        RTypeReader::<AB::F>::eval_op_a_immutable(
            builder,
            input.clk_high,
            input.clk_low,
            input.pc,
            input.opcode,
            input.cols,
            input.is_real,
            input.is_trusted,
        )
    }
}

// impl<T: Into<<ConstraintCompiler as AirBuilder>::Expr> + Clone>
//     Into<Shape<ExprRef<<ConstraintCompiler as AirBuilder>::F>,
// ExprExtRef<sp1_hypercube::ir::EF>>>     for RTypeReaderInput<ConstraintCompiler>
// {
//     fn into(
//         self,
//     ) -> Shape<ExprRef<<ConstraintCompiler as AirBuilder>::F>, ExprExtRef<sp1_hypercube::ir::EF>>
// {         Shape::Struct(
//             "RTypeReaderInput".to_string(),
//             vec![
//                 ("clk_high".to_string(), Box::new(self.clk_high.into())),
//                 ("clk_low".to_string(), Box::new(self.clk_low.into())),
//                 ("pc".to_string(), Box::new(self.pc.into())),
//                 ("opcode".to_string(), Box::new(self.opcode.into())),
//                 ("op_a_write_value".to_string(), Box::new(self.op_a_write_value.into())),
//                 ("cols".to_string(), Box::new(self.cols.into())),
//                 ("is_real".to_string(), Box::new(self.is_real.into())),
//             ],
//         )
//     }
// }

// impl RTypeReaderInput<ConstraintCompiler>
// {
//     // fn params_vec(
//     //     self,
//     // ) -> Vec<(
//     //     String,
//     //     Shape<ExprRef<<ConstraintCompiler as AirBuilder>::F>,
// ExprExtRef<sp1_hypercube::ir::EF>>,     // )> {
//     //     vec![
//     //         // for demonstration only; not all fields are filled in
//     //         ("clk_high".to_string(), self.clk_high.into()),
//     //         ("op_a_write_value".to_string(), self.op_a_write_value.into()),
//     //     ]
//     // }
//
//     fn to_input(&self, ctx: &mut FuncCtx) -> RTypeReaderInput<ConstraintCompiler> {
//         RTypeReaderInput::new(
//             Expr::input_arg(ctx),
//             Expr::input_arg(ctx),
//             Expr::input_arg(ctx),
//             Expr::input_arg(ctx),
//             Expr::input_from_struct(ctx),
//             Expr::input_from_struct(ctx),
//             Expr::input_arg(ctx),
//         )
//     }
// }
