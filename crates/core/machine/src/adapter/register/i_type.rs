use slop_air::{AirBuilder, ExtensionBuilder};
use slop_algebra::{AbstractField, Field, PrimeField32};
use sp1_core_executor::{
    events::{ByteRecord, MemoryAccessPosition},
    ITypeRecord,
};
use sp1_derive::{AlignedBorrow, IntoShape, SP1OperationBuilder};

use sp1_hypercube::{
    air::SP1AirBuilder,
    ir::{Attribute, ConstraintCompiler, FuncCtx, Shape},
    Word,
};
use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::{
    air::{MemoryAirBuilder, ProgramAirBuilder, SP1Operation, WordAirBuilder},
    memory::RegisterAccessCols,
    program::instruction::InstructionCols,
};

/// A set of columns to read operations with op_a and op_b being registers and op_c being an
/// immediate.
#[derive(
    AlignedBorrow, Default, Debug, Clone, Copy, IntoShape, SP1OperationBuilder, StructReflection,
)]
#[repr(C)]
pub struct ITypeReader<T> {
    pub op_a: T,
    pub op_a_memory: RegisterAccessCols<T>,
    pub op_a_0: T,
    pub op_b: T,
    pub op_b_memory: RegisterAccessCols<T>,
    pub op_c_imm: Word<T>,
}

impl<F: PrimeField32> ITypeReader<F> {
    pub fn populate(&mut self, blu_events: &mut impl ByteRecord, record: ITypeRecord) {
        self.op_a = F::from_canonical_u8(record.op_a);
        self.op_a_memory.populate(record.a, blu_events);
        self.op_a_0 = F::from_bool(record.op_a == 0);
        self.op_b = F::from_canonical_u64(record.op_b);
        self.op_b_memory.populate(record.b, blu_events);
        self.op_c_imm = Word::from(record.op_c);
    }
}

impl<T> ITypeReader<T> {
    pub fn prev_a(&self) -> &Word<T> {
        &self.op_a_memory.prev_value
    }

    pub fn b(&self) -> &Word<T> {
        &self.op_b_memory.prev_value
    }

    pub fn c(&self) -> &Word<T> {
        &self.op_c_imm
    }
}

impl<F: Field> ITypeReader<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn eval<AB: SP1AirBuilder + ProgramAirBuilder + MemoryAirBuilder>(
        builder: &mut AB,
        clk_high: AB::Expr,
        clk_low: AB::Expr,
        pc: [AB::Var; 3],
        opcode: impl Into<AB::Expr> + Clone,
        _instr_field_consts: [AB::Expr; 4],
        op_a_write_value: Word<impl Into<AB::Expr> + Clone>,
        cols: ITypeReader<AB::Var>,
        is_real: AB::Expr,
    ) {
        builder.assert_bool(is_real.clone());

        let instruction = InstructionCols {
            opcode: opcode.clone().into(),
            op_a: cols.op_a.into(),
            op_b: Word::extend_expr::<AB>(cols.op_b.into()),
            op_c: cols.op_c_imm.map(Into::into),
            op_a_0: cols.op_a_0.into(),
            imm_b: AB::Expr::zero(),
            imm_c: AB::Expr::one(),
        };

        builder.send_program(pc, instruction.clone(), is_real.clone());

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
            is_real,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_op_a_immutable<AB: SP1AirBuilder + ProgramAirBuilder + MemoryAirBuilder>(
        builder: &mut AB,
        clk_high: AB::Expr,
        clk_low: AB::Expr,
        pc: [AB::Var; 3],
        opcode: impl Into<AB::Expr> + Clone,
        instr_field_consts: [AB::Expr; 4],
        cols: ITypeReader<AB::Var>,
        is_real: AB::Expr,
    ) {
        Self::eval(
            builder,
            clk_high,
            clk_low,
            pc,
            opcode,
            instr_field_consts,
            cols.op_a_memory.prev_value,
            cols,
            is_real,
        );
    }
}

#[derive(Clone, Debug)]
pub struct ITypeReaderInput<AB: SP1AirBuilder, T: Into<AB::Expr> + Clone> {
    pub clk_high: AB::Expr,
    pub clk_low: AB::Expr,
    pub pc: [AB::Var; 3],
    pub opcode: T,
    pub instr_field_consts: [AB::Expr; 4],
    pub op_a_write_value: Word<T>,
    pub cols: ITypeReader<AB::Var>,
    pub is_real: AB::Expr,
}

impl<AB: SP1AirBuilder, T: Into<AB::Expr> + Clone> ITypeReaderInput<AB, T> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clk_high: AB::Expr,
        clk_low: AB::Expr,
        pc: [AB::Var; 3],
        opcode: T,
        instr_field_consts: [AB::Expr; 4],
        op_a_write_value: Word<T>,
        cols: ITypeReader<AB::Var>,
        is_real: AB::Expr,
    ) -> Self {
        Self { clk_high, clk_low, pc, opcode, instr_field_consts, op_a_write_value, cols, is_real }
    }
}

// TODO(gzgz): generate from macros
impl ITypeReaderInput<ConstraintCompiler, <ConstraintCompiler as AirBuilder>::Expr> {
    fn to_input(
        &self,
        ctx: &mut FuncCtx,
    ) -> ITypeReaderInput<ConstraintCompiler, <ConstraintCompiler as AirBuilder>::Expr> {
        type Expr = <ConstraintCompiler as AirBuilder>::Expr;

        ITypeReaderInput::new(
            Expr::input_arg(ctx),
            Expr::input_arg(ctx),
            core::array::from_fn(|_| Expr::input_arg(ctx)),
            Expr::input_arg(ctx),
            core::array::from_fn(|_| Expr::input_arg(ctx)),
            Expr::input_from_struct(ctx),
            Expr::input_from_struct(ctx),
            Expr::input_arg(ctx),
        )
    }
}

// TODO(gzgz): generate from macros
impl<T: Into<<ConstraintCompiler as AirBuilder>::Expr> + Clone>
    ITypeReaderInput<ConstraintCompiler, T>
{
    fn params_vec(
        self,
    ) -> Vec<(
        String,
        Attribute,
        Shape<
            <ConstraintCompiler as AirBuilder>::Expr,
            <ConstraintCompiler as ExtensionBuilder>::ExprEF,
        >,
    )> {
        vec![
            ("clk_high".to_string(), Attribute::default(), self.clk_high.into()),
            ("clk_low".to_string(), Attribute::default(), self.clk_low.into()),
            ("pc".to_string(), Attribute::default(), self.pc.into()),
            ("opcode".to_string(), Attribute::default(), self.opcode.into().into()),
            (
                "instr_field_consts".to_string(),
                Attribute::default(),
                self.instr_field_consts.into(),
            ),
            ("op_a_write_value".to_string(), Attribute::default(), self.op_a_write_value.into()),
            ("cols".to_string(), Attribute::default(), self.cols.into()),
            ("is_real".to_string(), Attribute::default(), self.is_real.into()),
        ]
    }
}

impl<AB: SP1AirBuilder> SP1Operation<AB> for ITypeReader<AB::F> {
    type Input = ITypeReaderInput<AB, AB::Expr>;

    type Output = ();

    fn lower(builder: &mut AB, input: Self::Input) -> Self::Output {
        Self::eval(
            builder,
            input.clk_high,
            input.clk_low,
            input.pc,
            input.opcode,
            input.instr_field_consts,
            input.op_a_write_value,
            input.cols,
            input.is_real,
        );
    }
}

#[derive(Clone, Debug)]
pub struct ITypeReaderImmutableInput<AB: SP1AirBuilder, T: Into<AB::Expr> + Clone> {
    pub clk_high: AB::Expr,
    pub clk_low: AB::Expr,
    pub pc: [AB::Var; 3],
    pub opcode: T,
    pub instr_field_consts: [AB::Expr; 4],
    pub cols: ITypeReader<AB::Var>,
    pub is_real: AB::Expr,
}

impl<AB: SP1AirBuilder, T: Into<AB::Expr> + Clone> ITypeReaderImmutableInput<AB, T> {
    pub fn new(
        clk_high: AB::Expr,
        clk_low: AB::Expr,
        pc: [AB::Var; 3],
        opcode: T,
        instr_field_consts: [AB::Expr; 4],
        cols: ITypeReader<AB::Var>,
        is_real: AB::Expr,
    ) -> Self {
        Self { clk_high, clk_low, pc, opcode, instr_field_consts, cols, is_real }
    }
}

#[derive(Debug, Clone, SP1OperationBuilder)]
pub struct ITypeReaderImmutable;

// TODO(gzgz): generate from macros
impl ITypeReaderImmutableInput<ConstraintCompiler, <ConstraintCompiler as AirBuilder>::Expr> {
    fn to_input(
        &self,
        ctx: &mut FuncCtx,
    ) -> ITypeReaderImmutableInput<ConstraintCompiler, <ConstraintCompiler as AirBuilder>::Expr>
    {
        type Expr = <ConstraintCompiler as AirBuilder>::Expr;

        ITypeReaderImmutableInput::new(
            Expr::input_arg(ctx),
            Expr::input_arg(ctx),
            core::array::from_fn(|_| Expr::input_arg(ctx)),
            Expr::input_arg(ctx),
            core::array::from_fn(|_| Expr::input_arg(ctx)),
            Expr::input_from_struct(ctx),
            Expr::input_arg(ctx),
        )
    }
}

// TODO(gzgz): generate from macros
impl<T: Into<<ConstraintCompiler as AirBuilder>::Expr> + Clone>
    ITypeReaderImmutableInput<ConstraintCompiler, T>
{
    fn params_vec(
        self,
    ) -> Vec<(
        String,
        Attribute,
        Shape<
            <ConstraintCompiler as AirBuilder>::Expr,
            <ConstraintCompiler as ExtensionBuilder>::ExprEF,
        >,
    )> {
        vec![
            ("clk_high".to_string(), Attribute::default(), self.clk_high.into()),
            ("clk_low".to_string(), Attribute::default(), self.clk_low.into()),
            ("pc".to_string(), Attribute::default(), self.pc.into()),
            ("opcode".to_string(), Attribute::default(), self.opcode.into().into()),
            (
                "instr_field_consts".to_string(),
                Attribute::default(),
                self.instr_field_consts.into(),
            ),
            ("cols".to_string(), Attribute::default(), self.cols.into()),
            ("is_real".to_string(), Attribute::default(), self.is_real.into()),
        ]
    }
}

impl<AB: SP1AirBuilder> SP1Operation<AB> for ITypeReaderImmutable {
    type Input = ITypeReaderImmutableInput<AB, AB::Expr>;
    type Output = ();

    fn lower(builder: &mut AB, input: Self::Input) -> Self::Output {
        ITypeReader::<AB::F>::eval_op_a_immutable(
            builder,
            input.clk_high,
            input.clk_low,
            input.pc,
            input.opcode,
            input.instr_field_consts,
            input.cols,
            input.is_real,
        );
    }
}
