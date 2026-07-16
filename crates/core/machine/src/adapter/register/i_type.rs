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

use sp1_primitives::consts::WORD_SIZE;

use crate::{
    air::{
        HostWitnessBuilder, MemoryAirBuilder, ProgramAirBuilder, SP1Operation, WitnessBuilder,
        WordAirBuilder,
    },
    memory::{MemoryAccessWitgenInput, RegisterAccessCols},
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

/// Witgen inputs of [`ITypeReader::witgen`], for nesting inside chip-level
/// witgen-input structs (see `record_witgen_inputs`). Field order IS the packed
/// input layout.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ITypeReaderWitgenInput<T> {
    pub op_a: T,
    pub a: MemoryAccessWitgenInput<T>,
    pub op_b: T,
    pub b: MemoryAccessWitgenInput<T>,
    pub op_c: T,
}

impl ITypeReaderWitgenInput<u64> {
    /// Pack an executor [`ITypeRecord`] into witgen-input form (`op_a`/`op_b` are
    /// register accesses; `op_c` is the immediate).
    pub fn from_record(record: &ITypeRecord) -> Self {
        Self {
            op_a: record.op_a as u64,
            a: MemoryAccessWitgenInput::from_record(record.a),
            op_b: record.op_b,
            b: MemoryAccessWitgenInput::from_record(record.b),
            op_c: record.op_c,
        }
    }
}

// Witgen in an unconstrained `impl<T>` (column type is the builder's `Field`).
impl<T> ITypeReader<T> {
    /// Backend-agnostic witgen: two register reads (`op_a`, `op_b`) and the immediate
    /// `op_c` as a Word. `op_c` is always an immediate here — no register read, no
    /// conditional (cf. the mixed `ALUTypeReader`). Mirrors [`Self::populate`].
    pub fn witgen<WB: WitnessBuilder>(
        wb: &mut WB,
        cols: &mut ITypeReader<WB::Field>,
        input: &ITypeReaderWitgenInput<WB::Nat>,
    ) {
        cols.op_a = wb.nat_to_field(input.op_a);
        RegisterAccessCols::<WB::Field>::witgen(
            wb,
            &mut cols.op_a_memory,
            input.a.prev_value,
            input.a.prev_ts,
            input.a.cur_ts,
        );
        let zero = wb.const_nat(0);
        let a_is_zero = wb.eq(input.op_a, zero);
        cols.op_a_0 = wb.nat_to_field(a_is_zero);
        cols.op_b = wb.nat_to_field(input.op_b);
        RegisterAccessCols::<WB::Field>::witgen(
            wb,
            &mut cols.op_b_memory,
            input.b.prev_value,
            input.b.prev_ts,
            input.b.cur_ts,
        );
        for i in 0..WORD_SIZE {
            let limb = wb.bits(input.op_c, (i as u32) * 16, 16);
            cols.op_c_imm[i] = wb.nat_to_field(limb);
        }
    }
}

impl<F: PrimeField32> ITypeReader<F> {
    pub fn populate(&mut self, blu_events: &mut impl ByteRecord, record: ITypeRecord) {
        let mut wb = HostWitnessBuilder::<F, _>::new(blu_events);
        Self::witgen(&mut wb, self, &ITypeReaderWitgenInput::from_record(&record));
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

impl<T: Copy> ITypeReader<T> {
    pub fn instruction<AB>(&self, opcode: impl Into<AB::Expr> + Clone) -> InstructionCols<AB::Expr>
    where
        AB: SP1AirBuilder<Var = T>,
        T: Into<AB::Expr>,
    {
        InstructionCols {
            opcode: opcode.clone().into(),
            op_a: self.op_a.into(),
            op_b: Word::extend_expr::<AB>(self.op_b.into()),
            op_c: self.op_c_imm.map(Into::into),
            op_a_0: self.op_a_0.into(),
            imm_b: AB::Expr::zero(),
            imm_c: AB::Expr::one(),
        }
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
        op_a_write_value: Word<impl Into<AB::Expr> + Clone>,
        cols: ITypeReader<AB::Var>,
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
        cols: ITypeReader<AB::Var>,
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

#[derive(Clone, Debug)]
pub struct ITypeReaderInput<AB: SP1AirBuilder, T: Into<AB::Expr> + Clone> {
    pub clk_high: AB::Expr,
    pub clk_low: AB::Expr,
    pub pc: [AB::Var; 3],
    pub opcode: T,
    pub op_a_write_value: Word<T>,
    pub cols: ITypeReader<AB::Var>,
    pub is_real: AB::Expr,
    pub is_trusted: AB::Expr,
}

impl<AB: SP1AirBuilder, T: Into<AB::Expr> + Clone> ITypeReaderInput<AB, T> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clk_high: AB::Expr,
        clk_low: AB::Expr,
        pc: [AB::Var; 3],
        opcode: T,
        op_a_write_value: Word<T>,
        cols: ITypeReader<AB::Var>,
        is_real: AB::Expr,
        is_trusted: AB::Expr,
    ) -> Self {
        Self { clk_high, clk_low, pc, opcode, op_a_write_value, cols, is_real, is_trusted }
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
            sp1_hypercube::Word(core::array::from_fn(|_| Expr::input_arg(ctx))),
            Expr::input_from_struct(ctx),
            Expr::input_arg(ctx),
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
            ("op_a_write_value".to_string(), Attribute::default(), self.op_a_write_value.into()),
            ("cols".to_string(), Attribute::default(), self.cols.into()),
            ("is_real".to_string(), Attribute::default(), self.is_real.into()),
            ("is_trusted".to_string(), Attribute::default(), self.is_trusted.into()),
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
            input.op_a_write_value,
            input.cols,
            input.is_real,
            input.is_trusted,
        );
    }
}

#[derive(Clone, Debug)]
pub struct ITypeReaderImmutableInput<AB: SP1AirBuilder, T: Into<AB::Expr> + Clone> {
    pub clk_high: AB::Expr,
    pub clk_low: AB::Expr,
    pub pc: [AB::Var; 3],
    pub opcode: T,
    pub cols: ITypeReader<AB::Var>,
    pub is_real: AB::Expr,
    pub is_trusted: AB::Expr,
}

impl<AB: SP1AirBuilder, T: Into<AB::Expr> + Clone> ITypeReaderImmutableInput<AB, T> {
    pub fn new(
        clk_high: AB::Expr,
        clk_low: AB::Expr,
        pc: [AB::Var; 3],
        opcode: T,
        cols: ITypeReader<AB::Var>,
        is_real: AB::Expr,
        is_trusted: AB::Expr,
    ) -> Self {
        Self { clk_high, clk_low, pc, opcode, cols, is_real, is_trusted }
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
            Expr::input_from_struct(ctx),
            Expr::input_arg(ctx),
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
            ("cols".to_string(), Attribute::default(), self.cols.into()),
            ("is_real".to_string(), Attribute::default(), self.is_real.into()),
            ("is_trusted".to_string(), Attribute::default(), self.is_trusted.into()),
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
            input.cols,
            input.is_real,
            input.is_trusted,
        );
    }
}
