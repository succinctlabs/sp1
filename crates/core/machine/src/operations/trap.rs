use crate::air::MemoryAirBuilder;
#[cfg(feature = "mprotect")]
use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field, PrimeField32};
use sp1_core_executor::{
    events::{ByteRecord, MemoryRecordEnum},
    TrapResult,
};
use sp1_derive::AlignedBorrow;
#[cfg(feature = "mprotect")]
use sp1_hypercube::air::BaseAirBuilder;

use sp1_hypercube::air::SP1AirBuilder;
use sp1_hypercube::Word;
use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::memory::MemoryAccessCols;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy, StructReflection)]
#[repr(C)]
pub struct TrapOperation<T> {
    pub next_pc_reader: MemoryAccessCols<T>,
    pub code_writer: MemoryAccessCols<T>,
    pub pc_writer: MemoryAccessCols<T>,
}

impl<F: PrimeField32> TrapOperation<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, trap_result: TrapResult) {
        self.next_pc_reader.populate(MemoryRecordEnum::Read(trap_result.handler_record), record);
        self.code_writer.populate(MemoryRecordEnum::Write(trap_result.code_record), record);
        self.pc_writer.populate(MemoryRecordEnum::Write(trap_result.pc_record), record);
    }
}

impl<F: Field> TrapOperation<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        cols: TrapOperation<AB::Var>,
        clk_high: AB::Expr,
        clk_low: AB::Expr,
        code: AB::Expr,
        pc: [AB::Expr; 3],
        addresses: [[AB::Var; 3]; 3],
        is_real: AB::Expr,
    ) -> [AB::Var; 3] {
        builder.assert_bool(is_real.clone());
        #[cfg(feature = "mprotect")]
        {
            let public_values = builder.extract_public_values();
            builder.when(is_real.clone()).assert_one(public_values.enable_trap_handler);

            for i in 0..3 {
                builder
                    .when(is_real.clone())
                    .assert_all_eq(public_values.trap_context[i], addresses[i]);
            }
        }
        // Read the `next_pc` value from the memory.
        builder.eval_memory_access_read(
            clk_high.clone(),
            clk_low.clone(),
            &addresses[0].map(Into::into),
            cols.next_pc_reader,
            is_real.clone(),
        );

        // Write the `code` value to the memory.
        // The caller is responsible to ensure that `code` is a valid u16 value.
        builder.eval_memory_access_write(
            clk_high.clone(),
            clk_low.clone(),
            &addresses[1].map(Into::into),
            cols.code_writer,
            Word::extend_expr::<AB>(code.clone()),
            is_real.clone(),
        );

        // Write the `pc` value to the memory.
        // The caller is responsible to ensure that `pc` is valid u16 limbs.
        builder.eval_memory_access_write(
            clk_high.clone(),
            clk_low.clone(),
            &addresses[2].map(Into::into),
            cols.pc_writer,
            Word([pc[0].clone(), pc[1].clone(), pc[2].clone(), AB::Expr::zero()]),
            is_real.clone(),
        );

        [
            cols.next_pc_reader.prev_value[0],
            cols.next_pc_reader.prev_value[1],
            cols.next_pc_reader.prev_value[2],
        ]
    }
}
