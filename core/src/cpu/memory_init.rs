use crate::air::{AirInteraction, CurtaAirBuilder, Word};
use crate::utils::{pad_to_power_of_two, Chip};
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use core::borrow::{Borrow, BorrowMut};
use core::mem::{size_of, transmute};
use p3_air::Air;
use p3_air::AirBuilder;
use p3_air::BaseAir;
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::MatrixRowSlices;
use p3_util::indices_arr;
use valida_derive::AlignedBorrow;

use super::instruction_cols::InstructionCols;
use super::opcode_cols::OpcodeSelectors;
use super::trace::CpuChip;
use crate::runtime::AccessPosition;
use crate::runtime::Segment;

const SEGMENT_MAX: u32 = 100_000;

pub struct MemoryInitChip {
    init: bool,
}

impl<F: PrimeField> Chip<F> for MemoryInitChip {
    fn name(&self) -> String {
        "MemoryInit".to_string()
    }

    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        let rows = segment
            .memory_access
            .iter() // TODO: change this back to par_iter
            .map(|(addr, val)| {
                let mut row = [F::zero(); NUM_MEMORY_INIT_COLS];
                let cols: &mut MemoryInitCols<F> = unsafe { transmute(&mut row) };
                cols.addr = F::from_canonical_u32(*addr);
                cols.value = if self.init {
                    0u32.into()
                } else {
                    (*val).into()
                };
                cols.is_real = F::one();
                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_INIT_COLS,
        );

        pad_to_power_of_two::<NUM_MEMORY_INIT_COLS, F>(&mut trace.values);

        trace
    }
}

#[derive(AlignedBorrow, Default, Debug)]
#[repr(C)]
pub struct MemoryInitCols<T> {
    pub addr: T,
    pub value: Word<T>,
    pub is_real: T,
}

pub(crate) const NUM_MEMORY_INIT_COLS: usize = size_of::<MemoryInitCols<u8>>();
pub(crate) const MEMORY_INIT_COL_MAP: MemoryInitCols<usize> = make_col_map();

const fn make_col_map() -> MemoryInitCols<usize> {
    let indices_arr = indices_arr::<NUM_MEMORY_INIT_COLS>();
    unsafe { transmute::<[usize; NUM_MEMORY_INIT_COLS], MemoryInitCols<usize>>(indices_arr) }
}

impl<F> BaseAir<F> for MemoryInitChip {
    fn width(&self) -> usize {
        NUM_MEMORY_INIT_COLS
    }
}

impl<AB> Air<AB> for MemoryInitChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &MemoryInitCols<AB::Var> = main.row_slice(0).borrow();

        // Dummy constraint of degree 3.
        builder.assert_eq(
            local.is_real * local.is_real * local.is_real,
            local.is_real * local.is_real * local.is_real,
        );

        if self.init {
            let mut values = vec![AB::Expr::zero(), AB::Expr::zero(), local.addr.into()];
            values.extend(local.value.map(Into::into));
            builder.receive(AirInteraction::new(
                values,
                local.is_real.into(),
                crate::lookup::InteractionKind::Memory,
            ));
        } else {
            let mut values: Vec<<AB as AirBuilder>::Expr> = vec![
                AB::Expr::from_canonical_u32(SEGMENT_MAX),
                AB::Expr::zero(),
                local.addr.into(),
            ];
            values.extend(local.value.map(Into::into));
            builder.send(AirInteraction::new(
                values,
                local.is_real.into(),
                crate::lookup::InteractionKind::Memory,
            ));
        }
    }
}
