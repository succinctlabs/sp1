use std::borrow::BorrowMut;

use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use crate::{
    air::{Bool, Word},
    memory::{MemOp, MemoryEvent},
};

use super::{
    air::{OutputPageCols, PageCols, NUM_OUT_PAGE_COLS, NUM_PAGE_COLS},
    InputPage, OutputPage,
};

pub struct OutputPageTrace<T> {
    pub(crate) page: RowMajorMatrix<T>,
    pub(crate) data: RowMajorMatrix<T>,
}

impl InputPage {
    pub(crate) fn generate_trace<F: Field>(&self, in_events: &[MemoryEvent]) -> RowMajorMatrix<F> {
        let rows = in_events
            .par_iter()
            .flat_map(|event| {
                let mut row = [F::zero(); NUM_PAGE_COLS];

                let cols: &mut PageCols<F> = row.as_mut_slice().borrow_mut();

                cols.addr = Word::from(event.addr);
                cols.value = Word::from(event.value);

                row
            })
            .collect::<Vec<_>>();

        RowMajorMatrix::new(rows, NUM_PAGE_COLS)
    }
}

impl OutputPage {
    pub(crate) fn generate_trace<F: Field>(
        &self,
        out_events: &[MemoryEvent],
    ) -> OutputPageTrace<F> {
        let page_rows = out_events
            .par_iter()
            .flat_map(|event| {
                let mut row = [F::zero(); NUM_PAGE_COLS];

                let cols: &mut PageCols<F> = row.as_mut_slice().borrow_mut();

                cols.addr = Word::from(event.addr);
                cols.value = Word::from(event.value);

                row
            })
            .collect::<Vec<_>>();

        let data_rows = out_events
            .par_iter()
            .flat_map(|event| {
                let mut row = [F::zero(); NUM_OUT_PAGE_COLS];

                let cols: &mut OutputPageCols<F> = row.as_mut_slice().borrow_mut();

                cols.clk = F::from_canonical_u32(event.clk);
                cols.is_read = Bool::from(event.op == MemOp::Read);

                row
            })
            .collect::<Vec<_>>();

        OutputPageTrace {
            page: RowMajorMatrix::new(page_rows, NUM_PAGE_COLS),
            data: RowMajorMatrix::new(data_rows, NUM_OUT_PAGE_COLS),
        }
    }
}
