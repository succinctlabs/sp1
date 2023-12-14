use core::mem::transmute;

use p3_air::VirtualPairCol;
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSlice;

use crate::air::Bool;
use crate::air::Word;
use crate::lookup::Interaction;
use crate::memory::air::MemoryCols;
use crate::memory::air::MEM_COL;
use crate::memory::air::NUM_MEMORY_COLS;
use crate::memory::MemOp;
use crate::memory::MemoryInteraction;
use crate::utils::Chip;
use crate::Runtime;

use super::{air::MemoryAir, MemoryEvent};

const fn dummy_events(clk: u32) -> (MemoryEvent, MemoryEvent) {
    (
        MemoryEvent {
            clk,
            addr: u32::MAX,
            value: 0,
            op: MemOp::Write,
        },
        MemoryEvent {
            clk: clk + 1,
            addr: u32::MAX,
            value: 0,
            op: MemOp::Read,
        },
    )
}

impl<F: PrimeField> Chip<F> for MemoryAir {
    // TODO: missing STLU events.
    fn generate_trace(&self, runtime: &mut crate::Runtime) -> RowMajorMatrix<F> {
        let Runtime { memory_events, .. } = runtime;
        Self::generate_trace(memory_events)
    }

    fn receives(&self) -> Vec<Interaction<F>> {
        // Memory chip accepts all the memory requests
        vec![MemoryInteraction::new(
            VirtualPairCol::single_main(MEM_COL.clk),
            MEM_COL.addr.map(VirtualPairCol::single_main),
            MEM_COL.value.map(VirtualPairCol::single_main),
            VirtualPairCol::single_main(MEM_COL.multiplicity),
            VirtualPairCol::single_main(MEM_COL.is_read.0),
        )
        .into()]
    }

    fn sends(&self) -> Vec<Interaction<F>> {
        todo!()
    }
}

impl MemoryAir {
    pub fn generate_trace<F: PrimeField>(events: &[MemoryEvent]) -> RowMajorMatrix<F> {
        let mut events = events.to_vec();
        // Sort the events by address and then by clock cycle.
        events.sort_by_key(|event| (event.addr, event.clk, event.op));

        // Collect events by making a vector of unique values and multiplicities.
        let mut unique_events = Vec::new();
        let mut multiplicities = Vec::new();
        let mut last_event = None;
        for event in events.into_iter() {
            if Some(event) == last_event {
                *multiplicities.last_mut().unwrap() += 1;
            } else {
                unique_events.push(event);
                multiplicities.push(1);
            }
            last_event = Some(event);
        }

        let mut next_events = unique_events[1..].to_vec();

        assert_eq!(unique_events.len(), multiplicities.len());
        assert_eq!(unique_events.len(), next_events.len() + 1);

        // // Pad to a power of two.
        let pad_len = unique_events.len().next_power_of_two();
        if pad_len > unique_events.len() {
            let (write_dummy, read_dummy) = dummy_events(unique_events.last().unwrap().clk + 1);
            unique_events.push(write_dummy);
            next_events.push(write_dummy);
            unique_events.resize(pad_len, read_dummy);
            next_events.resize(pad_len, read_dummy);
            multiplicities.resize(pad_len, 0);
        }

        let first_event = MemoryEvent {
            clk: 0,
            addr: 0,
            value: 0,
            op: MemOp::Read,
        };
        unique_events.insert(0, first_event);

        // Create the trace.
        let rows = unique_events
            .par_windows(2)
            .zip(multiplicities.par_iter())
            .flat_map(|(window, mult)| {
                let (prev, curr) = (window[0], window[1]);
                let mut row = [F::zero(); NUM_MEMORY_COLS];
                let cols: &mut MemoryCols<F> = unsafe { transmute(&mut row) };

                cols.clk = F::from_canonical_u32(curr.clk);
                cols.clk_word = Word::from(curr.clk);
                cols.addr = Word::from(curr.addr);
                cols.value = Word::from(curr.value);
                cols.is_read = Bool::from(curr.op == MemOp::Read);
                cols.multiplicity = F::from_canonical_u32(*mult as u32);

                cols.prev_addr = Word::from(prev.addr);
                cols.prev_clk_word = Word::from(prev.clk);

                cols.is_addr_eq = Bool::from(prev.addr == curr.addr);
                cols.is_addr_lt = Bool::from(prev.addr < curr.addr);
                cols.is_clk_eq = Bool::from(prev.clk == curr.clk);
                cols.is_clk_lt = Bool::from(prev.clk < curr.clk);
                cols.is_checked = Bool::from(curr.op == MemOp::Read && curr.addr == prev.addr);

                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows, NUM_MEMORY_COLS)
    }
}
