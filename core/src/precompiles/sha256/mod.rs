
use crate::air::{AirInteraction, CurtaAirBuilder, Word};
use crate::cpu::air::MemoryAccessCols;
use crate::utils::{pad_to_power_of_two, Chip};
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use core::borrow::{Borrow, BorrowMut};
use core::mem::{size_of, transmute};
use p3_air::Air;
use p3_air::BaseAir;
use p3_field::AbstractField;
use p3_matrix::MatrixRowSlices;
use p3_util::indices_arr;
use valida_derive::AlignedBorrow;

use crate::runtime::{Segment, AccessPosition};

pub struct ShaChip {
}

impl ShaChip {
    pub fn new() -> Self {
        Self{}
    }
}

impl<F> BaseAir<F> for ShaChip {
    fn width(&self) -> usize {
        NUM_MEMORY_INIT_COLS
    }
}

impl<F: PrimeField> Chip<F> for ShaChip {
    fn name(&self) -> String {
        "Sha".to_string()
    }

    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        todo!();
    }
}

#[derive(AlignedBorrow, Default, Debug)]
#[repr(C)]
pub struct ShaPreprocessCols<T> {
    pub i: T, // cycle = 16...64
    pub segment: T,
    pub clk: T, // The clk cycle to start the process 
    pub w_ptr: T, // Assuming that w[0...16] is filled in appropriately already with the chunk
    pub w_i: Word<T>, // This is a write.
    pub w_i_minus_15: Word<T>, // All of these are reads.
    pub w_i_minus_2: Word<T>,
    pub w_i_minus_16: Word<T>,
    pub w_i_minus_7: Word<T>,
    pub w_i_minus_15_rr_7: Word<T>,
    pub w_i_minus_15_rr_18: Word<T>,    
    pub w_i_minus_15_rs_3: Word<T>,
    pub w_i_minus_15_rr_7_xor_w_i_minus_15_rr_18: Word<T>,
    pub s0: Word<T>,
    pub w_i_minus_2_rr_17: Word<T>,
    pub w_i_minus_2_rr_19: Word<T>,
    pub w_i_minus_2_rs_10: Word<T>,
    pub w_i_minus_2_rr_17_xor_w_i_minus_2_rr_19: Word<T>,
    pub s1: Word<T>,
    pub w_i_minus_16_plus_s0: Word<T>,
    pub w_i_minus_7_plus_s1: Word<T>,
}

impl<AB> Air<AB> for MemoryInitChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &ShaPreprocessCols<AB::Var> = main.row_slice(0).borrow();

        // Dummy constraint of degree 3.
        builder.assert_eq(
            local.is_real * local.is_real * local.is_real,
            local.is_real * local.is_real * local.is_real,
        );

        // pub prev_value: Word<T>,
        // // The previous segment and timestamp that this memory access is being read from.
        // pub segment: T,
        // pub timestamp: T,

        builder.constraint_memory_access(
            local.segment, local.clk, local.w_ptr + local.i, 
            MemoryAccessCols{value: w_i, prev_value: w_i, }, 

            multiplicity
        );

    }
}

impl<F: PrimeField> Chip<F> for MemoryInitChip {
    fn name(&self) -> String {
        "ShaPreprocess".to_string()
    }

    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        for i in 16..64 {
            let addr = segment.memory.
            segment.memory.mr(add + i, AccessPosition::Precompile)
            let w_i_minus_15 = MemoryRecord{}
        }
        let rows = (0..len) // TODO: change this back to par_iter
            .map(|i| {
                let (addr, record) = if self.init {
                    segment.first_memory_record[i]
                } else {
                    segment.last_memory_record[i]
                };
                let mut row = [F::zero(); NUM_MEMORY_INIT_COLS];
                let cols: &mut MemoryInitCols<F> = unsafe { transmute(&mut row) };
                cols.addr = F::from_canonical_u32(addr);
                cols.segment = F::from_canonical_u32(record.segment);
                cols.timestamp = F::from_canonical_u32(record.timestamp);
                cols.value = record.value.into();
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
pub struct ShaCompressCols<T> {
    pub i: T, // cycle 0...64
    pub w_ptr: T,
    pub w_i: Word<T>,
    pub a: Word<T>,
    pub b: Word<T>,
    pub c: Word<T>,
    pub d: Word<T>,
    pub e: Word<T>,
    pub f: Word<T>,
    pub g: Word<T>,
    pub h: Word<T>,
    pub e_rr_6: Word<T>,
    pub e_rr_11: Word<T>,
    pub e_rr_25: Word<T>,
    pub e_rr_6_xor_e_rr_11: Word<T>,
    pub S1: Word<T>,
    pub e_and_f: Word<T>,
    pub not_e: Word<T>,
    pub not_e_and_g: Word<T>,
    pub ch: Word<T>,
    pub h_plus_S1: Word<T>,
    pub k_i_plus_w_i: Word<T>,
    pub h_plus_S1_plus_ch: Word<T>,
    pub temp1: Word<T>,
    pub a_rr_2: Word<T>,
    pub a_rr_13: Word<T>,
    pub a_rr_22: Word<T>,
    pub a_rr_2_xor_a_rr_13: Word<T>,
    pub S0: Word<T>,
    pub a_and_b: Word<T>,
    pub a_and_c: Word<T>,
    pub b_and_c: Word<T>,
    pub a_and_b_xor_a_and_c: Word<T>,
    pub maj: Word<T>,
    pub temp2: Word<T>,
    pub d_plus_temp2: Word<T>,
    pub temp1_plus_temp2: Word<T>
}

pub(crate) const NUM_SHA_COLS: usize = size_of::<ShaPreprocessCols<u8>>();
#[allow(dead_code)]
pub(crate) const SHA_COL_MAP: ShaCols<usize> = make_col_map();

const fn make_col_map() -> ShaCols<usize> {
    let indices_arr = indices_arr::<NUM_SHA_COLS>();
    unsafe { transmute::<[usize; NUM_SHA_COLS], ShaCols<usize>>(indices_arr) }
}


// // create a Sha256 object
// let mut hasher = Sha256::new();

// // write input message
// hasher.update(b"hello world");

// // read hash digest and consume hasher
// let result = hasher.finalize();

// chunk_oracle



// chunk_ptr (i.e. block)
// w_ptr
// digest_ptr

// cpy w_ptr[0...15] = chunk[:]


// fn sha() -> *

round chunk_ptr digest_ptr   w
0       100       102        w[0] = connect(chunk_ptr + round)
1
2
3
4
5


base_clk
round 
chunk_ptr
digest_ptr
a
b
...
S1
ch
temp1
S0
maj
temp2 
w_i -> 
w_i_minus_15
w_i_minus_2
w_i_minus_7
w_i_minus_16
