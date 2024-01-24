pub mod ed_add;
pub mod ed_scalar_mul;

use crate::utils::ec::{AffinePoint, EllipticCurve};
use num::BigUint;
use std::ops::Add;

use crate::precompiles::PrecompileRuntime;

struct EdAddChip;

// TODO: maybe this method should be moved out to a higher-level for all adds
// including secp, etc.
impl EdAddChip {
    pub fn new() -> Self {
        Self {}
    }

    pub fn execute<E: EllipticCurve>(rt: &mut PrecompileRuntime) -> u32 {
        let a0 = crate::runtime::Register::X10;
        let a1 = crate::runtime::Register::X11;

        let start_clk = rt.clk;

        // TODO: these will have to be be constrained, but can do it later.
        let p_ptr = rt.register_unsafe(a0);
        if p_ptr % 4 != 0 {
            panic!();
        }
        let (q_ptr_record, q_ptr) = rt.mr(a1 as u32);
        if q_ptr % 4 != 0 {
            panic!();
        }

        let p = rt.slice_unsafe(p_ptr, 16);
        let (q_records, q) = rt.mr_slice(q_ptr, 16);
        // When we write to p, we want the clk to be incremented.
        rt.clk += 4;

        let p_affine = AffinePoint::<E>::from_words_le(&p);
        let q_affine = AffinePoint::<E>::from_words_le(&q);
        let result_affine = p_affine + q_affine;
        let result_words = result_affine.to_words_le();

        let p_records = rt.mw_slice(p_ptr, result_words);

        // rt.segment_mut().ed_add_events.push(EdAddEvent {
        //     clk: start_clk,
        //     p_ptr,
        //     p,
        //     q_ptr,
        //     q,
        //     q_ptr_record,
        //     p_records,
        //     q_records,
        // });

        p_ptr
    }
}
