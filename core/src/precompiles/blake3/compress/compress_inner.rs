use core::borrow::Borrow;
use core::borrow::BorrowMut;
use flate2::Compress;
use num::integer::Roots;
use p3_air::AirBuilder;
use p3_field::AbstractField;
use p3_field::Field;

use std::mem::size_of;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;

pub const NUM_COMPRESS_INNER_COLS: usize = size_of::<CompressInnerOperation<u8>>();

use super::round::RoundOperation;
/// A set of columns needed to compute the `add_rc` of the input state.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct CompressInnerOperation<T> {
    pub something: T,
}
