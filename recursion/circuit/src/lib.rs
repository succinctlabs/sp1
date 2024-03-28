#![allow(clippy::type_complexity)]
#![allow(clippy::needless_range_loop)]

pub mod challenger;
pub mod fri;
pub mod poseidon2;

pub const SPONGE_SIZE: usize = 3;
pub const DIGEST_SIZE: usize = 1;
