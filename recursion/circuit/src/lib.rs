#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::explicit_counter_loop)]
#![allow(type_alias_bounds)]

pub mod challenger;
pub mod constraints;
pub mod domain;
pub mod fri;
pub mod mmcs;
pub mod poseidon2;
pub mod stark;
pub mod types;

pub const SPONGE_SIZE: usize = 3;
pub const DIGEST_SIZE: usize = 1;
pub const RATE: usize = 8;
