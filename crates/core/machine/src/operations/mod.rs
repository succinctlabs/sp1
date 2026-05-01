//! Operations implement common operations on sets of columns.
//!
//! They should always implement aim to implement `populate` and `eval` methods. The `populate`
//! method is used to populate the columns with values, while the `eval` method is used to evaluate
//! the constraints.

mod add;
mod add4;
mod add5;
mod add_u32;
mod address;
mod addrs_add;
mod addw;
mod and_u32;
mod bitwise;
mod bitwise_u16;
mod clk;
pub mod field;
mod fixed_rotate_right;
mod fixed_shift_right;
mod global_accumulation;
mod global_interaction;
mod is_equal_word;
mod is_zero;
mod is_zero_word;
mod msb;
mod mul;
mod not_u32;
mod page;
mod slt;
mod sp1_field_word;
mod sub;
mod subw;
mod syscall_addr;
mod trap;
mod u16_compare;
mod u16_operation;
mod u32_operation;
mod xor_u32;

pub use add::*;
pub use add4::*;
pub use add5::*;
pub use add_u32::*;
pub use address::*;
pub use addrs_add::*;
pub use addw::*;
pub use and_u32::*;
pub use bitwise::*;
pub use bitwise_u16::*;
pub use clk::*;
pub use fixed_rotate_right::*;
pub use fixed_shift_right::*;
pub use global_accumulation::*;
pub use global_interaction::*;
pub use is_equal_word::*;
pub use is_zero::*;
pub use is_zero_word::*;
pub use msb::*;
pub use mul::*;
pub use not_u32::*;
pub use page::*;
pub use slt::*;
pub use sp1_field_word::*;
pub use sub::*;
pub use subw::*;
pub use syscall_addr::*;
pub use trap::*;
pub use u16_compare::*;
pub use u16_operation::*;
pub use u32_operation::*;
pub use xor_u32::*;
