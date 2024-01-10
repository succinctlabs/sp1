//! Operations implement common operations on sets of columns.
//!
//! They should always implement aim to implement `populate` and `eval` methods. The `populate`
//! method is used to populate the columns with values, while the `eval` method is used to evaluate
//! the constraints.

mod add4;
mod fixed_rotate_right;
mod fixed_shift_right;
mod xor3;

pub use add4::*;
pub use fixed_rotate_right::*;
pub use fixed_shift_right::*;
pub use xor3::*;
