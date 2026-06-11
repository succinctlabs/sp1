//! APIs for AIRs, and generalizations like PAIRs.
//!
//! Vendored from `p3-air` (0.4.3-succinct) and extended with a third trace
//! group: the *global* trace. Chips read three separate row views —
//! `preprocessed()`, `global()`, and `main()` — via [`PairBuilder`],
//! [`GlobalBuilder`], and [`AirBuilder`] respectively. [`PairCol`] gains a
//! `Global` variant and [`VirtualPairCol::apply`] takes three slices.

mod air;
mod virtual_column;

pub use air::*;
pub use virtual_column::*;
