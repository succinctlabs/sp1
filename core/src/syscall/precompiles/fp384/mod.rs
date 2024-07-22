mod fp;

use std::{
    marker::PhantomData,
    mem::transmute,
    ops::{Add, Mul, Neg, Sub},
};

pub use fp::*;
