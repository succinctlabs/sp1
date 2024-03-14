use core::marker::PhantomData;

use alloc::{format, string::String};

#[derive(Debug, Clone, Copy)]
pub struct Var<N>(pub u32, pub PhantomData<N>);

#[derive(Debug, Clone, Copy)]
pub struct Felt<F>(pub u32, pub PhantomData<F>);

#[derive(Debug, Clone, Copy)]

pub struct Ext<F, EF>(pub u32, pub PhantomData<(F, EF)>);

#[derive(Debug, Clone, Copy)]

pub enum Usize<N> {
    Const(usize),
    Var(Var<N>),
}

impl<N> Usize<N> {
    pub fn value(&self) -> usize {
        match self {
            Usize::Const(c) => *c,
            Usize::Var(_) => panic!("Cannot get the value of a variable"),
        }
    }
}

impl<N> From<Var<N>> for Usize<N> {
    fn from(v: Var<N>) -> Self {
        Usize::Var(v)
    }
}

impl<N> From<usize> for Usize<N> {
    fn from(c: usize) -> Self {
        Usize::Const(c)
    }
}

impl<N> Var<N> {
    pub fn new(id: u32) -> Self {
        Self(id, PhantomData)
    }

    pub fn id(&self) -> String {
        format!("var{}", self.0)
    }
}

impl<F> Felt<F> {
    pub fn new(id: u32) -> Self {
        Self(id, PhantomData)
    }

    pub fn id(&self) -> String {
        format!("felt{}", self.0)
    }
}

impl<F, EF> Ext<F, EF> {
    pub fn new(id: u32) -> Self {
        Self(id, PhantomData)
    }

    pub fn id(&self) -> String {
        format!("ext{}", self.0)
    }
}
