use super::Store;

/// A simple store representing a function with no internal state and no co-processors.
pub struct FunctionStore<T> {
    pub memory: Vec<T>,
    pub inputs: Vec<T>,
    pub outputs: Vec<T>,
}

impl<T> Store for FunctionStore<T> {}

impl<T> FunctionStore<T> {
    pub fn new(inputs: Vec<T>) -> Self {
        Self {
            memory: vec![],
            inputs,
            outputs: vec![],
        }
    }
}
