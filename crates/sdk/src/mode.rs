#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Execute,
    Core,
    Compresssed,
    Plonk,
    Groth16,
}

impl Default for Mode {
    fn default() -> Self {
        Self::Groth16
    }
}
