#[derive(Debug, Clone, Copy)]
pub enum RecursionProgramType {
    Core,
    Deferred,
    Compress,
    Shrink,
    Wrap,
}
