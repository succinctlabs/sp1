/// An execution trace to be proved in a single ZK proof.
///
/// A segment consists of a program, initial values for memory, and the execution trace
/// of the program which is run to a specific number of cycles. Segmemts contain data that allows
/// them to be connected to other segments, and to be verified in a batch.
pub struct Segment;
