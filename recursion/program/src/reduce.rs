//! ReduceProgram defines a recursive program that can reduce a set of proofs into a single proof.
//!
//! Specifically, this program takes in an ordered list of proofs where each proof can be either an
//! SP1 Core proof or a recursive VM proof of itself. Each proof is verified and then checked to
//! ensure that each transition is valid. Finally, the overall start and end values are committed to.
//!
//! Because SP1 uses a global challenger system, `verify_start_challenger` is witnessed and used to
//! verify each core proof. As each core proof is verified, its commitment and public values are
//! observed into `reconstruct_challenger`. After recursively reducing down to one proof,
//! `reconstruct_challenger` must equal `verify_start_challenger`.
//!
//! "Deferred proofs" can also be passed in and verified. These are fully reduced proofs that were
//! committed to within the core VM. These proofs can then be verified here and then reconstructed
//! into a single digest which is checked against what was committed. Note that it is possible for
//! reduce to be called with only deferred proofs, and not any core/recursive proofs. In this case,
//! the start and end pc/shard values should be equal to each other.
//!
//! Because the program can verify ranges of a full SP1 proof, the program exposes `is_complete`
//! which is only 1 if the program has fully verified the execution of the program, including all
//! deferred proofs.
