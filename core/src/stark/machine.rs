use std::marker::PhantomData;

use crate::air::MachineAir;
use crate::runtime::ExecutionRecord;
use crate::runtime::Program;
use crate::runtime::ShardingConfig;
use p3_challenger::CanObserve;
use p3_field::AbstractField;
use p3_field::Field;

use super::Chip;
use super::Proof;
use super::Prover;
use super::RiscvAir;
use super::StarkGenericConfig;
use super::VerificationError;
use super::Verifier;

pub type RiscvChip<SC> =
    Chip<<SC as StarkGenericConfig>::Val, RiscvAir<<SC as StarkGenericConfig>::Val>>;

/// A STARK for proving RISC-V execution.
pub struct RiscvStark<SC: StarkGenericConfig, A = RiscvAir<<SC as StarkGenericConfig>::Val>> {
    /// The STARK settings for the RISC-V STARK.
    config: SC,
    /// The chips that make up the RISC-V STARK machine, in order of their execution.
    chips: Vec<Chip<SC::Val, A>>,
}

#[derive(Debug, Clone)]
pub struct ProvingKey<SC: StarkGenericConfig> {
    //TODO
    marker: std::marker::PhantomData<SC>,
}

#[derive(Debug, Clone)]
pub struct VerifyingKey<SC: StarkGenericConfig> {
    // TODO:
    marker: std::marker::PhantomData<SC>,
}

impl<SC: StarkGenericConfig> RiscvStark<SC> {
    /// Create a new RISC-V STARK machine.
    pub fn new(config: SC) -> Self {
        // The machine consists of a config (input) and a set of chips. The chip vector should
        // contain the chips in the order they are executed. Each chip's air is able to add events
        // to another chip's record (depending on interactions), so we order the chips by keeping
        // track of which chips receive events from which other chips.

        // First, get all the chips associated with this machine.
        let chips = RiscvAir::get_all()
            .into_iter()
            .map(Chip::new)
            .collect::<Vec<_>>();

        Self { config, chips }
    }

    /// Get an array containing a `ChipRef` for all the chips of this RISC-V STARK machine.
    pub fn chips(&self) -> &[RiscvChip<SC>] {
        &self.chips
    }

    pub fn shard_chips<'a, 'b>(
        &'a self,
        shard: &'b ExecutionRecord,
    ) -> impl Iterator<Item = &'b RiscvChip<SC>>
    where
        'a: 'b,
    {
        self.chips.iter().filter(|chip| chip.included(shard))
    }

    /// The setup preprocessing phase.
    ///
    /// Given a program, this function generates the proving and verifying keys. The keys correspond
    /// to the program code and other preprocessed colunms such as lookup tables.
    pub fn setup(&self, _program: &Program) -> (ProvingKey<SC>, VerifyingKey<SC>) {
        (
            ProvingKey {
                marker: PhantomData,
            },
            VerifyingKey {
                marker: PhantomData,
            },
        )
    }

    pub fn shard(
        &self,
        record: &mut ExecutionRecord,
        shard_config: &ShardingConfig,
    ) -> Vec<ExecutionRecord> {
        // Get the local and global chips.
        let chips = self.chips();

        tracing::info!("Generating trace for each chip.");
        // Display the statistics about the workload. This is incomplete because it's run before
        // generate_trace, which can adds events to the record.
        tracing::info!(
            "Record stats before generate_trace (incomplete): {:#?}",
            record.stats()
        );

        // Generate the trace for each chip to collect events emitted from chips with dependencies.
        chips.iter().for_each(|chip| {
            let mut output = ExecutionRecord::default();
            output.index = record.index;
            chip.generate_trace(record, &mut output);
            record.append(&mut output);
        });

        // Display the statistics about the workload after generate_trace.
        tracing::info!("Record stats finalized {:#?}", record.stats());
        tracing::info!("Sharding execution record by chip.");

        // For each chip, shard the events into segments.

        record.shard(shard_config)
    }

    /// Prove the execution record is valid.
    ///
    /// Given a proving key `pk` and a matching execution record `record`, this function generates
    /// a STARK proof that the execution record is valid.
    pub fn prove<P: Prover<SC>>(
        &self,
        pk: &ProvingKey<SC>,
        record: &mut ExecutionRecord,
        challenger: &mut SC::Challenger,
    ) -> Proof<SC> {
        tracing::info!("Sharding the execution record.");
        let shards = self.shard(record, &ShardingConfig::default());

        tracing::info!("Generating the shard proofs.");
        P::prove_shards(self, pk, &shards, challenger)
    }

    pub const fn config(&self) -> &SC {
        &self.config
    }

    pub fn verify(
        &self,
        _vk: &VerifyingKey<SC>,
        proof: &Proof<SC>,
        challenger: &mut SC::Challenger,
    ) -> Result<(), ProgramVerificationError>
    where
        SC::Challenger: Clone,
    {
        // TODO: Observe the challenges in a tree-like structure for easily verifiable reconstruction
        // in a map-reduce recursion setting.
        println!("cycle-tracker-start: observe challenges for all segments");
        #[cfg(feature = "perf")]
        tracing::info_span!("observe challenges for all segments").in_scope(|| {
            proof.shard_proofs.iter().for_each(|proof| {
                challenger.observe(proof.commitment.main_commit.clone());
            });
        });
        println!("cycle-tracker-end: observe challenges for all segments");

        // Verify the segment proofs.
        for (i, proof) in proof.shard_proofs.iter().enumerate() {
            tracing::info_span!("verifying segment", segment = i).in_scope(|| {
                let chips = self
                    .chips()
                    .iter()
                    .filter(|chip| proof.chip_ids.contains(&chip.name()))
                    .collect::<Vec<_>>();
                Verifier::verify_shard(&self.config, &chips, &mut challenger.clone(), proof)
                    .map_err(ProgramVerificationError::InvalidSegmentProof)
            })?;
        }

        // Verify the cumulative sum is 0.
        let mut sum = SC::Challenge::zero();
        #[cfg(feature = "perf")]
        {
            for proof in proof.shard_proofs.iter() {
                sum += proof.cumulative_sum();
            }
        }

        match sum.is_zero() {
            true => Ok(()),
            false => Err(ProgramVerificationError::NonZeroCumulativeSum),
        }
    }
}

#[derive(Debug)]
pub enum ProgramVerificationError {
    InvalidSegmentProof(VerificationError),
    InvalidGlobalProof(VerificationError),
    NonZeroCumulativeSum,
}

#[cfg(test)]
#[allow(non_snake_case)]
pub mod tests {

    use crate::runtime::tests::ecall_lwa_program;
    use crate::runtime::tests::fibonacci_program;
    use crate::runtime::tests::simple_memory_program;
    use crate::runtime::tests::simple_program;
    use crate::runtime::Instruction;
    use crate::runtime::Opcode;
    use crate::runtime::Program;
    use crate::utils;
    use crate::utils::run_test;
    use crate::utils::setup_logger;

    #[test]
    fn test_simple_prove() {
        let program = simple_program();
        run_test(program).unwrap();
    }

    #[test]
    fn test_ecall_lwa_prove() {
        let program = ecall_lwa_program();
        run_test(program).unwrap();
    }

    #[test]
    fn test_shift_prove() {
        let shift_ops = [Opcode::SRL, Opcode::SRA, Opcode::SLL];
        let operands = [
            (1, 1),
            (1234, 5678),
            (0xffff, 0xffff - 1),
            (u32::MAX - 1, u32::MAX),
            (u32::MAX, 0),
        ];
        for shift_op in shift_ops.iter() {
            for op in operands.iter() {
                let instructions = vec![
                    Instruction::new(Opcode::ADD, 29, 0, op.0, false, true),
                    Instruction::new(Opcode::ADD, 30, 0, op.1, false, true),
                    Instruction::new(*shift_op, 31, 29, 3, false, false),
                ];
                let program = Program::new(instructions, 0, 0);
                run_test(program).unwrap();
            }
        }
    }

    #[test]
    fn test_sub_prove() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
            Instruction::new(Opcode::SUB, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test(program).unwrap();
    }

    #[test]
    fn test_add_prove() {
        setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test(program).unwrap();
    }

    #[test]
    fn test_mul_prove() {
        let mul_ops = [Opcode::MUL, Opcode::MULH, Opcode::MULHU, Opcode::MULHSU];
        utils::setup_logger();
        let operands = [
            (1, 1),
            (1234, 5678),
            (8765, 4321),
            (0xffff, 0xffff - 1),
            (u32::MAX - 1, u32::MAX),
        ];
        for mul_op in mul_ops.iter() {
            for operand in operands.iter() {
                let instructions = vec![
                    Instruction::new(Opcode::ADD, 29, 0, operand.0, false, true),
                    Instruction::new(Opcode::ADD, 30, 0, operand.1, false, true),
                    Instruction::new(*mul_op, 31, 30, 29, false, false),
                ];
                let program = Program::new(instructions, 0, 0);
                run_test(program).unwrap();
            }
        }
    }

    #[test]
    fn test_lt_prove() {
        let less_than = [Opcode::SLT, Opcode::SLTU];
        for lt_op in less_than.iter() {
            let instructions = vec![
                Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
                Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
                Instruction::new(*lt_op, 31, 30, 29, false, false),
            ];
            let program = Program::new(instructions, 0, 0);
            run_test(program).unwrap();
        }
    }

    #[test]
    fn test_bitwise_prove() {
        let bitwise_opcodes = [Opcode::XOR, Opcode::OR, Opcode::AND];

        for bitwise_op in bitwise_opcodes.iter() {
            let instructions = vec![
                Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
                Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
                Instruction::new(*bitwise_op, 31, 30, 29, false, false),
            ];
            let program = Program::new(instructions, 0, 0);
            run_test(program).unwrap();
        }
    }

    #[test]
    fn test_divrem_prove() {
        let div_rem_ops = [Opcode::DIV, Opcode::DIVU, Opcode::REM, Opcode::REMU];
        let operands = [
            (1, 1),
            (123, 456 * 789),
            (123 * 456, 789),
            (0xffff * (0xffff - 1), 0xffff),
            (u32::MAX - 5, u32::MAX - 7),
        ];
        for div_rem_op in div_rem_ops.iter() {
            for op in operands.iter() {
                let instructions = vec![
                    Instruction::new(Opcode::ADD, 29, 0, op.0, false, true),
                    Instruction::new(Opcode::ADD, 30, 0, op.1, false, true),
                    Instruction::new(*div_rem_op, 31, 29, 30, false, false),
                ];
                let program = Program::new(instructions, 0, 0);
                run_test(program).unwrap();
            }
        }
    }

    #[test]
    fn test_fibonacci_prove() {
        setup_logger();
        let program = fibonacci_program();
        run_test(program).unwrap();
    }

    #[test]
    fn test_simple_memory_program_prove() {
        let program = simple_memory_program();
        run_test(program).unwrap();
    }
}
