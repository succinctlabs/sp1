use std::marker::PhantomData;

use super::debug_constraints;
use crate::air::MachineAir;
use crate::lookup::debug_interactions_with_all_chips;
use crate::lookup::InteractionBuilder;
use crate::lookup::InteractionKind;
use crate::stark::record::MachineRecord;
use crate::stark::DebugConstraintBuilder;
use crate::stark::ProverConstraintFolder;
use crate::stark::VerifierConstraintFolder;
use p3_air::Air;
use p3_challenger::CanObserve;
use p3_challenger::FieldChallenger;
use p3_field::AbstractField;
use p3_field::Field;
use p3_field::PrimeField32;
use p3_matrix::Matrix;
use p3_matrix::MatrixRowSlices;
use p3_maybe_rayon::prelude::*;

use sp1_zkvm::PI_DIGEST_WORD_SIZE;

use super::Chip;
use super::Proof;
use super::Prover;
use super::StarkGenericConfig;
use super::Val;
use super::VerificationError;
use super::Verifier;

pub type MachineChip<SC, A> = Chip<Val<SC>, A>;

/// A STARK for proving RISC-V execution.
pub struct MachineStark<SC: StarkGenericConfig, A> {
    /// The STARK settings for the RISC-V STARK.
    config: SC,
    /// The chips that make up the RISC-V STARK machine, in order of their execution.
    chips: Vec<Chip<Val<SC>, A>>,
}

impl<SC: StarkGenericConfig, A> MachineStark<SC, A> {
    pub fn new(config: SC, chips: Vec<Chip<Val<SC>, A>>) -> Self {
        Self { config, chips }
    }
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

impl<SC: StarkGenericConfig, A: MachineAir<Val<SC>>> MachineStark<SC, A> {
    /// Get an array containing a `ChipRef` for all the chips of this RISC-V STARK machine.
    pub fn chips(&self) -> &[MachineChip<SC, A>] {
        &self.chips
    }

    pub fn shard_chips<'a, 'b>(
        &'a self,
        shard: &'b A::Record,
    ) -> impl Iterator<Item = &'b MachineChip<SC, A>>
    where
        'a: 'b,
    {
        self.chips.iter().filter(|chip| chip.included(shard))
    }

    /// The setup preprocessing phase.
    ///
    /// Given a program, this function generates the proving and verifying keys. The keys correspond
    /// to the program code and other preprocessed colunms such as lookup tables.
    pub fn setup<P>(&self, _program: &P) -> (ProvingKey<SC>, VerifyingKey<SC>) {
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
        mut record: A::Record,
        config: &<A::Record as MachineRecord>::Config,
    ) -> Vec<A::Record> {
        // Get the local and global chips.
        let chips = self.chips();

        // Generate the trace for each chip to collect events emitted from chips with dependencies.
        chips.iter().for_each(|chip| {
            let mut output = A::Record::default();
            output.set_index(record.index());
            chip.generate_dependencies(&record, &mut output);
            record.append(&mut output);
        });

        // Display some statistics about the workload.
        let stats = record.stats();
        for (k, v) in stats {
            log::info!("{} = {}", k, v);
        }

        // For each chip, shard the events into segments.
        record.shard(config)
    }

    /// Prove the execution record is valid.
    ///
    /// Given a proving key `pk` and a matching execution record `record`, this function generates
    /// a STARK proof that the execution record is valid.
    pub fn prove<P: Prover<SC, A>>(
        &self,
        pk: &ProvingKey<SC>,
        record: A::Record,
        challenger: &mut SC::Challenger,
        pi_digest: [u32; PI_DIGEST_WORD_SIZE],
    ) -> Proof<SC>
    where
        A: for<'a> Air<ProverConstraintFolder<'a, SC>>
            + Air<InteractionBuilder<Val<SC>>>
            + for<'a> Air<VerifierConstraintFolder<'a, SC>>
            + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
    {
        tracing::debug!("sharding the execution record");
        let shards = self.shard(record, &<A::Record as MachineRecord>::Config::default());

        tracing::debug!("generating the shard proofs");
        P::prove_shards(self, pk, shards, challenger, pi_digest)
    }

    pub const fn config(&self) -> &SC {
        &self.config
    }

    pub fn verify(
        &self,
        _vk: &VerifyingKey<SC>,
        proof: &Proof<SC>,
        challenger: &mut SC::Challenger,
        pi_digest: [u32; PI_DIGEST_WORD_SIZE],
    ) -> Result<(), ProgramVerificationError>
    where
        SC::Challenger: Clone,
        A: for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    {
        // TODO: Observe the challenges in a tree-like structure for easily verifiable reconstruction
        // in a map-reduce recursion setting.
        #[cfg(feature = "perf")]
        tracing::debug_span!("observe challenges for all shards").in_scope(|| {
            proof.shard_proofs.iter().for_each(|proof| {
                challenger.observe(proof.commitment.main_commit.clone());
            });
        });

        // Observe the public input digest
        challenger.observe(pi_digest);

        // Verify the segment proofs.
        tracing::info!("verifying shard proofs");
        for (i, proof) in proof.shard_proofs.iter().enumerate() {
            tracing::debug_span!("verifying shard", segment = i).in_scope(|| {
                let chips = self
                    .chips()
                    .iter()
                    .filter(|chip| proof.chip_ids.contains(&chip.name()))
                    .collect::<Vec<_>>();
                Verifier::verify_shard(
                    &self.config,
                    &chips,
                    &mut challenger.clone(),
                    proof,
                    pi_digest,
                )
                .map_err(ProgramVerificationError::InvalidSegmentProof)
            })?;
        }
        tracing::info!("success");

        // Verify the cumulative sum is 0.
        let mut sum = SC::Challenge::zero();
        for proof in proof.shard_proofs.iter() {
            sum += proof.cumulative_sum();
        }
        match sum.is_zero() {
            true => Ok(()),
            false => Err(ProgramVerificationError::NonZeroCumulativeSum),
        }
    }

    pub fn debug_constraints(
        &self,
        _pk: &ProvingKey<SC>,
        record: A::Record,
        challenger: &mut SC::Challenger,
    ) where
        SC::Val: PrimeField32,
        A: for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
    {
        tracing::debug!("sharding the execution record");
        let mut shards = self.shard(record, &<A::Record as MachineRecord>::Config::default());

        tracing::debug!("checking constraints for each shard");

        let mut cumulative_sum = SC::Challenge::zero();
        for shard in shards.iter() {
            // Filter the chips based on what is used.
            let chips = self.shard_chips(shard).collect::<Vec<_>>();

            // Generate the main trace for each chip.
            let traces = chips
                .par_iter()
                .map(|chip| chip.generate_trace(shard, &mut A::Record::default()))
                .collect::<Vec<_>>();

            // Get a permutation challenge.
            // Obtain the challenges used for the permutation argument.
            let mut permutation_challenges: Vec<SC::Challenge> = Vec::new();
            for _ in 0..2 {
                permutation_challenges.push(challenger.sample_ext_element());
            }

            // Generate the permutation traces.
            let mut permutation_traces = Vec::with_capacity(chips.len());
            let mut cumulative_sums = Vec::with_capacity(chips.len());
            tracing::debug_span!("generate permutation traces").in_scope(|| {
                chips
                    .par_iter()
                    .zip(traces.par_iter())
                    .map(|(chip, main_trace)| {
                        let perm_trace = chip.generate_permutation_trace(
                            &None,
                            main_trace,
                            &permutation_challenges,
                        );
                        let cumulative_sum = perm_trace
                            .row_slice(main_trace.height() - 1)
                            .last()
                            .copied()
                            .unwrap();
                        (perm_trace, cumulative_sum)
                    })
                    .unzip_into_vecs(&mut permutation_traces, &mut cumulative_sums);
            });

            cumulative_sum += cumulative_sums.iter().copied().sum::<SC::Challenge>();

            // Compute some statistics.
            for i in 0..chips.len() {
                let trace_width = traces[i].width();
                let permutation_width = permutation_traces[i].width();
                let total_width = trace_width + permutation_width;
                tracing::debug!(
                "{:<11} | Cols = {:<5} | Rows = {:<5} | Cells = {:<10} | Main Cols = {:.2}% | Perm Cols = {:.2}%",
                chips[i].name(),
                total_width,
                traces[i].height(),
                total_width * traces[i].height(),
                (100f32 * trace_width as f32) / total_width as f32,
                (100f32 * permutation_width as f32) / total_width as f32);
            }

            tracing::info_span!("debug constraints").in_scope(|| {
                for i in 0..chips.len() {
                    debug_constraints::<SC, A>(
                        chips[i],
                        None,
                        &traces[i],
                        &permutation_traces[i],
                        &permutation_challenges,
                    );
                }
            });
        }

        // If the cumulative sum is not zero, debug the interactions.
        if !cumulative_sum.is_zero() {
            // Get the total record
            let mut record = A::Record::default();
            for shard in shards.iter_mut() {
                record.append(shard);
            }
            debug_interactions_with_all_chips::<SC, A>(
                self.chips(),
                &record,
                InteractionKind::all_kinds(),
            );
        }
    }
}

#[derive(Debug)]
pub enum ProgramVerificationError {
    InvalidSegmentProof(VerificationError),
    InvalidGlobalProof(VerificationError),
    NonZeroCumulativeSum,
    DebugInteractionsFailed,
}

#[cfg(test)]
#[allow(non_snake_case)]
pub mod tests {

    use crate::runtime::tests::ecall_lwa_program;
    use crate::runtime::tests::fibonacci_program;
    use crate::runtime::tests::simple_memory_program;
    use crate::runtime::tests::simple_program;
    use crate::runtime::tests::ssz_withdrawals_program;
    use crate::runtime::Instruction;
    use crate::runtime::Opcode;
    use crate::runtime::Program;
    use crate::utils;
    use crate::utils::run_test;
    use crate::utils::setup_logger;

    use sp1_zkvm::PI_DIGEST_WORD_SIZE;

    const EMPTY_PI_DIGEST: [u32; PI_DIGEST_WORD_SIZE] = [0; PI_DIGEST_WORD_SIZE];

    #[test]
    fn test_simple_prove() {
        utils::setup_logger();
        let program = simple_program();
        run_test(program, EMPTY_PI_DIGEST).unwrap();
    }

    #[test]
    fn test_ecall_lwa_prove() {
        utils::setup_logger();
        let program = ecall_lwa_program();
        run_test(program, EMPTY_PI_DIGEST).unwrap();
    }

    #[test]
    fn test_shift_prove() {
        utils::setup_logger();
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
                run_test(program, EMPTY_PI_DIGEST).unwrap();
            }
        }
    }

    #[test]
    fn test_sub_prove() {
        utils::setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
            Instruction::new(Opcode::SUB, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test(program, EMPTY_PI_DIGEST).unwrap();
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
        run_test(program, EMPTY_PI_DIGEST).unwrap();
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
                run_test(program, EMPTY_PI_DIGEST).unwrap();
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
            run_test(program, EMPTY_PI_DIGEST).unwrap();
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
            run_test(program, EMPTY_PI_DIGEST).unwrap();
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
                run_test(program, EMPTY_PI_DIGEST).unwrap();
            }
        }
    }

    #[test]
    fn test_fibonacci_prove() {
        setup_logger();
        let program = fibonacci_program();
        run_test(program, EMPTY_PI_DIGEST).unwrap();
    }

    #[test]
    fn test_simple_memory_program_prove() {
        let program = simple_memory_program();
        run_test(program, EMPTY_PI_DIGEST).unwrap();
    }

    #[test]
    fn test_ssz_withdrawal() {
        let program = ssz_withdrawals_program();
        run_test(program, EMPTY_PI_DIGEST).unwrap();
    }
}
