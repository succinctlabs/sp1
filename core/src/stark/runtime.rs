use crate::alu::divrem::DivRemChip;
use crate::alu::mul::MulChip;
use crate::bytes::ByteChip;
use crate::field::FieldLTUChip;
use crate::memory::MemoryGlobalChip;

use crate::alu::{AddChip, BitwiseChip, LtChip, ShiftLeft, ShiftRightChip, SubChip};
use crate::cpu::CpuChip;
use crate::memory::MemoryChipKind;
use crate::precompiles::edwards::ed_add::EdAddAssignChip;
use crate::precompiles::edwards::ed_decompress::EdDecompressChip;
use crate::precompiles::k256::decompress::K256DecompressChip;
use crate::precompiles::keccak256::KeccakPermuteChip;
use crate::precompiles::sha256::{ShaCompressChip, ShaExtendChip};
use crate::precompiles::weierstrass::weierstrass_add::WeierstrassAddAssignChip;
use crate::precompiles::weierstrass::weierstrass_double::WeierstrassDoubleAssignChip;
use crate::program::ProgramChip;
use crate::runtime::{Runtime, Segment};
use crate::stark::Verifier;
use crate::utils::ec::edwards::ed25519::Ed25519Parameters;
use crate::utils::ec::edwards::EdwardsCurve;
use crate::utils::ec::weierstrass::secp256k1::Secp256k1Parameters;
use crate::utils::ec::weierstrass::SWCurve;
use crate::utils::AirChip;
use p3_challenger::CanObserve;
use p3_maybe_rayon::prelude::IndexedParallelIterator;
use p3_maybe_rayon::prelude::IntoParallelIterator;
use p3_maybe_rayon::prelude::ParallelIterator;
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::OpeningProof;

#[cfg(not(feature = "perf"))]
use crate::stark::debug_cumulative_sums;

use p3_commit::Pcs;
use p3_field::{ExtensionField, PrimeField, PrimeField32, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;

use super::prover::Prover;
use super::types::{MainData, SegmentProof};
use super::{StarkConfig, VerificationError};

pub const NUM_CHIPS: usize = 20;

impl Runtime {
    /// Chips used in each segment.
    ///
    /// The chips must be ordered to address dependencies. Some operations, like division, depend
    /// on others, like multiplication, for verification.
    pub fn segment_chips<SC: StarkConfig>() -> [Box<dyn AirChip<SC>>; NUM_CHIPS]
    where
        SC::Val: PrimeField32,
    {
        [
            Box::new(ProgramChip::default()),
            Box::new(CpuChip::default()),
            Box::new(ShaExtendChip::default()),
            Box::new(ShaCompressChip::default()),
            Box::new(EdAddAssignChip::<
                EdwardsCurve<Ed25519Parameters>,
                Ed25519Parameters,
            >::new()),
            Box::new(EdDecompressChip::<Ed25519Parameters>::default()),
            Box::new(K256DecompressChip::default()),
            Box::new(WeierstrassAddAssignChip::<
                SWCurve<Secp256k1Parameters>,
                Secp256k1Parameters,
            >::new()),
            Box::new(WeierstrassDoubleAssignChip::<
                SWCurve<Secp256k1Parameters>,
                Secp256k1Parameters,
            >::new()),
            Box::new(KeccakPermuteChip::new()),
            Box::new(AddChip::default()),
            Box::new(SubChip::default()),
            Box::new(BitwiseChip::default()),
            Box::new(DivRemChip::default()),
            Box::new(MulChip::default()),
            Box::new(ShiftRightChip::default()),
            Box::new(ShiftLeft::default()),
            Box::new(LtChip::default()),
            Box::new(FieldLTUChip::default()),
            Box::new(ByteChip::<SC::Val>::new()),
        ]
    }

    /// Chips used in the global segment.
    ///
    /// The chips must be ordered to address dependencies, similar to `segment_chips`.
    pub fn global_chips<SC: StarkConfig>() -> [Box<dyn AirChip<SC>>; 3]
    where
        SC::Val: PrimeField32,
    {
        let memory_init = MemoryGlobalChip::new(MemoryChipKind::Init);
        let memory_finalize = MemoryGlobalChip::new(MemoryChipKind::Finalize);
        let program_memory_init = MemoryGlobalChip::new(MemoryChipKind::Program);
        [
            Box::new(memory_init),
            Box::new(memory_finalize),
            Box::new(program_memory_init),
        ]
    }

    /// Prove the program.
    ///
    /// The function returns a vector of segment proofs, one for each segment, and a global proof.
    pub fn prove<F, EF, SC, P>(
        &mut self,
        config: &SC,
        challenger: &mut SC::Challenger,
    ) -> (Vec<SegmentProof<SC>>, SegmentProof<SC>)
    where
        F: PrimeField + TwoAdicField + PrimeField32,
        EF: ExtensionField<F>,
        SC: StarkConfig<Val = F, Challenge = EF> + Send + Sync,
        SC::Challenger: Clone,
        <SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::Commitment: Send + Sync,
        <SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::ProverData: Send + Sync,
        MainData<SC>: Serialize + DeserializeOwned,
        P: Prover<SC>,
        OpeningProof<SC>: Send + Sync,
    {
        // Generate the trace for each chip to collect events emitted from chips with dependencies.
        let chips = Self::segment_chips::<SC>();
        chips.iter().for_each(|chip| {
            chip.generate_trace(&mut self.segment);
        });

        // For each chip, shard the events into segments.
        let mut segments: Vec<Segment> = Vec::new();
        chips.iter().for_each(|chip| {
            chip.shard(&self.segment, &mut segments);
        });

        let num_segments = segments.len();
        let (cycle_count, keccak_count, sha_count) = segments.iter().fold((0, 0, 0), |acc, s| {
            (
                acc.0 + s.cpu_events.len(),
                acc.1 + s.keccak_permute_events.len(),
                acc.2 + s.sha_compress_events.len(),
            )
        });
        tracing::info!(
            "total_cycles: {}, segments: {}, keccak: {}, sha: {}",
            cycle_count,
            num_segments,
            keccak_count,
            sha_count,
        );

        let segment_chips = Self::segment_chips::<SC>();
        let (commitments, segment_main_data) =
            P::generate_segment_traces::<F, EF>(config, &mut segments, &segment_chips);

        // TODO: Observe the challenges in a tree-like structure for easily verifiable reconstruction
        // in a map-reduce recursion setting.
        tracing::info_span!("observe challenges for all segments").in_scope(|| {
            commitments.into_iter().for_each(|commitment| {
                challenger.observe(commitment);
            });
        });

        // We clone the challenger so that each segment can observe the same "global" challenges.
        let local_segment_proofs: Vec<_> =
            tracing::info_span!("proving all segments").in_scope(|| {
                segment_main_data
                    .into_par_iter()
                    .enumerate()
                    .map(|(i, main_data)| {
                        tracing::info_span!("proving segment", segment = i).in_scope(|| {
                            let p = P::prove(
                                config,
                                &mut challenger.clone(),
                                &segment_chips,
                                main_data,
                            );
                            tracing::info!("finished proving for segment {}", i);
                            p
                        })
                    })
                    .collect()
            });

        #[cfg(feature = "proof-debug")]
        // Verify the segment proofs.
        tracing::info_span!("proving all segments").in_scope(|| {
            local_segment_proofs
                .iter()
                .enumerate()
                .for_each(|(i, proof)| {
                    tracing::info_span!("verifying segment", segment = i).in_scope(|| {
                        Verifier::verify(config, &segment_chips, &mut challenger.clone(), proof)
                            .unwrap()
                    })
                })
        });

        let global_chips = Self::global_chips::<SC>();
        let global_main_data =
            tracing::info_span!("commit main for global segments").in_scope(|| {
                P::commit_main(config, &global_chips, &mut self.global_segment).to_in_memory()
            });
        let global_proof = tracing::info_span!("proving global segments").in_scope(|| {
            P::prove(
                config,
                &mut challenger.clone(),
                &global_chips,
                global_main_data,
            )
        });

        #[cfg(feature = "proof-debug")]
        // Verify the global proof.
        tracing::info_span!("verifying global segments").in_scope(|| {
            Verifier::verify(
                config,
                &global_chips,
                &mut challenger.clone(),
                &global_proof,
            )
            .unwrap()
        });

        #[cfg(not(feature = "perf"))]
        let mut all_permutation_traces = local_segment_proofs
            .into_iter()
            .flat_map(|proof| proof.permutation_traces)
            .collect::<Vec<_>>();
        #[cfg(not(feature = "perf"))]
        all_permutation_traces.extend_from_slice(&global_proof.permutation_traces);

        // Compute the cumulative bus sum from all segments
        // Make sure that this cumulative bus sum is 0.
        #[cfg(not(feature = "perf"))]
        debug_cumulative_sums::<F, EF>(&all_permutation_traces);

        #[cfg(feature = "perf")]
        return (local_segment_proofs, global_proof);

        #[cfg(not(feature = "perf"))]
        (vec![], global_proof)
    }

    pub fn verify<F, EF, SC>(
        &mut self,
        config: &SC,
        challenger: &mut SC::Challenger,
        segments_proofs: &[SegmentProof<SC>],
        global_proof: &SegmentProof<SC>,
    ) -> Result<(), ProgramVerificationError>
    where
        F: PrimeField + TwoAdicField + PrimeField32,
        EF: ExtensionField<F>,
        SC: StarkConfig<Val = F, Challenge = EF> + Send + Sync,
        SC::Challenger: Clone,
        <SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::Commitment: Send + Sync,
        <SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::ProverData: Send + Sync,
    {
        // TODO: Observe the challenges in a tree-like structure for easily verifiable reconstruction
        // in a map-reduce recursion setting.
        #[cfg(feature = "perf")]
        tracing::info_span!("observe challenges for all segments").in_scope(|| {
            segments_proofs.iter().for_each(|proof| {
                challenger.observe(proof.commitment.main_commit.clone());
            });
        });

        // Verify the segment proofs.
        let segment_chips = Self::segment_chips::<SC>();
        for (i, proof) in segments_proofs.iter().enumerate() {
            tracing::info_span!("verifying segment", segment = i).in_scope(|| {
                Verifier::verify(config, &segment_chips, &mut challenger.clone(), proof)
                    .map_err(ProgramVerificationError::InvalidSegmentProof)
            })?;
        }

        // Verifiy the global proof.
        let global_chips = Self::global_chips::<SC>();
        tracing::info_span!("verifying global segment").in_scope(|| {
            Verifier::verify(config, &global_chips, &mut challenger.clone(), global_proof)
                .map_err(ProgramVerificationError::InvalidGlobalProof)
        })?;

        // Verify the cumulative sum is 0.
        let mut sum = SC::Challenge::zero();
        #[cfg(feature = "perf")]
        {
            for proof in segments_proofs.iter() {
                sum += proof
                    .commulative_sums
                    .iter()
                    .copied()
                    .sum::<SC::Challenge>();
            }
            sum += global_proof
                .commulative_sums
                .iter()
                .copied()
                .sum::<SC::Challenge>();
        }

        match sum.is_zero() {
            true => Ok(()),
            false => Err(ProgramVerificationError::NonZeroCommulativeSum),
        }
    }
}

#[derive(Debug)]
pub enum ProgramVerificationError {
    InvalidSegmentProof(VerificationError),
    InvalidGlobalProof(VerificationError),
    NonZeroCommulativeSum,
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
    use crate::utils::prove;
    use crate::utils::setup_logger;

    #[test]
    fn test_simple_prove() {
        let program = simple_program();
        prove(program);
    }

    #[test]
    fn test_ecall_lwa_prove() {
        let program = ecall_lwa_program();
        prove(program);
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
                prove(program);
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
        prove(program);
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
        prove(program);
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
                prove(program);
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
            prove(program);
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
            prove(program);
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
                prove(program);
            }
        }
    }

    #[test]
    fn test_fibonacci_prove() {
        setup_logger();
        let program = fibonacci_program();
        prove(program);
    }

    #[test]
    fn test_simple_memory_program_prove() {
        let program = simple_memory_program();
        prove(program);
    }
}
