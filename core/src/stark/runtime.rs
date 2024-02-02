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
use crate::stark::{MainData, Verifier};
use crate::utils::ec::edwards::ed25519::Ed25519Parameters;
use crate::utils::ec::edwards::EdwardsCurve;
use crate::utils::ec::weierstrass::secp256k1::Secp256k1Parameters;
use crate::utils::ec::weierstrass::SWCurve;
use crate::utils::AirChip;
use crate::utils::Chip;
use p3_challenger::CanObserve;
use std::{mem, thread};

use super::OpeningProof;

#[cfg(not(feature = "perf"))]
use crate::stark::debug_cumulative_sums;

use p3_commit::Pcs;
use p3_field::{ExtensionField, PrimeField, PrimeField32, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;

use super::prover::Prover;
use super::types::SegmentProof;
use super::{StarkConfig, VerificationError};

pub const NUM_CHIPS: usize = 20;

impl Runtime {
    pub fn segment_chips<SC: StarkConfig>() -> [Box<dyn AirChip<SC>>; NUM_CHIPS]
    where
        SC::Val: PrimeField32,
    {
        // Initialize chips.
        let program = ProgramChip::new();
        let cpu = CpuChip::new();
        let add = AddChip::default();
        let sub = SubChip::default();
        let bitwise = BitwiseChip::default();
        let mul = MulChip::default();
        let divrem = DivRemChip::default();
        let shift_right = ShiftRightChip::default();
        let shift_left = ShiftLeft::default();
        let lt = LtChip::default();
        let bytes = ByteChip::<SC::Val>::new();
        let field = FieldLTUChip::default();
        let sha_extend = ShaExtendChip::new();
        let sha_compress = ShaCompressChip::new();
        let ed_add = EdAddAssignChip::<EdwardsCurve<Ed25519Parameters>, Ed25519Parameters>::new();
        let ed_decompress = EdDecompressChip::<Ed25519Parameters>::new();
        let keccak_permute = KeccakPermuteChip::new();
        let weierstrass_add =
            WeierstrassAddAssignChip::<SWCurve<Secp256k1Parameters>, Secp256k1Parameters>::new();
        let weierstrass_double =
            WeierstrassDoubleAssignChip::<SWCurve<Secp256k1Parameters>, Secp256k1Parameters>::new();
        let k256_decompress = K256DecompressChip::new();
        // This vector contains chips ordered to address dependencies. Some operations, like div,
        // depend on others like mul for verification. To prevent race conditions and ensure correct
        // execution sequences, dependent operations are positioned before their dependencies.
        [
            Box::new(program),
            Box::new(cpu),
            Box::new(sha_extend),
            Box::new(sha_compress),
            Box::new(ed_add),
            Box::new(ed_decompress),
            Box::new(k256_decompress),
            Box::new(weierstrass_add),
            Box::new(weierstrass_double),
            Box::new(keccak_permute),
            Box::new(add),
            Box::new(sub),
            Box::new(bitwise),
            Box::new(divrem),
            Box::new(mul),
            Box::new(shift_right),
            Box::new(shift_left),
            Box::new(lt),
            Box::new(field),
            Box::new(bytes),
        ]
    }

    pub fn global_chips<SC: StarkConfig>() -> [Box<dyn AirChip<SC>>; 3]
    where
        SC::Val: PrimeField32,
    {
        // Initialize chips.
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
    pub fn prove<F, EF, SC>(
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
        OpeningProof<SC>: Send + Sync,
    {
        // Fill in events.
        let chips = Self::segment_chips::<SC>();
        chips.iter().for_each(|chip| {
            chip.generate_trace(&mut self.segment);
        });

        // Commit.
        let main_datas: Vec<MainData<SC>> = chips
            .par_iter()
            .map(|chip| {
                let shards = chip.shard(&self.segment);
                let traces = shards
                    .into_iter()
                    .map(|mut shard| chip.generate_trace(&mut shard))
                    .collect::<Vec<_>>();
                let (main_commit, main_data) = config.pcs().commit_batches(traces.to_vec());
                MainData {
                    traces,
                    main_commit,
                    main_data,
                }
            })
            .collect::<Vec<_>>();

        // Observe.
        main_datas.iter().for_each(|main_data| {
            challenger.observe(main_data.main_commit.clone());
        });

        // Generate chip proofs.
        let local_proofs: Vec<SegmentProof<SC>> = main_datas
            .into_par_iter()
            .enumerate()
            .map(|(i, main_data)| {
                let mut chips = Self::segment_chips::<SC>();
                let placeholder = Box::new(ProgramChip::new());
                let chip = mem::replace(&mut chips[i], placeholder);
                Prover::prove(config, &mut challenger.clone(), &[chip], main_data)
            })
            .collect::<Vec<_>>();

        // Generate global proofs.
        let global_chips = Self::global_chips::<SC>();
        let global_main_data = tracing::info_span!("commit main for global segments")
            .in_scope(|| Prover::commit_main(config, &global_chips, &mut self.global_segment));
        let global_proof = tracing::info_span!("proving global segments").in_scope(|| {
            Prover::prove(
                config,
                &mut challenger.clone(),
                &global_chips,
                global_main_data,
            )
        });

        // Verify chip proofs.
        // let chips = Self::segment_chips::<SC>();
        // chips
        //     .into_iter()
        //     .zip(local_proofs)
        //     .for_each(|(chip, proof)| {
        //         Verifier::verify(config, &[chip], &mut challenger.clone(), &proof).unwrap()
        //     });

        // // Verify global proofs.
        // Verifier::verify(
        //     config,
        //     &global_chips,
        //     &mut challenger.clone(),
        //     &global_proof,
        // )
        // .unwrap();

        // #[cfg(not(feature = "perf"))]
        // {
        //     let mut all_permutation_traces = local_proofs
        //         .clone()
        //         .into_iter()
        //         .flat_map(|proof| proof.permutation_traces)
        //         .collect::<Vec<_>>();
        //     all_permutation_traces.extend_from_slice(&global_proof.permutation_traces);
        //     debug_cumulative_sums::<F, EF>(&all_permutation_traces);
        // }

        (local_proofs, global_proof)

        // // Compute the cumulative bus sum from all segments
        // // Make sure that this cumulative bus sum is 0.
        // #[cfg(not(feature = "perf"))]
        // debug_cumulative_sums::<F, EF>(&all_permutation_traces);

        // // local_segment_proofs
        // // .iter()
        // // .enumerate()
        // // .for_each(|(i, proof)| {
        // //     tracing::info_span!("verifying segment", segment = i).in_scope(|| {
        // //         Verifier::verify(config, &segment_chips, &mut challenger.clone(), proof)
        // //             .unwrap()
        // //     })
        // // })

        // // segment_main_data
        // //             .into_par_iter()
        // //             .enumerate()
        // //             .map(|(i, main_data)| {
        // //                 tracing::info_span!("proving segment", segment = i).in_scope(|| {
        // //                     Prover::prove(
        // //                         config,
        // //                         &mut challenger.clone(),
        // //                         &segment_chips,
        // //                         main_data,
        // //                     )
        // //                 })
        // //             })
        // //             .collect()

        // // // Compute optimal event allocation.
        // // const SHARD_SIZE: usize = 1 << 20;
        // // fn shard<T: Clone>(vec: &[T], size: usize) -> Vec<Vec<T>> {
        // //     vec.chunks(size).map(|c| c.to_vec()).collect::<Vec<_>>()
        // // }
        // // let cpu_shards = shard(&self.segment.cpu_events, SHARD_SIZE);
        // // let add_shards = shard(&self.segment.add_events, SHARD_SIZE);
        // // let mul_shards = shard(&self.segment.mul_events, SHARD_SIZE);
        // // let sub_shards = shard(&self.segment.sub_events, SHARD_SIZE);
        // // let bitwise_shards = shard(&self.segment.bitwise_events, SHARD_SIZE);
        // // let shift_left_shards = shard(&self.segment.shift_left_events, SHARD_SIZE);
        // // let shift_right_shards = shard(&self.segment.shift_right_events, SHARD_SIZE);
        // // let lt_shards = shard(&self.segment.lt_events, SHARD_SIZE);
        // // let field_events = shard(&self.segment.field_events, SHARD_SIZE);

        // // // CPU.
        // // let cpu: Box<dyn AirChip<SC>> = Box::new(CpuChip::new());
        // // let cpu_traces = cpu_shards
        // //     .into_iter()
        // //     .map(|shard| {
        // //         let mut segment = Segment::default();
        // //         segment.cpu_events = shard;
        // //         let (commit, main) = cpu.generate_trace(&mut segment);
        // //     })
        // //     .collect::<Vec<_>>();

        // // let (cpu_commit, cpu_data) = config.pcs().commit_batches(cpu_traces);

        // // // ADD.
        // // let add: Box<dyn AirChip<SC>> = Box::new(AddChip::default());
        // // let add_traces = add_shards
        // //     .into_iter()
        // //     .map(|shard| {
        // //         let mut segment = Segment::default();
        // //         segment.add_events = shard;
        // //         add.generate_trace(&mut segment)
        // //     })
        // //     .collect::<Vec<_>>();
        // // let (add_commit, add_data) = config.pcs().commit_batches(add_traces);

        // // let nb_jobs = [
        // //     cpu_shards.len(),
        // //     add_shards.len(),
        // //     mul_shards.len(),
        // //     sub_shards.len(),
        // //     bitwise_shards.len(),
        // //     shift_left_shards.len(),
        // //     shift_right_shards.len(),
        // //     lt_shards.len(),
        // //     field_events.len(),
        // // ]
        // // .into_iter()
        // // .max()
        // // .unwrap();
        // // let mut jobs = Vec::new();
        // // for i in 0..nb_jobs {
        // //     let mut job = Segment::default();
        // //     job.program = self.segment.program.clone();
        // //     job.cpu_events = cpu_shards.get(i).cloned().unwrap_or_default();
        // //     job.add_events = add_shards.get(i).cloned().unwrap_or_default();
        // //     job.mul_events = mul_shards.get(i).cloned().unwrap_or_default();
        // //     job.sub_events = sub_shards.get(i).cloned().unwrap_or_default();
        // //     job.bitwise_events = bitwise_shards.get(i).cloned().unwrap_or_default();
        // //     job.shift_left_events = shift_left_shards.get(i).cloned().unwrap_or_default();
        // //     job.shift_right_events = shift_right_shards.get(i).cloned().unwrap_or_default();
        // //     job.lt_events = lt_shards.get(i).cloned().unwrap_or_default();
        // //     job.field_events = field_events.get(i).cloned().unwrap_or_default();
        // //     jobs.push(job);
        // // }

        // // let idx = jobs.len() - 1;
        // // jobs[idx].program = self.segment.program.clone();
        // // jobs[idx].byte_lookups = self.segment.byte_lookups.clone();
        // // jobs[idx].sha_extend_events = self.segment.sha_extend_events.clone();
        // // jobs[idx].sha_compress_events = self.segment.sha_compress_events.clone();
        // // jobs[idx].keccak_permute_events = self.segment.keccak_permute_events.clone();
        // // jobs[idx].ed_add_events = self.segment.ed_add_events.clone();
        // // jobs[idx].ed_decompress_events = self.segment.ed_decompress_events.clone();
        // // jobs[idx].weierstrass_add_events = self.segment.weierstrass_add_events.clone();
        // // jobs[idx].weierstrass_double_events = self.segment.weierstrass_double_events.clone();
        // // jobs[idx].k256_decompress_events = self.segment.k256_decompress_events.clone();

        // // self.sharded_segments = jobs;

        // tracing::info!(
        //     "total_cycles: {}, segments: {}",
        //     self.segment.cpu_events.len(),
        //     self.sharded_segments.len()
        // );
        // let segment_chips = Self::segment_chips::<SC>();
        // let segment_main_data =
        //     tracing::info_span!("commit main for all segments").in_scope(|| {
        //         vec![self.segment.clone()]
        //             .par_iter_mut()
        //             .map(|segment| {
        //                 Prover::commit_main(config, &segment_chips, &mut segment.clone())
        //             })
        //             .collect::<Vec<_>>()
        //     });

        // // TODO: Observe the challenges in a tree-like structure for easily verifiable reconstruction
        // // in a map-reduce recursion setting.
        // tracing::info_span!("observe challenges for all segments").in_scope(|| {
        //     segment_main_data.iter().for_each(|main_data| {
        //         challenger.observe(main_data.main_commit.clone());
        //     });
        // });

        // // We clone the challenger so that each segment can observe the same "global" challenges.
        // let local_segment_proofs: Vec<_> =
        //     tracing::info_span!("proving all segments").in_scope(|| {
        //         segment_main_data
        //             .into_par_iter()
        //             .enumerate()
        //             .map(|(i, main_data)| {
        //                 tracing::info_span!("proving segment", segment = i).in_scope(|| {
        //                     Prover::prove(
        //                         config,
        //                         &mut challenger.clone(),
        //                         &segment_chips,
        //                         main_data,
        //                     )
        //                 })
        //             })
        //             .collect()
        //     });

        // #[cfg(feature = "proof-debug")]
        // // Verify the segment proofs.
        // tracing::info_span!("proving all segments").in_scope(|| {
        //     local_segment_proofs
        //         .iter()
        //         .enumerate()
        //         .for_each(|(i, proof)| {
        //             tracing::info_span!("verifying segment", segment = i).in_scope(|| {
        //                 Verifier::verify(config, &segment_chips, &mut challenger.clone(), proof)
        //                     .unwrap()
        //             })
        //         })
        // });

        // let global_chips = Self::global_chips::<SC>();
        // let global_main_data = tracing::info_span!("commit main for global segments")
        //     .in_scope(|| Prover::commit_main(config, &global_chips, &mut self.global_segment));
        // let global_proof = tracing::info_span!("proving global segments").in_scope(|| {
        //     Prover::prove(
        //         config,
        //         &mut challenger.clone(),
        //         &global_chips,
        //         global_main_data,
        //     )
        // });

        // #[cfg(feature = "proof-debug")]
        // // Verify the global proof.
        // tracing::info_span!("verifying global segments").in_scope(|| {
        //     Verifier::verify(
        //         config,
        //         &global_chips,
        //         &mut challenger.clone(),
        //         &global_proof,
        //     )
        //     .unwrap()
        // });

        // #[cfg(not(feature = "perf"))]
        // let mut all_permutation_traces = local_segment_proofs
        //     .into_iter()
        //     .flat_map(|proof| proof.permutation_traces)
        //     .collect::<Vec<_>>();
        // #[cfg(not(feature = "perf"))]
        // all_permutation_traces.extend_from_slice(&global_proof.permutation_traces);

        // // Compute the cumulative bus sum from all segments
        // // Make sure that this cumulative bus sum is 0.
        // #[cfg(not(feature = "perf"))]
        // debug_cumulative_sums::<F, EF>(&all_permutation_traces);

        // #[cfg(feature = "perf")]
        // return (local_segment_proofs, global_proof);

        // #[cfg(not(feature = "perf"))]
        // (vec![], global_proof)
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
        for (i, (chip, proof)) in segment_chips.into_iter().zip(segments_proofs).enumerate() {
            tracing::info_span!("verifying segment", segment = chip.name()).in_scope(|| {
                Verifier::verify(config, &[chip], &mut challenger.clone(), proof)
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
        let program = fibonacci_program();
        prove(program);
    }

    #[test]
    fn test_simple_memory_program_prove() {
        let program = simple_memory_program();
        prove(program);
    }
}
