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
use p3_matrix::Matrix;
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
        // Fill in events for the master segment.
        let chips = Self::segment_chips::<SC>();
        chips.iter().for_each(|chip| {
            chip.generate_trace(&mut self.segment);
        });

        const NB_ROWS_PER_SHARD: usize = 1 << 17;
        let cpu_events = self
            .segment
            .cpu_events
            .chunks(NB_ROWS_PER_SHARD)
            .collect::<Vec<_>>();
        let add_events = self
            .segment
            .add_events
            .chunks(NB_ROWS_PER_SHARD)
            .collect::<Vec<_>>();
        let mul_events = self
            .segment
            .mul_events
            .chunks(NB_ROWS_PER_SHARD)
            .collect::<Vec<_>>();
        let sub_events = self
            .segment
            .sub_events
            .chunks(NB_ROWS_PER_SHARD)
            .collect::<Vec<_>>();
        let bitwise_events = self
            .segment
            .bitwise_events
            .chunks(NB_ROWS_PER_SHARD)
            .collect::<Vec<_>>();
        let shift_left_events = self
            .segment
            .shift_left_events
            .chunks(NB_ROWS_PER_SHARD)
            .collect::<Vec<_>>();
        let shift_right_events = self
            .segment
            .shift_right_events
            .chunks(NB_ROWS_PER_SHARD)
            .collect::<Vec<_>>();
        let divrem_events = self
            .segment
            .divrem_events
            .chunks(NB_ROWS_PER_SHARD)
            .collect::<Vec<_>>();
        let lt_events = self
            .segment
            .lt_events
            .chunks(NB_ROWS_PER_SHARD)
            .collect::<Vec<_>>();
        let field_events = self
            .segment
            .field_events
            .chunks(NB_ROWS_PER_SHARD * 4)
            .collect::<Vec<_>>();
        let sha_extend_events = self
            .segment
            .sha_extend_events
            .chunks(NB_ROWS_PER_SHARD)
            .collect::<Vec<_>>();
        let sha_compress_events = self
            .segment
            .sha_compress_events
            .chunks(NB_ROWS_PER_SHARD)
            .collect::<Vec<_>>();
        let keccak_permute_events = self
            .segment
            .keccak_permute_events
            .chunks(NB_ROWS_PER_SHARD)
            .collect::<Vec<_>>();
        let ed_add_events = self
            .segment
            .ed_add_events
            .chunks(NB_ROWS_PER_SHARD)
            .collect::<Vec<_>>();
        let ed_decompress_events = self
            .segment
            .ed_decompress_events
            .chunks(NB_ROWS_PER_SHARD)
            .collect::<Vec<_>>();
        let weierstrass_add_events = self
            .segment
            .weierstrass_add_events
            .chunks(NB_ROWS_PER_SHARD)
            .collect::<Vec<_>>();
        let weierrstrass_double_events = self
            .segment
            .weierstrass_double_events
            .chunks(NB_ROWS_PER_SHARD)
            .collect::<Vec<_>>();
        let k256_decompress_events = self
            .segment
            .k256_decompress_events
            .chunks(NB_ROWS_PER_SHARD)
            .collect::<Vec<_>>();
        let nb_segments = [
            cpu_events.len(),
            add_events.len(),
            mul_events.len(),
            sub_events.len(),
            bitwise_events.len(),
            shift_left_events.len(),
            shift_right_events.len(),
            divrem_events.len(),
            lt_events.len(),
            field_events.len(),
            sha_extend_events.len(),
            sha_compress_events.len(),
            ed_add_events.len(),
            ed_decompress_events.len(),
            weierstrass_add_events.len(),
            weierrstrass_double_events.len(),
            k256_decompress_events.len(),
        ]
        .into_iter()
        .max()
        .unwrap();

        println!("nb_segments: {}", nb_segments);
        println!("cpu_shards: {}", cpu_events.len());
        println!("add_shards: {}", add_events.len());
        println!("mul_shards: {}", mul_events.len());
        println!("sub_shards: {}", sub_events.len());
        println!("bitwise_shards: {}", bitwise_events.len());
        println!("shift_left_shards: {}", shift_left_events.len());
        println!("shift_right_shards: {}", shift_right_events.len());
        println!("divrem_shards: {}", divrem_events.len());
        println!("lt_shards: {}", lt_events.len());
        println!("field_shards: {}", field_events.len());
        println!("sha_extend_shards: {}", sha_extend_events.len());
        println!("sha_compress_shards: {}", sha_compress_events.len());
        println!("keccak_permute_shards: {}", keccak_permute_events.len());
        println!("ed_add_shards: {}", ed_add_events.len());
        println!("ed_decompress_shards: {}", ed_decompress_events.len());
        println!("weierstrass_add_shards: {}", weierstrass_add_events.len());
        println!(
            "weierrstrass_double_shards: {}",
            weierrstrass_double_events.len()
        );
        println!("k256_decompress_shards: {}", k256_decompress_events.len());

        let mut segments = Vec::new();
        for i in 0..nb_segments {
            let cpu_events = match cpu_events.get(i) {
                Some(events) => events.to_vec(),
                None => Vec::new(),
            };
            let add_events = match add_events.get(i) {
                Some(events) => events.to_vec(),
                None => Vec::new(),
            };
            let mul_events = match mul_events.get(i) {
                Some(events) => events.to_vec(),
                None => Vec::new(),
            };
            let sub_events = match sub_events.get(i) {
                Some(events) => events.to_vec(),
                None => Vec::new(),
            };
            let bitwise_events = match bitwise_events.get(i) {
                Some(events) => events.to_vec(),
                None => Vec::new(),
            };
            let shift_left_events = match shift_left_events.get(i) {
                Some(events) => events.to_vec(),
                None => Vec::new(),
            };
            let shift_right_events = match shift_right_events.get(i) {
                Some(events) => events.to_vec(),
                None => Vec::new(),
            };
            let divrem_events = match divrem_events.get(i) {
                Some(events) => events.to_vec(),
                None => Vec::new(),
            };
            let lt_events = match lt_events.get(i) {
                Some(events) => events.to_vec(),
                None => Vec::new(),
            };
            let field_events = match field_events.get(i) {
                Some(events) => events.to_vec(),
                None => Vec::new(),
            };
            let sha_extend_events = match sha_extend_events.get(i) {
                Some(events) => events.to_vec(),
                None => Vec::new(),
            };
            let sha_compress_events = match sha_compress_events.get(i) {
                Some(events) => events.to_vec(),
                None => Vec::new(),
            };
            let keccak_permute_events = match keccak_permute_events.get(i) {
                Some(events) => events.to_vec(),
                None => Vec::new(),
            };
            let ed_add_events = match ed_add_events.get(i) {
                Some(events) => events.to_vec(),
                None => Vec::new(),
            };
            let ed_decompress_events = match ed_decompress_events.get(i) {
                Some(events) => events.to_vec(),
                None => Vec::new(),
            };
            let weierstrass_add_events = match weierstrass_add_events.get(i) {
                Some(events) => events.to_vec(),
                None => Vec::new(),
            };
            let weierstrass_double_events = match weierrstrass_double_events.get(i) {
                Some(events) => events.to_vec(),
                None => Vec::new(),
            };
            let k256_decompress_events = match k256_decompress_events.get(i) {
                Some(events) => events.to_vec(),
                None => Vec::new(),
            };
            let mut segment = Segment {
                program: self.segment.program.clone(),
                byte_lookups: self.segment.byte_lookups.clone(),
                cpu_events,
                add_events,
                mul_events,
                sub_events,
                bitwise_events,
                shift_left_events,
                shift_right_events,
                divrem_events,
                lt_events,
                field_events,
                sha_extend_events,
                sha_compress_events,
                keccak_permute_events,
                ed_add_events,
                ed_decompress_events,
                weierstrass_add_events,
                weierstrass_double_events,
                k256_decompress_events,
                first_memory_record: Vec::new(),
                last_memory_record: Vec::new(),
                program_memory_record: Vec::new(),
            };
            segments.push(segment);
        }

        let main_datas: Vec<MainData<SC>> = segments
            .par_iter()
            .enumerate()
            .map(|(i, segment)| {
                // For each chip, generate the trace.
                let traces = chips
                    .iter()
                    .map(|chip| chip.generate_trace(&mut segment.clone()))
                    .collect::<Vec<_>>();

                // Commit to the batch of traces.
                let (main_commit, main_data) = config.pcs().commit_batches(traces.to_vec());

                println!("finished commiting to segment {}", i);

                MainData {
                    traces,
                    main_commit,
                    main_data,
                    n: 0,
                }
            })
            .collect::<Vec<_>>();

        // Observe.
        main_datas.iter().for_each(|main_data| {
            challenger.observe(main_data.main_commit.clone());
        });

        let segment_chips = Self::segment_chips::<SC>();
        let local_segment_proofs: Vec<_> = main_datas
            .into_par_iter()
            .enumerate()
            .map(|(i, main_data)| {
                tracing::info_span!("proving segment", segment = i).in_scope(|| {
                    let p =
                        Prover::prove(config, &mut challenger.clone(), &segment_chips, main_data);
                    println!("finished proving segment {}", i);
                    p
                })
            })
            .collect();

        // // Commit.
        // let main_datas: Vec<Vec<MainData<SC>>> = chips
        //     .par_iter()
        //     .map(|chip| {
        //         let batch_shards = chip.batch_shard(&self.segment);
        //         batch_shards
        //             .into_par_iter()
        //             .map(|shards| {
        //                 let n = shards.len();
        //                 let traces = shards
        //                     .into_iter()
        //                     .map(|mut shard| chip.generate_trace(&mut shard))
        //                     .collect::<Vec<_>>();
        //                 println!(
        //                     "chip: {} height: {} nb_shards: {}",
        //                     chip.name(),
        //                     traces.iter().map(|t| t.height()).sum::<usize>(),
        //                     n
        //                 );
        //                 let (main_commit, main_data) = config.pcs().commit_batches(traces.to_vec());
        //                 MainData {
        //                     traces,
        //                     main_commit,
        //                     main_data,
        //                     n,
        //                 }
        //             })
        //             .collect::<Vec<_>>()
        //     })
        //     .collect::<Vec<_>>();

        // // Observe.
        // main_datas.iter().for_each(|main_data_arr| {
        //     main_data_arr.iter().for_each(|main_data| {
        //         challenger.observe(main_data.main_commit.clone());
        //     });
        // });

        // // Generate chip proofs.
        // let local_proofs: Vec<Vec<SegmentProof<SC>>> = main_datas
        //     .into_par_iter()
        //     .enumerate()
        //     .map(|(i, main_data_arr)| {
        //         main_data_arr
        //             .into_par_iter()
        //             .map(|main_data| {
        //                 let mut chips_v2 = Vec::new();
        //                 for _ in 0..main_data.n {
        //                     let mut chips = Self::segment_chips::<SC>();
        //                     let placeholder = Box::new(ProgramChip::new());
        //                     let chip = mem::replace(&mut chips[i], placeholder);
        //                     chips_v2.push(chip);
        //                 }
        //                 println!("chip: {} proving start", chips_v2[0].name());
        //                 let res =
        //                     Prover::prove(config, &mut challenger.clone(), &chips_v2, main_data);
        //                 println!("chip: {} proving done", chips_v2[0].name());
        //                 res
        //             })
        //             .collect::<Vec<_>>()
        //     })
        //     .collect::<Vec<_>>();
        // println!("local proofs done");

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
        println!("global proofs done");

        (local_segment_proofs, global_proof)
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
        // // TODO: Observe the challenges in a tree-like structure for easily verifiable reconstruction
        // // in a map-reduce recursion setting.
        // #[cfg(feature = "perf")]
        // tracing::info_span!("observe challenges for all segments").in_scope(|| {
        //     segments_proofs.iter().for_each(|proofs| {
        //         proofs.iter().for_each(|proof| {
        //             challenger.observe(proof.commitment.main_commit.clone());
        //         })
        //     });
        // });

        // // Verify the segment proofs.
        // let segment_chips = Self::segment_chips::<SC>();
        // for (i, (chip, proof_arr)) in segment_chips.into_iter().zip(segments_proofs).enumerate() {
        //     tracing::info_span!("verifying segment", segment = chip.name()).in_scope(|| {
        //         for proof in proof_arr {
        //             let mut chips_v2 = Vec::new();
        //             for _ in 0..proof.n {
        //                 let mut chips = Self::segment_chips::<SC>();
        //                 let placeholder = Box::new(ProgramChip::new());
        //                 let chip = mem::replace(&mut chips[i], placeholder);
        //                 chips_v2.push(chip);
        //             }
        //             Verifier::verify(config, &chips_v2, &mut challenger.clone(), proof)
        //                 .map_err(ProgramVerificationError::InvalidSegmentProof)
        //                 .unwrap();
        //         }
        //     });
        // }

        // // Verifiy the global proof.
        // let global_chips = Self::global_chips::<SC>();
        // tracing::info_span!("verifying global segment").in_scope(|| {
        //     Verifier::verify(config, &global_chips, &mut challenger.clone(), global_proof)
        //         .map_err(ProgramVerificationError::InvalidGlobalProof)
        // })?;

        // // Verify the cumulative sum is 0.
        // let mut sum = SC::Challenge::zero();
        // #[cfg(feature = "perf")]
        // {
        //     for proofs in segments_proofs.iter() {
        //         for proof in proofs {
        //             sum += proof
        //                 .commulative_sums
        //                 .iter()
        //                 .copied()
        //                 .sum::<SC::Challenge>();
        //         }
        //     }
        //     sum += global_proof
        //         .commulative_sums
        //         .iter()
        //         .copied()
        //         .sum::<SC::Challenge>();
        // }

        match true {
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
