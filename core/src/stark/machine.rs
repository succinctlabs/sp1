use crate::air::MachineAir;
use crate::alu::AddChip;
use crate::alu::BitwiseChip;
use crate::alu::DivRemChip;
use crate::alu::LtChip;
use crate::alu::MulChip;
use crate::alu::ShiftLeft;
use crate::alu::ShiftRightChip;
use crate::alu::SubChip;
use crate::bytes::ByteChip;
use crate::cpu::CpuChip;
use crate::field::FieldLTUChip;
use crate::memory::MemoryChipKind;
use crate::memory::MemoryGlobalChip;
use crate::program::ProgramChip;
use crate::runtime::ExecutionRecord;
use crate::syscall::precompiles::edwards::EdAddAssignChip;
use crate::syscall::precompiles::edwards::EdDecompressChip;
use crate::syscall::precompiles::k256::K256DecompressChip;
use crate::syscall::precompiles::keccak256::KeccakPermuteChip;
use crate::syscall::precompiles::sha256::ShaCompressChip;
use crate::syscall::precompiles::sha256::ShaExtendChip;
use crate::syscall::precompiles::weierstrass::WeierstrassAddAssignChip;
use crate::syscall::precompiles::weierstrass::WeierstrassDoubleAssignChip;
use crate::utils::ec::edwards::ed25519::Ed25519Parameters;
use crate::utils::ec::edwards::EdwardsCurve;
use crate::utils::ec::weierstrass::secp256k1::Secp256k1Parameters;
use crate::utils::ec::weierstrass::SWCurve;
use p3_air::BaseAir;
use p3_challenger::CanObserve;
use p3_commit::Pcs;
use p3_field::AbstractField;
use p3_field::Field;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::Chip;
use super::ChipRef;
use super::Com;
use super::MainData;
use super::OpeningProof;
use super::Proof;
use super::Prover;
use super::StarkConfig;
use super::VerificationError;
use super::Verifier;

pub struct RiscvStark<SC: StarkConfig> {
    config: SC,

    program: Chip<SC::Val, ProgramChip>,
    cpu: Chip<SC::Val, CpuChip>,
    sha_extend: Chip<SC::Val, ShaExtendChip>,
    sha_compress: Chip<SC::Val, ShaCompressChip>,
    ed_add_assign:
        Chip<SC::Val, EdAddAssignChip<EdwardsCurve<Ed25519Parameters>, Ed25519Parameters>>,
    ed_decompress: Chip<SC::Val, EdDecompressChip<Ed25519Parameters>>,
    k256_decompress: Chip<SC::Val, K256DecompressChip>,
    weierstrass_add_assign:
        Chip<SC::Val, WeierstrassAddAssignChip<SWCurve<Secp256k1Parameters>, Secp256k1Parameters>>,
    weierstrass_double_assign: Chip<
        SC::Val,
        WeierstrassDoubleAssignChip<SWCurve<Secp256k1Parameters>, Secp256k1Parameters>,
    >,
    keccak_permute: Chip<SC::Val, KeccakPermuteChip>,
    add: Chip<SC::Val, AddChip>,
    sub: Chip<SC::Val, SubChip>,
    bitwise: Chip<SC::Val, BitwiseChip>,
    div_rem: Chip<SC::Val, DivRemChip>,
    mul: Chip<SC::Val, MulChip>,
    shift_right: Chip<SC::Val, ShiftRightChip>,
    shift_left: Chip<SC::Val, ShiftLeft>,
    lt: Chip<SC::Val, LtChip>,
    field_ltu: Chip<SC::Val, FieldLTUChip>,
    byte: Chip<SC::Val, ByteChip<SC::Val>>,

    // Global chips
    memory_init: Chip<SC::Val, MemoryGlobalChip>,
    memory_finalize: Chip<SC::Val, MemoryGlobalChip>,
    program_memory_init: Chip<SC::Val, MemoryGlobalChip>,

    // Commitment to the preprocessed data
    preprocessed_local_commitment: Option<Com<SC>>,
    preprocessed_global_commitment: Option<Com<SC>>,
}

impl<SC: StarkConfig> RiscvStark<SC>
where
    SC::Val: PrimeField32,
{
    pub fn new(config: SC) -> Self {
        let program = Chip::new(ProgramChip::default());
        let cpu = Chip::new(CpuChip::default());
        let sha_extend = Chip::new(ShaExtendChip::default());
        let sha_compress = Chip::new(ShaCompressChip::default());
        let ed_add_assign = Chip::new(EdAddAssignChip::<
            EdwardsCurve<Ed25519Parameters>,
            Ed25519Parameters,
        >::new());
        let ed_decompress = Chip::new(EdDecompressChip::<Ed25519Parameters>::default());
        let k256_decompress = Chip::new(K256DecompressChip::default());
        let weierstrass_add_assign = Chip::new(WeierstrassAddAssignChip::<
            SWCurve<Secp256k1Parameters>,
            Secp256k1Parameters,
        >::new());
        let weierstrass_double_assign = Chip::new(WeierstrassDoubleAssignChip::<
            SWCurve<Secp256k1Parameters>,
            Secp256k1Parameters,
        >::new());
        let keccak_permute = Chip::new(KeccakPermuteChip::new());
        let add = Chip::new(AddChip::default());
        let sub = Chip::new(SubChip::default());
        let bitwise = Chip::new(BitwiseChip::default());
        let div_rem = Chip::new(DivRemChip::default());
        let mul = Chip::new(MulChip::default());
        let shift_right = Chip::new(ShiftRightChip::default());
        let shift_left = Chip::new(ShiftLeft::default());
        let lt = Chip::new(LtChip::default());
        let field_ltu = Chip::new(FieldLTUChip::default());
        let byte = Chip::new(ByteChip::<SC::Val>::new());

        // Global chips
        let memory_init = Chip::new(MemoryGlobalChip::new(MemoryChipKind::Init));
        let memory_finalize = Chip::new(MemoryGlobalChip::new(MemoryChipKind::Finalize));
        let program_memory_init = Chip::new(MemoryGlobalChip::new(MemoryChipKind::Program));

        let mut machine = Self {
            config,
            program,
            cpu,
            sha_extend,
            sha_compress,
            ed_add_assign,
            ed_decompress,
            k256_decompress,
            weierstrass_add_assign,
            weierstrass_double_assign,
            keccak_permute,
            add,
            sub,
            bitwise,
            div_rem,
            mul,
            shift_right,
            shift_left,
            lt,
            field_ltu,
            byte,
            memory_init,
            memory_finalize,
            program_memory_init,

            preprocessed_local_commitment: None,
            preprocessed_global_commitment: None,
        };

        // Compute commitments to the preprocessed data
        let local_preprocessed_traces = machine
            .local_chips()
            .iter()
            .flat_map(|chip| chip.preprocessed_trace())
            .collect::<Vec<_>>();
        let local_commit = if !local_preprocessed_traces.is_empty() {
            Some(
                machine
                    .config
                    .pcs()
                    .commit_batches(local_preprocessed_traces)
                    .0,
            )
        } else {
            None
        };

        // Compute commitments to the global preprocessed data
        let global_preprocessed_traces = machine
            .global_chips()
            .iter()
            .flat_map(|chip| chip.preprocessed_trace())
            .collect::<Vec<_>>();
        let global_commit = if !global_preprocessed_traces.is_empty() {
            Some(
                machine
                    .config
                    .pcs()
                    .commit_batches(global_preprocessed_traces)
                    .0,
            )
        } else {
            None
        };

        // Store the commitments in the machine
        machine.preprocessed_local_commitment = local_commit;
        machine.preprocessed_global_commitment = global_commit;

        machine
    }

    pub fn local_chips(&self) -> [ChipRef<SC>; 20] {
        [
            self.program.as_ref(),
            self.cpu.as_ref(),
            self.sha_extend.as_ref(),
            self.sha_compress.as_ref(),
            self.ed_add_assign.as_ref(),
            self.ed_decompress.as_ref(),
            self.k256_decompress.as_ref(),
            self.weierstrass_add_assign.as_ref(),
            self.weierstrass_double_assign.as_ref(),
            self.keccak_permute.as_ref(),
            self.add.as_ref(),
            self.sub.as_ref(),
            self.bitwise.as_ref(),
            self.div_rem.as_ref(),
            self.mul.as_ref(),
            self.shift_right.as_ref(),
            self.shift_left.as_ref(),
            self.lt.as_ref(),
            self.field_ltu.as_ref(),
            self.byte.as_ref(),
        ]
    }

    pub fn global_chips(&self) -> [ChipRef<SC>; 3] {
        [
            self.memory_init.as_ref(),
            self.memory_finalize.as_ref(),
            self.program_memory_init.as_ref(),
        ]
    }

    /// Prove the program.
    ///
    /// The function returns a vector of segment proofs, one for each segment, and a global proof.
    pub fn prove<P>(
        &self,
        record: &mut ExecutionRecord,
        challenger: &mut SC::Challenger,
    ) -> Proof<SC>
    where
        P: Prover<SC>,
        SC: Send + Sync,
        SC::Challenger: Clone,
        <SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::Commitment: Send + Sync,
        <SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::ProverData: Send + Sync,
        MainData<SC>: Serialize + DeserializeOwned,
        OpeningProof<SC>: Send + Sync,
    {
        // Get the local and global chips.
        let local_chips = self.local_chips();
        let global_chips = self.global_chips();

        // Generate the trace for each chip to collect events emitted from chips with dependencies.
        local_chips.iter().for_each(|chip| {
            chip.generate_trace(record);
        });

        // Display the statistics about the workload.
        tracing::info!("{:#?}", record.stats());

        // For each chip, shard the events into segments.
        let mut segments: Vec<ExecutionRecord> = Vec::new();
        local_chips.iter().for_each(|chip| {
            chip.shard(record, &mut segments);
        });

        // Generate and commit the traces for each segment.
        let (segment_commits, segment_datas) =
            P::generate_segment_traces(&self.config, &mut segments, &local_chips);

        // Observe the challenges for each segment.
        segment_commits.into_iter().for_each(|commitment| {
            challenger.observe(commitment);
        });

        // Generate a proof for each segment. Note that we clone the challenger so we can observe
        // identical global challenges across the segments.
        let segment_proofs = segment_datas
            .into_par_iter()
            .enumerate()
            .map(|(_, main_data)| {
                let local_chips = self.local_chips();
                P::prove(
                    &self.config,
                    &mut challenger.clone(),
                    &local_chips,
                    main_data,
                )
            })
            .collect::<Vec<_>>();

        // Generate and commit to the global segment.
        let global_main_data = P::commit_main(&self.config, &global_chips, record).to_in_memory();

        // Generate a proof for the global segment.
        let global_proof = P::prove(
            &self.config,
            &mut challenger.clone(),
            &global_chips,
            global_main_data,
        );

        Proof {
            segment_proofs,
            global_proof,
        }
    }

    pub fn verify(
        &self,
        challenger: &mut SC::Challenger,
        proof: &Proof<SC>,
    ) -> Result<(), ProgramVerificationError>
    where
        SC::Val: PrimeField32,
        SC::Challenger: Clone,
    {
        // TODO: Observe the challenges in a tree-like structure for easily verifiable reconstruction
        // in a map-reduce recursion setting.
        #[cfg(feature = "perf")]
        tracing::info_span!("observe challenges for all segments").in_scope(|| {
            proof.segment_proofs.iter().for_each(|proof| {
                challenger.observe(proof.commitment.main_commit.clone());
            });
        });

        // Verify the segment proofs.
        for (i, proof) in proof.segment_proofs.iter().enumerate() {
            tracing::info_span!("verifying segment", segment = i).in_scope(|| {
                let local_chips = self.local_chips();
                Verifier::verify(&self.config, &local_chips, &mut challenger.clone(), proof)
                    .map_err(ProgramVerificationError::InvalidSegmentProof)
            })?;
        }

        // Verifiy the global proof.
        let global_chips = self.global_chips();
        tracing::info_span!("verifying global segment").in_scope(|| {
            Verifier::verify(
                &self.config,
                &global_chips,
                &mut challenger.clone(),
                &proof.global_proof,
            )
            .map_err(ProgramVerificationError::InvalidGlobalProof)
        })?;

        // Verify the cumulative sum is 0.
        let mut sum = SC::Challenge::zero();
        #[cfg(feature = "perf")]
        {
            for proof in proof.segment_proofs.iter() {
                sum += proof.cumulative_sum();
            }
            sum += proof.global_proof.cumulative_sum();
        }

        match sum.is_zero() {
            true => Ok(()),
            false => Err(ProgramVerificationError::NonZeroCumulativeSum),
        }
    }

    // /// Chips used in each segment.
    // ///
    // /// The chips must be ordered to address dependencies. Some operations, like division, depend
    // /// on others, like multiplication, for verification.
    // pub fn local_chips<SC: StarkConfig>() -> Vec<Box<dyn AirChip<SC>>>
    // where
    //     SC::Val: PrimeField32,
    // {
    //     vec![
    //         Box::new(ProgramChip::default()),
    //         Box::new(CpuChip::default()),
    //         Box::new(ShaExtendChip::default()),
    //         Box::new(ShaCompressChip::default()),
    //         Box::new(EdAddAssignChip::<
    //             EdwardsCurve<Ed25519Parameters>,
    //             Ed25519Parameters,
    //         >::new()),
    //         Box::new(EdDecompressChip::<Ed25519Parameters>::default()),
    //         Box::new(K256DecompressChip::default()),
    //         Box::new(WeierstrassAddAssignChip::<
    //             SWCurve<Secp256k1Parameters>,
    //             Secp256k1Parameters,
    //         >::new()),
    //         Box::new(WeierstrassDoubleAssignChip::<
    //             SWCurve<Secp256k1Parameters>,
    //             Secp256k1Parameters,
    //         >::new()),
    //         Box::new(KeccakPermuteChip::new()),
    //         Box::new(AddChip::default()),
    //         Box::new(SubChip::default()),
    //         Box::new(BitwiseChip::default()),
    //         Box::new(DivRemChip::default()),
    //         Box::new(MulChip::default()),
    //         Box::new(ShiftRightChip::default()),
    //         Box::new(ShiftLeft::default()),
    //         Box::new(LtChip::default()),
    //         Box::new(FieldLTUChip::default()),
    //         Box::new(ByteChip::<SC::Val>::new()),
    //     ]
    // }

    // /// Chips used in the global segment.
    // ///
    // /// The chips must be ordered to address dependencies, similar to `segment_chips`.
    // pub fn global_chips<SC: StarkConfig>() -> Vec<Box<dyn AirChip<SC>>>
    // where
    //     SC::Val: PrimeField32,
    // {
    //     let memory_init = MemoryGlobalChip::new(MemoryChipKind::Init);
    //     let memory_finalize = MemoryGlobalChip::new(MemoryChipKind::Finalize);
    //     let program_memory_init = MemoryGlobalChip::new(MemoryChipKind::Program);
    //     vec![
    //         Box::new(memory_init),
    //         Box::new(memory_finalize),
    //         Box::new(program_memory_init),
    //     ]
    // }
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
