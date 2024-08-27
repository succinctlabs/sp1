use p3_baby_bear::BabyBear;
use sp1_core_executor::{syscalls::SyscallCode, ExecutionReport, Opcode};

use crate::riscv::RiscvAirDiscriminants;

use super::RiscvAir;

pub trait CostEstimator {
    /// Estimates the trace area of the execution.
    fn estimate_area(&self) -> u64;

    /// Estimates the proving cost of the execution in terms of "gas".
    ///
    /// The gas is defined as the trace area divided by the lowerbound per cpu cycle.
    ///
    /// NOTE: This is an approximation and may not be accurate. For example, it does not currently
    /// account for dependencies.
    fn estimate_gas(&self) -> u64 {
        let costs = RiscvAir::<BabyBear>::costs();
        let cpu_gas = costs[&RiscvAirDiscriminants::Cpu];
        let total_gas = self.estimate_area();
        total_gas / cpu_gas
    }
}

impl CostEstimator for ExecutionReport {
    fn estimate_area(&self) -> u64 {
        let mut total_area = 0;
        let mut total_chips = 3;
        let (chips, costs) = RiscvAir::<BabyBear>::get_chips_and_costs();

        let cpu_events = self.total_instruction_count();
        total_area += (cpu_events as u64) * costs[&RiscvAirDiscriminants::Cpu];
        total_chips += 1;

        let sha_extend_events = *self.syscall_counts.get(&SyscallCode::SHA_EXTEND).unwrap_or(&0);
        total_area += (sha_extend_events as u64) * costs[&RiscvAirDiscriminants::Sha256Extend];
        total_chips += 1;

        let sha_compress_events =
            *self.syscall_counts.get(&SyscallCode::SHA_COMPRESS).unwrap_or(&0);
        total_area += (sha_compress_events as u64) * costs[&RiscvAirDiscriminants::Sha256Compress];
        total_chips += 1;

        let ed_add_events = *self.syscall_counts.get(&SyscallCode::ED_ADD).unwrap_or(&0);
        total_area += (ed_add_events as u64) * costs[&RiscvAirDiscriminants::Ed25519Add];
        total_chips += 1;

        let ed_decompress_events =
            *self.syscall_counts.get(&SyscallCode::ED_DECOMPRESS).unwrap_or(&0);
        total_area +=
            (ed_decompress_events as u64) * costs[&RiscvAirDiscriminants::Ed25519Decompress];
        total_chips += 1;

        let k256_decompress_events =
            *self.syscall_counts.get(&SyscallCode::SECP256K1_DECOMPRESS).unwrap_or(&0);
        total_area +=
            (k256_decompress_events as u64) * costs[&RiscvAirDiscriminants::K256Decompress];
        total_chips += 1;

        let secp256k1_add_events =
            *self.syscall_counts.get(&SyscallCode::SECP256K1_ADD).unwrap_or(&0);
        total_area += (secp256k1_add_events as u64) * costs[&RiscvAirDiscriminants::Secp256k1Add];
        total_chips += 1;

        let secp256k1_double_events =
            *self.syscall_counts.get(&SyscallCode::SECP256K1_DOUBLE).unwrap_or(&0);
        total_area +=
            (secp256k1_double_events as u64) * costs[&RiscvAirDiscriminants::Secp256k1Double];
        total_chips += 1;

        let keccak256_permute_events =
            *self.syscall_counts.get(&SyscallCode::KECCAK_PERMUTE).unwrap_or(&0);
        total_area += (keccak256_permute_events as u64) * costs[&RiscvAirDiscriminants::KeccakP];
        total_chips += 1;

        let bn254_add_events = *self.syscall_counts.get(&SyscallCode::BN254_ADD).unwrap_or(&0);
        total_area += (bn254_add_events as u64) * costs[&RiscvAirDiscriminants::Bn254Add];
        total_chips += 1;

        let bn254_double_events =
            *self.syscall_counts.get(&SyscallCode::BN254_DOUBLE).unwrap_or(&0);
        total_area += (bn254_double_events as u64) * costs[&RiscvAirDiscriminants::Bn254Double];
        total_chips += 1;

        let bls12381_add_events =
            *self.syscall_counts.get(&SyscallCode::BLS12381_ADD).unwrap_or(&0);
        total_area += (bls12381_add_events as u64) * costs[&RiscvAirDiscriminants::Bls12381Add];
        total_chips += 1;

        let bls12381_double_events =
            *self.syscall_counts.get(&SyscallCode::BLS12381_DOUBLE).unwrap_or(&0);
        total_area +=
            (bls12381_double_events as u64) * costs[&RiscvAirDiscriminants::Bls12381Double];
        total_chips += 1;

        let uint256_mul_events = *self.syscall_counts.get(&SyscallCode::UINT256_MUL).unwrap_or(&0);
        total_area += (uint256_mul_events as u64) * costs[&RiscvAirDiscriminants::Uint256Mul];
        total_chips += 1;

        let bls12381_fp_events =
            *self.syscall_counts.get(&SyscallCode::BLS12381_FP_ADD).unwrap_or(&0)
                + *self.syscall_counts.get(&SyscallCode::BLS12381_FP_SUB).unwrap_or(&0)
                + *self.syscall_counts.get(&SyscallCode::BLS12381_FP_MUL).unwrap_or(&0);
        total_area += (bls12381_fp_events as u64) * costs[&RiscvAirDiscriminants::Bls12381Fp];
        total_chips += 1;

        let bls12381_fp2_addsub_events =
            *self.syscall_counts.get(&SyscallCode::BLS12381_FP2_ADD).unwrap_or(&0)
                + *self.syscall_counts.get(&SyscallCode::BLS12381_FP2_SUB).unwrap_or(&0);
        total_area +=
            (bls12381_fp2_addsub_events as u64) * costs[&RiscvAirDiscriminants::Bls12381Fp2AddSub];
        total_chips += 1;

        let bls12381_fp2_mul_events =
            *self.syscall_counts.get(&SyscallCode::BLS12381_FP2_MUL).unwrap_or(&0);
        total_area +=
            (bls12381_fp2_mul_events as u64) * costs[&RiscvAirDiscriminants::Bls12381Fp2Mul];
        total_chips += 1;

        let bn254_fp_events = *self.syscall_counts.get(&SyscallCode::BN254_FP_ADD).unwrap_or(&0)
            + *self.syscall_counts.get(&SyscallCode::BN254_FP_SUB).unwrap_or(&0)
            + *self.syscall_counts.get(&SyscallCode::BN254_FP_MUL).unwrap_or(&0);
        total_area += (bn254_fp_events as u64) * costs[&RiscvAirDiscriminants::Bn254Fp];
        total_chips += 1;

        let bn254_fp2_addsub_events =
            *self.syscall_counts.get(&SyscallCode::BN254_FP2_ADD).unwrap_or(&0)
                + *self.syscall_counts.get(&SyscallCode::BN254_FP2_SUB).unwrap_or(&0);
        total_area +=
            (bn254_fp2_addsub_events as u64) * costs[&RiscvAirDiscriminants::Bn254Fp2AddSub];
        total_chips += 1;

        let bn254_fp2_mul_events =
            *self.syscall_counts.get(&SyscallCode::BN254_FP2_MUL).unwrap_or(&0);
        total_area += (bn254_fp2_mul_events as u64) * costs[&RiscvAirDiscriminants::Bn254Fp2Mul];
        total_chips += 1;

        let bls12381_decompress_events =
            *self.syscall_counts.get(&SyscallCode::BLS12381_DECOMPRESS).unwrap_or(&0);
        total_area +=
            (bls12381_decompress_events as u64) * costs[&RiscvAirDiscriminants::Bls12381Decompress];
        total_chips += 1;

        let divrem_events = *self.opcode_counts.get(&Opcode::DIV).unwrap_or(&0)
            + *self.opcode_counts.get(&Opcode::REM).unwrap_or(&0)
            + *self.opcode_counts.get(&Opcode::DIVU).unwrap_or(&0)
            + *self.opcode_counts.get(&Opcode::REMU).unwrap_or(&0);
        total_area += (divrem_events as u64) * costs[&RiscvAirDiscriminants::DivRem];
        total_chips += 1;

        let addsub_events = *self.opcode_counts.get(&Opcode::ADD).unwrap_or(&0)
            + *self.opcode_counts.get(&Opcode::SUB).unwrap_or(&0);
        total_area += (addsub_events as u64) * costs[&RiscvAirDiscriminants::Add];
        total_chips += 1;

        let bitwise_events = *self.opcode_counts.get(&Opcode::AND).unwrap_or(&0)
            + *self.opcode_counts.get(&Opcode::OR).unwrap_or(&0)
            + *self.opcode_counts.get(&Opcode::XOR).unwrap_or(&0);
        total_area += (bitwise_events as u64) * costs[&RiscvAirDiscriminants::Bitwise];
        total_chips += 1;

        let mul_events = *self.opcode_counts.get(&Opcode::MUL).unwrap_or(&0)
            + *self.opcode_counts.get(&Opcode::MULH).unwrap_or(&0)
            + *self.opcode_counts.get(&Opcode::MULHU).unwrap_or(&0)
            + *self.opcode_counts.get(&Opcode::MULHSU).unwrap_or(&0);
        total_area += (mul_events as u64) * costs[&RiscvAirDiscriminants::Mul];
        total_chips += 1;

        let shift_right_events = *self.opcode_counts.get(&Opcode::SRL).unwrap_or(&0)
            + *self.opcode_counts.get(&Opcode::SRA).unwrap_or(&0);
        total_area += (shift_right_events as u64) * costs[&RiscvAirDiscriminants::ShiftRight];
        total_chips += 1;

        let shift_left_events = *self.opcode_counts.get(&Opcode::SLL).unwrap_or(&0);
        total_area += (shift_left_events as u64) * costs[&RiscvAirDiscriminants::ShiftLeft];
        total_chips += 1;

        let lt_events = *self.opcode_counts.get(&Opcode::SLT).unwrap_or(&0)
            + *self.opcode_counts.get(&Opcode::SLTU).unwrap_or(&0);
        total_area += (lt_events as u64) * costs[&RiscvAirDiscriminants::Lt];
        total_chips += 1;

        let memory_initialize_events = self.touched_memory_addresses;
        total_area += (memory_initialize_events as u64) * costs[&RiscvAirDiscriminants::MemoryInit];
        total_chips += 1;

        let memory_finalize_events = self.touched_memory_addresses;
        total_area += (memory_finalize_events as u64) * costs[&RiscvAirDiscriminants::MemoryFinal];
        total_chips += 1;

        assert_eq!(total_chips, chips.len(), "chip count mismatch");
        total_area
    }
}
