use p3_baby_bear::BabyBear;
use sp1_core_executor::ExecutionRecord;

use crate::riscv::RiscvAirDiscriminants;

use super::RiscvAir;

pub trait MachineCostEstimator {
    fn estimate_gas(&self) -> u64;
    fn estimate_cycles(&self) -> u64;
}

impl MachineCostEstimator for ExecutionRecord {
    fn estimate_gas(&self) -> u64 {
        let mut total_gas = 0;
        let mut total_chips = 1 + 1 + 1;
        let (chips, costs) = RiscvAir::<BabyBear>::get_chips_and_costs();

        total_gas += (self.cpu_events.len() as u64) * costs[&RiscvAirDiscriminants::Cpu];
        total_chips += 1;

        total_gas +=
            (self.sha_extend_events.len() as u64) * costs[&RiscvAirDiscriminants::Sha256Extend];
        total_chips += 1;

        total_gas +=
            (self.sha_compress_events.len() as u64) * costs[&RiscvAirDiscriminants::Sha256Compress];
        total_chips += 1;

        total_gas += (self.ed_add_events.len() as u64) * costs[&RiscvAirDiscriminants::Ed25519Add];
        total_chips += 1;

        total_gas += (self.ed_decompress_events.len() as u64)
            * costs[&RiscvAirDiscriminants::Ed25519Decompress];
        total_chips += 1;

        total_gas += (self.k256_decompress_events.len() as u64)
            * costs[&RiscvAirDiscriminants::K256Decompress];
        total_chips += 1;

        total_gas +=
            (self.secp256k1_add_events.len() as u64) * costs[&RiscvAirDiscriminants::Secp256k1Add];
        total_chips += 1;

        total_gas += (self.secp256k1_double_events.len() as u64)
            * costs[&RiscvAirDiscriminants::Secp256k1Double];
        total_chips += 1;

        total_gas +=
            (self.keccak_permute_events.len() as u64) * costs[&RiscvAirDiscriminants::KeccakP];
        total_chips += 1;

        total_gas += (self.bn254_add_events.len() as u64) * costs[&RiscvAirDiscriminants::Bn254Add];
        total_chips += 1;

        total_gas +=
            (self.bn254_double_events.len() as u64) * costs[&RiscvAirDiscriminants::Bn254Double];
        total_chips += 1;

        total_gas +=
            (self.bls12381_add_events.len() as u64) * costs[&RiscvAirDiscriminants::Bls12381Add];
        total_chips += 1;

        total_gas += (self.bls12381_double_events.len() as u64)
            * costs[&RiscvAirDiscriminants::Bls12381Double];
        total_chips += 1;

        total_gas +=
            (self.uint256_mul_events.len() as u64) * costs[&RiscvAirDiscriminants::Uint256Mul];
        total_chips += 1;

        total_gas +=
            (self.bls12381_fp_events.len() as u64) * costs[&RiscvAirDiscriminants::Bls12381Fp];
        total_chips += 1;

        total_gas += (self.bls12381_fp2_addsub_events.len() as u64)
            * costs[&RiscvAirDiscriminants::Bls12381Fp2AddSub];
        total_chips += 1;

        total_gas += (self.bls12381_fp2_mul_events.len() as u64)
            * costs[&RiscvAirDiscriminants::Bls12381Fp2Mul];
        total_chips += 1;

        total_gas += (self.bn254_fp_events.len() as u64) * costs[&RiscvAirDiscriminants::Bn254Fp];
        total_chips += 1;

        total_gas += (self.bn254_fp2_addsub_events.len() as u64)
            * costs[&RiscvAirDiscriminants::Bn254Fp2AddSub];
        total_chips += 1;

        total_gas +=
            (self.bn254_fp2_mul_events.len() as u64) * costs[&RiscvAirDiscriminants::Bn254Fp2Mul];
        total_chips += 1;

        total_gas += (self.bls12381_decompress_events.len() as u64)
            * costs[&RiscvAirDiscriminants::Bls12381Decompress];
        total_chips += 1;

        total_gas += (self.divrem_events.len() as u64) * costs[&RiscvAirDiscriminants::DivRem];
        total_chips += 1;

        total_gas += (self.add_events.len() as u64) * costs[&RiscvAirDiscriminants::Add];
        total_chips += 1;

        total_gas += (self.bitwise_events.len() as u64) * costs[&RiscvAirDiscriminants::Bitwise];
        total_chips += 1;

        total_gas += (self.mul_events.len() as u64) * costs[&RiscvAirDiscriminants::Mul];
        total_chips += 1;

        total_gas +=
            (self.shift_right_events.len() as u64) * costs[&RiscvAirDiscriminants::ShiftRight];
        total_chips += 1;

        total_gas +=
            (self.shift_left_events.len() as u64) * costs[&RiscvAirDiscriminants::ShiftLeft];
        total_chips += 1;

        total_gas += (self.lt_events.len() as u64) * costs[&RiscvAirDiscriminants::Lt];
        total_chips += 1;

        total_gas += (self.memory_initialize_events.len() as u64)
            * costs[&RiscvAirDiscriminants::MemoryInit];
        total_chips += 1;

        total_gas +=
            (self.memory_finalize_events.len() as u64) * costs[&RiscvAirDiscriminants::MemoryFinal];
        total_chips += 1;

        assert_eq!(total_chips, chips.len(), "chip count mismatch");
        total_gas
    }

    fn estimate_cycles(&self) -> u64 {
        let costs = RiscvAir::<BabyBear>::costs();
        let cpu_gas = costs[&RiscvAirDiscriminants::Cpu];
        let total_gas = self.estimate_gas();
        total_gas / cpu_gas
    }
}
