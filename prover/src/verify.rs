use sp1_core::stark::{MachineProof, ProgramVerificationError, RiscvAir, StarkGenericConfig};

use crate::{CoreSC, SP1CoreProof, SP1ReduceProof, SP1VerifyingKey};

impl SP1CoreProof {
    pub fn verify(&self, vk: &SP1VerifyingKey) -> Result<(), ProgramVerificationError> {
        let core_machine = RiscvAir::machine(CoreSC::default());
        let mut challenger = core_machine.config().challenger();
        let machine_proof = MachineProof {
            shard_proofs: self.shard_proofs.clone(),
        };
        core_machine.verify(&vk.vk, &machine_proof, &mut challenger)?;
        Ok(())
    }
}

impl SP1ReduceProof<CoreSC> {
    pub fn verify(&self, _vk: &SP1VerifyingKey) -> Result<(), ProgramVerificationError> {
        todo!()
    }
}
