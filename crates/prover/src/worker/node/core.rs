use std::sync::Arc;

use sp1_core_executor::{ExecutionReport, Program, SP1Context, SP1CoreOpts};
use sp1_core_machine::io::SP1Stdin;
use sp1_core_machine::riscv::RiscvAir;
use sp1_hypercube::{Machine, SP1VerifyingKey};
use sp1_primitives::{io::SP1PublicValues, SP1Field};
use sp1_verifier::SP1Proof;
use tracing::instrument;

use crate::{
    verify::{SP1Verifier, VerifierRecursionVks},
    worker::{execute_with_options_and_machine, SP1ExecutorConfig},
    SP1CoreProofData,
};

struct SP1NodeCoreInner {
    verifier: SP1Verifier,
    opts: SP1CoreOpts,
}

pub struct SP1NodeCore {
    inner: Arc<SP1NodeCoreInner>,
}

impl Clone for SP1NodeCore {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl SP1NodeCore {
    pub fn new(verifier: SP1Verifier, opts: SP1CoreOpts) -> Self {
        Self { inner: Arc::new(SP1NodeCoreInner { verifier, opts }) }
    }

    pub fn machine(&self) -> &Machine<SP1Field, RiscvAir<SP1Field>> {
        self.inner.verifier.core.machine()
    }

    #[instrument(name = "execute_program", skip_all)]
    pub async fn execute(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
        context: SP1Context<'static>,
    ) -> anyhow::Result<(SP1PublicValues, [u8; 32], ExecutionReport)> {
        let program = Program::from(elf)
            .map_err(|e| anyhow::anyhow!("failed to dissassemble program: {}", e))?;
        let program = Arc::new(program);
        let (public_values, public_value_digest, report) = execute_with_options_and_machine(
            program,
            stdin,
            context,
            self.inner.opts.clone(),
            SP1ExecutorConfig::default(),
            self.machine().clone(),
        )
        .await?;
        Ok((public_values, public_value_digest, report))
    }

    pub fn verify(&self, vk: &SP1VerifyingKey, proof: &SP1Proof) -> anyhow::Result<()> {
        // Verify the underlying proof.
        match proof {
            SP1Proof::Core(proof) => {
                let core_proof = SP1CoreProofData(proof.clone());
                self.inner.verifier.verify(&core_proof, vk)?;
            }
            SP1Proof::Compressed(proof) => {
                self.inner.verifier.verify_compressed(proof, vk)?;
            }
            SP1Proof::Plonk(proof) => {
                self.inner.verifier.verify_plonk_bn254(proof, vk)?;
            }
            SP1Proof::Groth16(proof) => {
                self.inner.verifier.verify_groth16_bn254(proof, vk)?;
            }
        }

        Ok(())
    }

    pub fn recursion_vks(&self) -> VerifierRecursionVks {
        self.inner.verifier.recursion_vks.clone()
    }

    pub fn vk_verification(&self) -> bool {
        self.inner.verifier.vk_verification()
    }

    pub fn allowed_vk_height(&self) -> usize {
        let num_shapes = self.inner.verifier.recursion_vks.num_keys();
        num_shapes.next_power_of_two().ilog2() as usize
    }

    #[cfg(test)]
    pub(crate) fn wrap_vk(
        &self,
    ) -> &sp1_hypercube::MachineVerifyingKey<sp1_primitives::SP1OuterGlobalContext> {
        &self.inner.verifier.wrap_vk
    }
}
