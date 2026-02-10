use super::{EnvProver, EnvProvingKey};
use crate::{
    blocking::{prover::BaseProveRequest, ProveRequest, Prover},
    SP1ProofWithPublicValues,
};
use anyhow::Result;

/// A prover request for the [`EnvProver`].
pub struct EnvProveRequest<'a> {
    pub(crate) base: BaseProveRequest<'a, EnvProver>,
}

impl<'a> ProveRequest<'a, EnvProver> for EnvProveRequest<'a> {
    fn base(&mut self) -> &mut BaseProveRequest<'a, EnvProver> {
        &mut self.base
    }

    fn run(self) -> Result<SP1ProofWithPublicValues> {
        let BaseProveRequest { prover, pk, stdin, mode, context_builder } = self.base;
        match prover {
            EnvProver::Cpu(prover) => match pk {
                EnvProvingKey::Cpu { pk, .. } => {
                    let mut req = prover.prove(pk, stdin);
                    req.base.mode = mode;
                    req.base.context_builder = context_builder;
                    Ok(req.run()?)
                }
                _ => panic!("Invalid proving key type for CPU prover"),
            },
            EnvProver::Cuda(prover) => match self.base.pk {
                EnvProvingKey::Cuda { pk, .. } => {
                    let mut req = prover.prove(pk, stdin);
                    req.base.mode = mode;
                    req.base.context_builder = context_builder;
                    Ok(req.run()?)
                }
                _ => panic!("Invalid proving key type for CUDA prover"),
            },
            EnvProver::Mock(prover) => match self.base.pk {
                EnvProvingKey::Mock { pk, .. } => {
                    let mut req = prover.prove(pk, stdin);
                    req.base.mode = mode;
                    req.base.context_builder = context_builder;
                    Ok(req.run()?)
                }
                _ => panic!("Invalid proving key type for Mock prover"),
            },
            EnvProver::Light(prover) => match self.base.pk {
                EnvProvingKey::Light { pk, .. } => {
                    let mut req = prover.prove(pk, stdin);
                    req.base.mode = mode;
                    req.base.context_builder = context_builder;
                    Ok(req.run()?)
                }
                _ => panic!("Invalid proving key type for Light prover"),
            },
        }
    }
}
