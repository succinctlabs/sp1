use std::{
    future::{Future, IntoFuture},
    pin::Pin,
};

use super::{EnvProver, EnvProvingKey};
use crate::{prover::BaseProveRequest, ProveRequest, Prover, SP1ProofWithPublicValues};
use anyhow::Result;

/// A prover request for the [`EnvProver`].
pub struct EnvProveRequest<'a> {
    pub(crate) base: BaseProveRequest<'a, EnvProver>,
}

impl<'a> ProveRequest<'a, EnvProver> for EnvProveRequest<'a> {
    fn base(&mut self) -> &mut BaseProveRequest<'a, EnvProver> {
        &mut self.base
    }
}

impl<'a> IntoFuture for EnvProveRequest<'a> {
    type Output = Result<SP1ProofWithPublicValues>;

    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        let BaseProveRequest { prover, pk, stdin, mode, context_builder } = self.base;

        match prover {
            EnvProver::Cpu(prover) => match pk {
                EnvProvingKey::Cpu { pk, .. } => {
                    let mut req = prover.prove(pk, stdin);
                    req.base.mode = mode;
                    req.base.context_builder = context_builder;

                    Box::pin(async move { Ok(req.into_future().await?) })
                }
                _ => panic!("Invalid proving key type for CPU prover"),
            },
            EnvProver::Cuda(prover) => match self.base.pk {
                EnvProvingKey::Cuda { pk, .. } => {
                    let mut req = prover.prove(pk, stdin);
                    req.base.mode = mode;
                    req.base.context_builder = context_builder;

                    Box::pin(async move { Ok(req.into_future().await?) })
                }
                _ => panic!("Invalid proving key type for CUDA prover"),
            },
            EnvProver::Mock(prover) => match self.base.pk {
                EnvProvingKey::Mock { pk, .. } => {
                    let mut req = prover.prove(pk, stdin);
                    req.base.mode = mode;
                    req.base.context_builder = context_builder;

                    Box::pin(async move { req.await })
                }
                _ => panic!("Invalid proving key type for Mock prover"),
            },
            EnvProver::Light(prover) => match self.base.pk {
                EnvProvingKey::Light { pk, .. } => {
                    let mut req = prover.prove(pk, stdin);
                    req.base.mode = mode;
                    req.base.context_builder = context_builder;

                    Box::pin(async move { req.await })
                }
                _ => panic!("Invalid proving key type for Light prover"),
            },
            #[cfg(feature = "network")]
            EnvProver::Network(prover) => match self.base.pk {
                EnvProvingKey::Network { pk, .. } => {
                    let mut req = prover.prove(pk, stdin);
                    req.base.mode = mode;
                    req.base.context_builder = context_builder;

                    req.into_future()
                }
                _ => panic!("Invalid proving key type for Network prover"),
            },
        }
    }
}
