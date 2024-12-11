use crate::SP1ProofWithPublicValues;
use anyhow::Result;
use std::future::Future;
use std::pin::Pin;

pub trait ProofRequest {
    fn run(
        self,
    ) -> Pin<Box<dyn Future<Output = Result<SP1ProofWithPublicValues>> + Send + 'static>>;
}

pub struct DynProofRequest<'a> {
    inner: Box<dyn ProofRequest + 'a>,
}

impl<'a> DynProofRequest<'a> {
    pub fn new<T: ProofRequest + 'a>(request: T) -> Self {
        Self { inner: Box::new(request) }
    }
}

impl<'a> ProofRequest for DynProofRequest<'a> {
    fn run(
        self,
    ) -> Pin<Box<dyn Future<Output = Result<SP1ProofWithPublicValues>> + Send + 'static>> {
        self.inner.run()
    }
}
