use alloc::vec::Vec;
use bn::{pairing_batch, AffineG1, AffineG2, Fr, Gt, G1, G2};

use super::error::Groth16Error;

/// G1 elements of the verification key.
#[derive(Clone, PartialEq)]
pub(crate) struct Groth16G1 {
    pub(crate) alpha: AffineG1,
    pub(crate) k: Vec<AffineG1>,
}

/// G2 elements of the verification key.
#[derive(Clone, PartialEq)]
pub(crate) struct Groth16G2 {
    pub(crate) beta: AffineG2,
    pub(crate) delta: AffineG2,
    pub(crate) gamma: AffineG2,
}

/// Verification key for the Groth16 proof.
#[derive(Clone, PartialEq)]
pub(crate) struct Groth16VerifyingKey {
    pub(crate) g1: Groth16G1,
    pub(crate) g2: Groth16G2,
}

/// Proof for the Groth16 verification.
pub(crate) struct Groth16Proof {
    pub(crate) ar: AffineG1,
    pub(crate) krs: AffineG1,
    pub(crate) bs: AffineG2,
}

/// Prepare the inputs for the Groth16 verification by combining the public inputs with the
/// corresponding elements of the verification key.
fn prepare_inputs(vk: Groth16VerifyingKey, public_inputs: &[Fr]) -> Result<G1, Groth16Error> {
    if (public_inputs.len() + 1) != vk.g1.k.len() {
        return Err(Groth16Error::PrepareInputsFailed);
    }

    Ok(public_inputs
        .iter()
        .zip(vk.g1.k.iter().skip(1))
        .fold(vk.g1.k[0], |acc, (i, b)| acc + (*b * *i))
        .into())
}

/// Verify the Groth16 proof
///
/// First, prepare the public inputs by folding them with the verification key.
/// Then, verify the proof by checking the pairing equation.
pub(crate) fn verify_groth16_raw(
    vk: &Groth16VerifyingKey,
    proof: &Groth16Proof,
    public_inputs: &[Fr],
) -> Result<bool, Groth16Error> {
    let prepared_inputs = prepare_inputs(vk.clone(), public_inputs)?;

    Ok(pairing_batch(&[
        (-Into::<G1>::into(proof.ar), proof.bs.into()),
        (prepared_inputs, vk.g2.gamma.into()),
        (proof.krs.into(), vk.g2.delta.into()),
        (vk.g1.alpha.into(), -Into::<G2>::into(vk.g2.beta)),
    ]) == Gt::one())
}
