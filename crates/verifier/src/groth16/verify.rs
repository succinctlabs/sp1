use alloc::vec::Vec;
use bn::{pairing_batch, AffineG1, AffineG2, Fr, Gt, G1, G2};

use super::error::Groth16Error;

#[derive(Clone, PartialEq)]
pub struct Groth16G1 {
    pub alpha: AffineG1,
    pub beta: AffineG1,
    pub delta: AffineG1,
    pub k: Vec<AffineG1>,
}

#[derive(Clone, PartialEq)]
pub struct Groth16G2 {
    pub beta: AffineG2,
    pub delta: AffineG2,
    pub gamma: AffineG2,
}

#[derive(Clone, PartialEq)]
pub struct Groth16VerifyingKey {
    pub g1: Groth16G1,
    pub g2: Groth16G2,
    pub public_and_commitment_committed: Vec<Vec<u32>>,
}

#[allow(dead_code)]
pub struct Groth16Proof {
    pub ar: AffineG1,
    pub krs: AffineG1,
    pub bs: AffineG2,
    pub commitments: Vec<AffineG1>,
    pub commitment_pok: AffineG1,
}

#[derive(Clone, PartialEq)]
pub struct PreparedVerifyingKey {
    pub vk: Groth16VerifyingKey,
    pub alpha_g1_beta_g2: Gt,
    pub gamma_g2_neg_pc: G2,
    pub delta_g2_neg_pc: G2,
}

// Prepare the inputs for the Groth16 verification by combining the public inputs with the corresponding elements of the verification key.
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

pub fn verify_groth16(
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
