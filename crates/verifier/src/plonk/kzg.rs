use alloc::{string::ToString, vec, vec::Vec};
use bn::{pairing_batch, AffineG1, Fr, G1, G2};

use crate::{error::Error, plonk::transcript::Transcript};

use super::{converter::g1_to_bytes, error::PlonkError, GAMMA, U};

pub(crate) type Digest = AffineG1;

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) struct E2 {
    pub(crate) a0: Fr,
    pub(crate) a1: Fr,
}

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) struct LineEvaluationAff {
    pub(crate) r0: E2,
    pub(crate) r1: E2,
}

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) struct KZGVerifyingKey {
    pub(crate) g2: [G2; 2], // [G₂, [α]G₂]
    pub(crate) g1: G1,
    // Precomputed pairing lines corresponding to G₂, [α]G₂
    pub(crate) lines: [[[LineEvaluationAff; 66]; 2]; 2],
}

#[derive(Clone, Debug)]
pub(crate) struct BatchOpeningProof {
    pub(crate) h: AffineG1,
    pub(crate) claimed_values: Vec<Fr>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct OpeningProof {
    pub(crate) h: AffineG1,
    pub(crate) claimed_value: Fr,
}

/// Derives the folding factor for the batched opening proof.
///
/// Uses a separate transcript than the main transcript used for the other fiat shamir randomness.
fn derive_gamma(
    point: &Fr,
    digests: Vec<Digest>,
    claimed_values: Vec<Fr>,
    data_transcript: Option<Vec<u8>>,
) -> Result<Fr, PlonkError> {
    let mut transcript = Transcript::new(Some([GAMMA.to_string()].to_vec()))?;
    transcript.bind(GAMMA, &point.into_u256().to_bytes_be())?;

    for digest in digests.iter() {
        transcript.bind(GAMMA, &g1_to_bytes(digest)?)?;
    }

    for claimed_value in claimed_values.iter() {
        transcript.bind(GAMMA, &claimed_value.into_u256().to_bytes_be())?;
    }

    if let Some(data_transcript) = data_transcript {
        transcript.bind(GAMMA, &data_transcript)?;
    }

    let gamma_byte = transcript.compute_challenge(GAMMA)?;

    let x = Fr::from_bytes_be_mod_order(gamma_byte.as_slice())
        .map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;

    Ok(x)
}

fn fold(di: Vec<Digest>, fai: Vec<Fr>, ci: Vec<Fr>) -> Result<(AffineG1, Fr), PlonkError> {
    let nb_digests = di.len();
    let mut folded_evaluations = Fr::zero();

    for i in 0..nb_digests {
        folded_evaluations += fai[i] * ci[i];
    }

    let folded_digests = AffineG1::msm(&di, &ci);

    Ok((folded_digests, folded_evaluations))
}

pub(crate) fn fold_proof(
    digests: Vec<Digest>,
    batch_opening_proof: &BatchOpeningProof,
    point: &Fr,
    data_transcript: Option<Vec<u8>>,
    global_transcript: &mut Transcript,
) -> Result<(OpeningProof, AffineG1), PlonkError> {
    let nb_digests = digests.len();

    if nb_digests != batch_opening_proof.claimed_values.len() {
        return Err(PlonkError::InvalidNumberOfDigests);
    }

    let gamma = derive_gamma(
        point,
        digests.clone(),
        batch_opening_proof.claimed_values.clone(),
        data_transcript,
    )?;

    // Bind gamma to the transcript to challenge U.
    global_transcript.bind(U, &gamma.into_u256().to_bytes_be())?;

    let mut gammai = vec![Fr::zero(); nb_digests];
    gammai[0] = Fr::one();

    if nb_digests > 1 {
        gammai[1] = gamma;
    }

    for i in 2..nb_digests {
        gammai[i] = gammai[i - 1] * gamma;
    }

    let (folded_digests, folded_evaluations) =
        fold(digests, batch_opening_proof.claimed_values.clone(), gammai)?;

    let open_proof = OpeningProof { h: batch_opening_proof.h, claimed_value: folded_evaluations };

    Ok((open_proof, folded_digests))
}

pub(crate) fn batch_verify_multi_points(
    digests: Vec<Digest>,
    proofs: Vec<OpeningProof>,
    points: Vec<Fr>,
    u: Fr,
    vk: &KZGVerifyingKey,
) -> Result<(), PlonkError> {
    let nb_digests = digests.len();
    let nb_proofs = proofs.len();
    let nb_points = points.len();

    if nb_digests != nb_proofs {
        return Err(PlonkError::InvalidNumberOfDigests);
    }

    if nb_digests != nb_points {
        return Err(PlonkError::InvalidNumberOfDigests);
    }

    if nb_digests == 1 {
        unimplemented!();
    }

    let mut random_numbers = Vec::with_capacity(nb_digests);
    random_numbers.push(Fr::one());
    for i in 1..nb_digests {
        random_numbers.push(u * random_numbers[i - 1]);
    }

    let mut quotients = Vec::with_capacity(nb_proofs);
    for item in proofs.iter().take(nb_digests) {
        quotients.push(item.h);
    }

    let mut folded_quotients = AffineG1::msm(&quotients, &random_numbers);
    let mut evals = Vec::with_capacity(nb_digests);

    for item in proofs.iter().take(nb_digests) {
        evals.push(item.claimed_value);
    }

    let (mut folded_digests, folded_evals) = fold(digests, evals, random_numbers.clone())?;
    let folded_evals_commit = vk.g1 * folded_evals;
    folded_digests = folded_digests - folded_evals_commit.into();

    for i in 0..random_numbers.len() {
        random_numbers[i] *= points[i];
    }
    let folded_points_quotients = AffineG1::msm(&quotients, &random_numbers);

    folded_digests = folded_digests + folded_points_quotients;
    folded_quotients = -folded_quotients;

    let pairing_result =
        pairing_batch(&[(folded_digests.into(), vk.g2[0]), (folded_quotients.into(), vk.g2[1])]);

    if !pairing_result.is_one() {
        return Err(PlonkError::PairingCheckFailed);
    }

    Ok(())
}
