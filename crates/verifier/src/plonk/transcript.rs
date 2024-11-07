use alloc::{collections::btree_map::BTreeMap, string::String, vec::Vec};
use sha2::{Digest, Sha256};

use crate::PlonkError;

/// A challenge in the transcript, derived with randomness from `bindings` and the previous
/// challenge.
#[derive(Clone, Debug)]
pub(crate) struct Challenge {
    position: usize,
    bindings: Vec<Vec<u8>>,
    value: Vec<u8>,
    is_computed: bool,
}

/// A Fiat-Shamir transcript.
#[derive(Clone, Debug)]
pub(crate) struct Transcript {
    pub(crate) h: Sha256,

    pub(crate) challenges: BTreeMap<String, Challenge>,
    previous_challenge: Option<Challenge>,
}

impl Transcript {
    /// Creates a new transcript.
    pub(crate) fn new(challenges_id: Option<Vec<String>>) -> Result<Self, PlonkError> {
        let h = Sha256::new();

        if let Some(challenges_id) = challenges_id {
            let mut challenges = BTreeMap::new();
            for (position, id) in challenges_id.iter().enumerate() {
                challenges.insert(
                    id.clone(),
                    Challenge {
                        position,
                        bindings: Vec::new(),
                        value: Vec::new(),
                        is_computed: false,
                    },
                );
            }

            Ok(Transcript { h, challenges, previous_challenge: None })
        } else {
            Ok(Transcript { h, challenges: BTreeMap::new(), previous_challenge: None })
        }
    }

    /// Binds some data to a challenge.
    pub(crate) fn bind(&mut self, id: &str, binding: &[u8]) -> Result<(), PlonkError> {
        let current_challenge = self.challenges.get_mut(id).ok_or(PlonkError::ChallengeNotFound)?;
        if current_challenge.is_computed {
            return Err(PlonkError::ChallengeAlreadyComputed);
        }

        current_challenge.bindings.push(binding.to_vec());

        Ok(())
    }

    /// Computes a challenge and returns its value.
    ///
    /// Challenges must be computed in order. The previous challenge is automatically fed into the
    /// challenge currently being computed.
    pub(crate) fn compute_challenge(&mut self, challenge_id: &str) -> Result<Vec<u8>, PlonkError> {
        let challenge =
            self.challenges.get_mut(challenge_id).ok_or(PlonkError::ChallengeNotFound)?;

        if challenge.is_computed {
            return Ok(challenge.value.clone());
        }

        // Reset the hash function before and after computing the challenge
        self.h.reset();

        self.h.update(challenge_id.as_bytes());

        if challenge.position != 0 {
            if let Some(previous_challenge) = &self.previous_challenge {
                if previous_challenge.position != challenge.position - 1 {
                    return Err(PlonkError::PreviousChallengeNotComputed);
                }
                self.h.update(&previous_challenge.value)
            } else {
                return Err(PlonkError::PreviousChallengeNotComputed);
            }
        }

        for binding in challenge.bindings.iter() {
            self.h.update(binding)
        }

        let res = self.h.finalize_reset();

        challenge.value = res.to_vec();
        challenge.is_computed = true;

        // Update the previous challenge reference
        self.previous_challenge = Some(challenge.clone());

        Ok(res.to_vec())
    }
}
