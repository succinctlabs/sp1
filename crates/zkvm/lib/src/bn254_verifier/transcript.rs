use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::bn254_verifier::constants::{
    ERR_CHALLENGE_ALREADY_COMPUTED, ERR_CHALLENGE_NOT_FOUND, ERR_PREVIOUS_CHALLENGE_NOT_COMPUTED,
};

#[derive(Clone, Debug)]
pub(crate) struct Challenge {
    position: usize,
    bindings: Vec<Vec<u8>>,
    value: Vec<u8>,
    is_computed: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct Transcript {
    pub(crate) h: Sha256,

    pub(crate) challenges: HashMap<String, Challenge>,
    previous_challenge: Option<Challenge>,
}

impl Transcript {
    pub(crate) fn new(challenges_id: Option<Vec<String>>) -> Result<Self> {
        let h = Sha256::new();

        if let Some(challenges_id) = challenges_id {
            let mut challenges = HashMap::new();
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
            Ok(Transcript { h, challenges: HashMap::new(), previous_challenge: None })
        }
    }

    pub(crate) fn bind(&mut self, id: &str, binding: &[u8]) -> Result<()> {
        let current_challenge = self.challenges.get_mut(id).expect(ERR_CHALLENGE_NOT_FOUND);
        if current_challenge.is_computed {
            return Err(anyhow!(ERR_CHALLENGE_ALREADY_COMPUTED));
        }

        current_challenge.bindings.push(binding.to_vec());

        Ok(())
    }

    pub(crate) fn compute_challenge(&mut self, challenge_id: &str) -> Result<Vec<u8>> {
        let challenge = match self.challenges.get_mut(challenge_id) {
            Some(challenge) => challenge,
            None => {
                return Err(anyhow!(ERR_CHALLENGE_NOT_FOUND));
            }
        };

        if challenge.is_computed {
            return Ok(challenge.value.clone());
        }

        // Reset the hash function before and after computing the challenge
        self.h.reset();

        self.h.update(challenge_id.as_bytes());

        if challenge.position != 0 {
            if let Some(previous_challenge) = &self.previous_challenge {
                if previous_challenge.position != challenge.position - 1 {
                    return Err(anyhow!(ERR_PREVIOUS_CHALLENGE_NOT_COMPUTED));
                }
                self.h.update(&previous_challenge.value)
            } else {
                return Err(anyhow!(ERR_PREVIOUS_CHALLENGE_NOT_COMPUTED));
            }
        }

        for binding in challenge.bindings.iter() {
            self.h.update(binding)
        }

        let res = self.h.finalize_reset();

        challenge.value = res.to_vec().clone();
        challenge.is_computed = true;

        // Update the previous challenge reference
        self.previous_challenge = Some(challenge.clone());

        Ok(res.to_vec())
    }
}
