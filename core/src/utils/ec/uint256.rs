use typenum::{U36, U70};

use crate::utils::ec::field::{FieldParameters, NumLimbs};
use num::{BigUint, One};
use serde::{Deserialize, Serialize};

/// Although `U256` is technically not a field, we utilize `FieldParameters` here for compatibility.
/// This approach is specifically for the `FieldOps` multiplication operation, which employs these
/// parameters solely as a modulus, rather than enforcing the requirement of being a proper field.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct U256Field;

impl FieldParameters for U256Field {
    /// The modulus of the field. It is represented as a little-endian array of 33 bytes.
    const MODULUS: &'static [u8] = &[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 1,
    ];

    /// A rough witness-offset estimate given the size of the limbs and the size of the field.
    const WITNESS_OFFSET: usize = 1usize << 13;

    /// The modulus of Uint235 is 2^256.
    fn modulus() -> BigUint {
        BigUint::one() << 256
    }
}

impl NumLimbs for U256Field {
    type Limbs = U36;
    type Witness = U70;
}
