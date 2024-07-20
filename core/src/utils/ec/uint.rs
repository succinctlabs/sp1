use typenum::{U32, U63};

use num::{BigUint, One};
use serde::{Deserialize, Serialize};

use crate::operations::field::params::{FieldParameters, NumLimbs};

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
    const WITNESS_OFFSET: usize = 1usize << 14;

    /// The modulus of Uint235 is 2^256.
    fn modulus() -> BigUint {
        BigUint::one() << 256
    }
}

impl NumLimbs for U256Field {
    type Limbs = U32;
    // Note we use one more limb than usual because for mulmod with mod 1<<256, we need an extra limb.
    type Witness = U63;
}
