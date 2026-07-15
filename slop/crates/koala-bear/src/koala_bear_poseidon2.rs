use std::array::from_fn;

use crate::{DiffusionMatrixKoalaBear, KoalaBear};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use slop_algebra::{extension::BinomialExtensionField, AbstractField};
use slop_challenger::{DuplexChallenger, IopCtx};
use slop_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use slop_symmetric::{PaddingFreeSponge, TruncatedPermutation};

pub(crate) fn string_to_koala_bear(hex_string: String) -> KoalaBear {
    KoalaBear::from_canonical_u64(
        u64::from_str_radix(&hex_string[2..], 16).expect("Invalid KoalaBear hex string"),
    )
}

#[derive(Debug, Clone, Default, Copy, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct Poseidon2KoalaBearConfig<const STATE_WIDTH: usize = 16>;

pub type KoalaPerm =
    Poseidon2<KoalaBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixKoalaBear, 16, 3>;

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq, Debug, Default)]
pub struct KoalaBearDegree4Duplex;

pub const KOALA_BEAR_DIGEST_SIZE: usize = 8;

impl IopCtx for KoalaBearDegree4Duplex {
    type F = KoalaBear;
    type EF = BinomialExtensionField<KoalaBear, 4>;
    type Digest = [KoalaBear; KOALA_BEAR_DIGEST_SIZE];
    type Challenger = DuplexChallenger<Self::F, KoalaPerm, 16, 8>;
    type Hasher = PaddingFreeSponge<KoalaPerm, 16, 8, 8>;
    type Compressor = TruncatedPermutation<KoalaPerm, 2, 8, 16>;

    fn default_hasher_and_compressor() -> (Self::Hasher, Self::Compressor) {
        let perm = my_kb_16_perm();
        let hasher = Self::Hasher::new(perm.clone());
        let compressor = Self::Compressor::new(perm.clone());
        (hasher, compressor)
    }

    fn default_challenger() -> Self::Challenger {
        DuplexChallenger::new(my_kb_16_perm())
    }

    fn digest_to_elements(digest: &Self::Digest) -> Vec<Self::F> {
        digest.to_vec()
    }

    fn digest_from_elements(elements: &[Self::F]) -> Self::Digest {
        from_fn(|i| elements[i])
    }
}

pub fn my_kb_16_perm() -> KoalaPerm {
    const ROUNDS_F: usize = 8;
    const ROUNDS_P: usize = 20;
    let mut external_round_constants = KoalaBear_BEGIN_EXT_CONSTS.to_vec();
    let internal_round_constants = KoalaBear_PARTIAL_CONSTS.to_vec();
    external_round_constants.extend_from_slice(KoalaBear_END_EXT_CONSTS.as_slice());

    KoalaPerm::new(
        ROUNDS_F,
        external_round_constants,
        Poseidon2ExternalMatrixGeneral,
        ROUNDS_P,
        internal_round_constants,
        DiffusionMatrixKoalaBear,
    )
}

const KOALA_BEAR_POSEIDON2_HALF_FULL_ROUNDS: usize = 4;
const KOALA_BEAR_POSEIDON2_PARTIAL_ROUNDS: usize = 20;
const KOALA_BEAR_POSEIDON2_WIDTH: usize = 16;

pub(crate) fn koala_bear_round_consts(
) -> ([[KoalaBear; 16]; 4], [KoalaBear; 20], [[KoalaBear; 16]; 4]) {
    let p3_rc16: Vec<Vec<KoalaBear>> = RC16
        .iter()
        .map(|round| round.iter().map(|elem| string_to_koala_bear(elem.clone())).collect())
        .collect();
    let p_end = KOALA_BEAR_POSEIDON2_HALF_FULL_ROUNDS + KOALA_BEAR_POSEIDON2_PARTIAL_ROUNDS;

    let beginning_full_round_constants: [[KoalaBear; KOALA_BEAR_POSEIDON2_WIDTH];
        KOALA_BEAR_POSEIDON2_HALF_FULL_ROUNDS] =
        from_fn(|i| p3_rc16[i].clone().try_into().unwrap());
    let partial_round_constants: [KoalaBear; KOALA_BEAR_POSEIDON2_PARTIAL_ROUNDS] =
        from_fn(|i| p3_rc16[i + KOALA_BEAR_POSEIDON2_HALF_FULL_ROUNDS][0]);
    let ending_full_round_constants: [[KoalaBear; KOALA_BEAR_POSEIDON2_WIDTH];
        KOALA_BEAR_POSEIDON2_HALF_FULL_ROUNDS] =
        from_fn(|i| p3_rc16[i + p_end].clone().try_into().unwrap());

    (beginning_full_round_constants, partial_round_constants, ending_full_round_constants)
}

lazy_static! {
    pub static ref KoalaBear_BEGIN_EXT_CONSTS: [[KoalaBear; KOALA_BEAR_POSEIDON2_WIDTH]; KOALA_BEAR_POSEIDON2_HALF_FULL_ROUNDS] =
        koala_bear_round_consts().0;
    pub static ref KoalaBear_PARTIAL_CONSTS: [KoalaBear; KOALA_BEAR_POSEIDON2_PARTIAL_ROUNDS] =
        koala_bear_round_consts().1;
    pub static ref KoalaBear_END_EXT_CONSTS: [[KoalaBear; KOALA_BEAR_POSEIDON2_WIDTH]; KOALA_BEAR_POSEIDON2_HALF_FULL_ROUNDS] =
        koala_bear_round_consts().2;
    pub static ref RC16: Vec<Vec<String>> = vec![
        vec![
            ("0x7ee56a48".to_string()),
            ("0x11367045".to_string()),
            ("0x12e41941".to_string()),
            ("0x7ebbc12b".to_string()),
            ("0x1970b7d5".to_string()),
            ("0x662b60e8".to_string()),
            ("0x3e4990c6".to_string()),
            ("0x679f91f5".to_string()),
            ("0x350813bb".to_string()),
            ("0x00874ad4".to_string()),
            ("0x28a0081a".to_string()),
            ("0x18fa5872".to_string()),
            ("0x5f25b071".to_string()),
            ("0x5e5d5998".to_string()),
            ("0x5e6fd3e7".to_string()),
            ("0x5b2e2660".to_string()),
        ],
        vec![
            ("0x6f1837bf".to_string()),
            ("0x3fe6182b".to_string()),
            ("0x1edd7ac5".to_string()),
            ("0x57470d00".to_string()),
            ("0x43d486d5".to_string()),
            ("0x1982c70f".to_string()),
            ("0x0ea53af9".to_string()),
            ("0x61d6165b".to_string()),
            ("0x51639c00".to_string()),
            ("0x2dec352c".to_string()),
            ("0x2950e531".to_string()),
            ("0x2d2cb947".to_string()),
            ("0x08256cef".to_string()),
            ("0x1a0109f6".to_string()),
            ("0x1f51faf3".to_string()),
            ("0x5cef1c62".to_string()),
        ],
        vec![
            ("0x3d65e50e".to_string()),
            ("0x33d91626".to_string()),
            ("0x133d5a1e".to_string()),
            ("0x0ff49b0d".to_string()),
            ("0x38900cd1".to_string()),
            ("0x2c22cc3f".to_string()),
            ("0x28852bb2".to_string()),
            ("0x06c65a02".to_string()),
            ("0x7b2cf7bc".to_string()),
            ("0x68016e1a".to_string()),
            ("0x15e16bc0".to_string()),
            ("0x5248149a".to_string()),
            ("0x6dd212a0".to_string()),
            ("0x18d6830a".to_string()),
            ("0x5001be82".to_string()),
            ("0x64dac34e".to_string()),
        ],
        vec![
            ("0x5902b287".to_string()),
            ("0x426583a0".to_string()),
            ("0x0c921632".to_string()),
            ("0x3fe028a5".to_string()),
            ("0x245f8e49".to_string()),
            ("0x43bb297e".to_string()),
            ("0x7873dbd9".to_string()),
            ("0x3cc987df".to_string()),
            ("0x286bb4ce".to_string()),
            ("0x640a8dcd".to_string()),
            ("0x512a8e36".to_string()),
            ("0x03a4cf55".to_string()),
            ("0x481837a2".to_string()),
            ("0x03d6da84".to_string()),
            ("0x73726ac7".to_string()),
            ("0x760e7fdf".to_string()),
        ],
        vec![
            ("0x54dfeb5d".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
        ],
        vec![
            ("0x7d40afd6".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
        ],
        vec![
            ("0x722cb316".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
        ],
        vec![
            ("0x106a4573".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
        ],
        vec![
            ("0x45a7ccdb".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
        ],
        vec![
            ("0x44061375".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
        ],
        vec![
            ("0x154077a5".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
        ],
        vec![
            ("0x45744faa".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
        ],
        vec![
            ("0x4eb5e5ee".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
        ],
        vec![
            ("0x3794e83f".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
        ],
        vec![
            ("0x47c7093c".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
        ],
        vec![
            ("0x5694903c".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
        ],
        vec![
            ("0x69cb6299".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
        ],
        vec![
            ("0x373df84c".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
        ],
        vec![
            ("0x46a0df58".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
        ],
        vec![
            ("0x46b8758a".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
        ],
        vec![
            ("0x3241ebcb".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
        ],
        vec![
            ("0x0b09d233".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
        ],
        vec![
            ("0x1af42357".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
        ],
        vec![
            ("0x1e66cec2".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
            ("0x00000000".to_string()),
        ],
        vec![
            ("0x43e7dc24".to_string()),
            ("0x259a5d61".to_string()),
            ("0x27e85a3b".to_string()),
            ("0x1b9133fa".to_string()),
            ("0x343e5628".to_string()),
            ("0x485cd4c2".to_string()),
            ("0x16e269f5".to_string()),
            ("0x165b60c6".to_string()),
            ("0x25f683d9".to_string()),
            ("0x124f81f9".to_string()),
            ("0x174331f9".to_string()),
            ("0x77344dc5".to_string()),
            ("0x5a821dba".to_string()),
            ("0x5fc4177f".to_string()),
            ("0x54153bf5".to_string()),
            ("0x5e3f1194".to_string()),
        ],
        vec![
            ("0x3bdbf191".to_string()),
            ("0x088c84a3".to_string()),
            ("0x68256c9b".to_string()),
            ("0x3c90bbc6".to_string()),
            ("0x6846166a".to_string()),
            ("0x03f4238d".to_string()),
            ("0x463335fb".to_string()),
            ("0x5e3d3551".to_string()),
            ("0x6e59ae6f".to_string()),
            ("0x32d06cc0".to_string()),
            ("0x596293f3".to_string()),
            ("0x6c87edb2".to_string()),
            ("0x08fc60b5".to_string()),
            ("0x34bcca80".to_string()),
            ("0x24f007f3".to_string()),
            ("0x62731c6f".to_string()),
        ],
        vec![
            ("0x1e1db6c6".to_string()),
            ("0x0ca409bb".to_string()),
            ("0x585c1e78".to_string()),
            ("0x56e94edc".to_string()),
            ("0x16d22734".to_string()),
            ("0x18e11467".to_string()),
            ("0x7b2c3730".to_string()),
            ("0x770075e4".to_string()),
            ("0x35d1b18c".to_string()),
            ("0x22be3db5".to_string()),
            ("0x4fb1fbb7".to_string()),
            ("0x477cb3ed".to_string()),
            ("0x7d5311c6".to_string()),
            ("0x5b62ae7d".to_string()),
            ("0x559c5fa8".to_string()),
            ("0x77f15048".to_string()),
        ],
        vec![
            ("0x3211570b".to_string()),
            ("0x490fef6a".to_string()),
            ("0x77ec311f".to_string()),
            ("0x2247171b".to_string()),
            ("0x4e0ac711".to_string()),
            ("0x2edf69c9".to_string()),
            ("0x3b5a8850".to_string()),
            ("0x65809421".to_string()),
            ("0x5619b4aa".to_string()),
            ("0x362019a7".to_string()),
            ("0x6bf9d4ed".to_string()),
            ("0x5b413dff".to_string()),
            ("0x617e181e".to_string()),
            ("0x5e7ab57b".to_string()),
            ("0x33ad7833".to_string()),
            ("0x3466c7ca".to_string()),
        ],
    ];
}
