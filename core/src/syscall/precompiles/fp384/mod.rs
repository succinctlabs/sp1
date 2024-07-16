mod fp;
mod fp12;

use std::{
    mem::transmute,
    ops::{Add, Mul, Neg, Sub},
};

pub use fp::*;
pub use fp12::*;

use num_bigint::BigUint;

use crate::{
    operations::field::params::FieldParameters,
    utils::{bytes_to_words_le, words_to_bytes_le_vec},
};

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C)]
pub struct Fp(pub [u64; 6]);

impl Fp {
    const MODULUS: &'static [u8] = &[
        171, 170, 255, 255, 255, 255, 254, 185, 255, 255, 83, 177, 254, 255, 171, 30, 36, 246, 176,
        246, 160, 210, 48, 103, 191, 18, 133, 243, 132, 75, 119, 100, 215, 172, 75, 67, 182, 167,
        27, 75, 154, 230, 127, 57, 234, 17, 1, 26,
    ];
    const R_INV: [u64; 6] = [
        0xf4d38259380b4820,
        0x7fe11274d898fafb,
        0x343ea97914956dc8,
        0x1797ab1458a88de9,
        0xed5e64273c4f538b,
        0x14fec701e8fb0ce9,
    ];
    pub(crate) fn to_words(self) -> [u32; 12] {
        unsafe { transmute(self.0) }
    }

    pub(crate) fn from_words(bytes: &[u32; 12]) -> Self {
        unsafe { Self(transmute::<[u32; 12], [u64; 6]>(*bytes)) }
    }
}

impl Mul for Fp {
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        let rhs = BigUint::from_bytes_le(&words_to_bytes_le_vec(&self.to_words()));
        let lhs = BigUint::from_bytes_le(&words_to_bytes_le_vec(&other.to_words()));

        let out = (lhs * rhs) % BigUint::from_bytes_le(Self::MODULUS);
        let out = (out * BigUint::from_slice(&Fp(Self::R_INV).to_words()))
            % BigUint::from_bytes_le(Self::MODULUS);

        let mut padded = out.to_bytes_le();
        padded.resize(48, 0);
        Self::from_words(&bytes_to_words_le::<12>(&padded))
    }
}

impl Add for Fp {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        let rhs = BigUint::from_bytes_le(&words_to_bytes_le_vec(&self.to_words()));
        let lhs = BigUint::from_bytes_le(&words_to_bytes_le_vec(&other.to_words()));

        let out = (lhs + rhs) % BigUint::from_bytes_le(Self::MODULUS);
        let mut padded = out.to_bytes_le();
        padded.resize(48, 0);
        Self::from_words(&bytes_to_words_le::<12>(&padded))
    }
}

impl Neg for Fp {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let modulus = BigUint::from_bytes_le(Self::MODULUS);
        let val = BigUint::from_bytes_le(&words_to_bytes_le_vec(&self.to_words()));
        let out = &modulus - (val % &modulus);
        let mut padded = out.to_bytes_le();
        padded.resize(48, 0);
        Self::from_words(&bytes_to_words_le::<12>(&padded))
    }
}

impl Sub for Fp {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C)]
pub struct Fp2 {
    c0: Fp,
    c1: Fp,
}

impl Fp2 {
    pub(crate) fn to_words(self) -> [u32; 24] {
        let mut bytes = [0; 24];
        bytes[..12].copy_from_slice(&self.c0.to_words());
        bytes[12..].copy_from_slice(&self.c1.to_words());
        bytes
    }

    pub(crate) fn from_words(bytes: &[u32; 24]) -> Self {
        Self {
            c0: Fp::from_words(bytes[..12].try_into().unwrap()),
            c1: Fp::from_words(bytes[12..].try_into().unwrap()),
        }
    }

    fn mul_by_nonresidue(self) -> Self {
        Self {
            c0: self.c0 - self.c1,
            c1: self.c0 + self.c1,
        }
    }
}

impl Mul for Fp2 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Fp2 {
            c0: self.c0 * rhs.c0 - self.c1 * rhs.c1,
            c1: self.c0 * rhs.c1 + self.c1 * rhs.c0,
        }
    }
}

impl Add for Fp2 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
        }
    }
}

impl Neg for Fp2 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            c0: -self.c0,
            c1: -self.c1,
        }
    }
}

impl Sub for Fp2 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C)]
pub struct Fp6 {
    c0: Fp2,
    c1: Fp2,
    c2: Fp2,
}

impl Fp6 {
    pub(crate) fn to_words(&self) -> [u32; 72] {
        let mut bytes = [0; 72];
        bytes[..24].copy_from_slice(&self.c0.to_words());
        bytes[24..48].copy_from_slice(&self.c1.to_words());
        bytes[48..].copy_from_slice(&self.c2.to_words());
        bytes
    }

    pub(crate) fn from_words(bytes: &[u32; 72]) -> Self {
        Self {
            c0: Fp2::from_words(bytes[..24].try_into().unwrap()),
            c1: Fp2::from_words(bytes[24..48].try_into().unwrap()),
            c2: Fp2::from_words(bytes[48..].try_into().unwrap()),
        }
    }

    fn mul_by_nonresidue(&self) -> Fp6 {
        Fp6 {
            c0: self.c2.mul_by_nonresidue(),
            c1: self.c0,
            c2: self.c1,
        }
    }
}

impl Mul for Fp6 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let b10_p_b11 = rhs.c1.c0 + rhs.c1.c1;
        let b10_m_b11 = rhs.c1.c0 - rhs.c1.c1;
        let b20_p_b21 = rhs.c2.c0 + rhs.c2.c1;
        let b20_m_b21 = rhs.c2.c0 - rhs.c2.c1;

        let c00 = self.c0.c0 * rhs.c0.c0 - self.c0.c1 * rhs.c0.c1 + self.c1.c0 * b20_m_b21
            - self.c1.c1 * b20_p_b21
            + self.c2.c0 * b10_m_b11
            - self.c2.c1 * b10_p_b11;
        let c01 = self.c0.c0 * rhs.c0.c1
            + self.c0.c1 * rhs.c0.c0
            + self.c1.c0 * b20_p_b21
            + self.c1.c1 * b20_m_b21
            + self.c2.c0 * b10_p_b11
            + self.c2.c1 * b10_m_b11;
        Fp6 {
            c0: Fp2 { c0: c00, c1: c01 },
            c1: Fp2 {
                c0: self.c0.c0 * rhs.c1.c0 - self.c0.c1 * rhs.c1.c1 + self.c1.c0 * rhs.c0.c0
                    - self.c1.c1 * rhs.c0.c1
                    + self.c2.c0 * b20_m_b21
                    - self.c2.c1 * b20_p_b21,
                c1: self.c0.c0 * rhs.c1.c1
                    + self.c0.c1 * rhs.c1.c0
                    + self.c1.c0 * rhs.c0.c1
                    + self.c1.c1 * rhs.c0.c0
                    + self.c2.c0 * b20_p_b21
                    + self.c2.c1 * b20_m_b21,
            },
            c2: Fp2 {
                c0: self.c0.c0 * rhs.c2.c0 - self.c0.c1 * rhs.c2.c1 + self.c1.c0 * rhs.c1.c0
                    - self.c1.c1 * rhs.c1.c1
                    + self.c2.c0 * rhs.c0.c0
                    - self.c2.c1 * rhs.c0.c1,
                c1: self.c0.c0 * rhs.c2.c1
                    + self.c0.c1 * rhs.c2.c0
                    + self.c1.c0 * rhs.c1.c1
                    + self.c1.c1 * rhs.c1.c0
                    + self.c2.c0 * rhs.c0.c1
                    + self.c2.c1 * rhs.c0.c0,
            },
        }
    }
}

impl Add for Fp6 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Fp6 {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
            c2: self.c2 + rhs.c2,
        }
    }
}

impl Neg for Fp6 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Fp6 {
            c0: -self.c0,
            c1: -self.c1,
            c2: -self.c2,
        }
    }
}

impl Sub for Fp6 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C)]
pub struct Fp12 {
    c0: Fp6,
    c1: Fp6,
}

impl Fp12 {
    pub(crate) fn to_words(self) -> [u32; 144] {
        let mut bytes = [0; 144];
        bytes[..72].copy_from_slice(&self.c0.to_words());
        bytes[72..].copy_from_slice(&self.c1.to_words());
        bytes
    }

    pub(crate) fn from_words(bytes: &[u32; 144]) -> Self {
        // Self {
        //     c0: Fp6::from_words(bytes[..72].try_into().unwrap()),
        //     c1: Fp6::from_words(bytes[72..].try_into().unwrap()),
        // }
        unsafe { transmute::<[u32; 144], Self>(*bytes) }
    }
}

impl Add for Fp12 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
        }
    }
}

impl Mul for Fp12 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let aa = self.c0 * rhs.c0;
        let bb = self.c1 * rhs.c1;
        let o = rhs.c0 + rhs.c1;
        let c1 = self.c1 + self.c0;
        let c1 = c1 * o;
        let c1 = c1 - aa;
        let c1 = c1 - bb;
        let c0 = bb.mul_by_nonresidue();
        let c0 = c0 + aa;

        Fp12 { c0, c1 }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_fp_multiplication() {
        let a = Fp([
            0x0397_a383_2017_0cd4,
            0x734c_1b2c_9e76_1d30,
            0x5ed2_55ad_9a48_beb5,
            0x095a_3c6b_22a7_fcfc,
            0x2294_ce75_d4e2_6a27,
            0x1333_8bd8_7001_1ebb,
        ]);
        let b = Fp([
            0xb9c3_c7c5_b119_6af7,
            0x2580_e208_6ce3_35c1,
            0xf49a_ed3d_8a57_ef42,
            0x41f2_81e4_9846_e878,
            0xe076_2346_c384_52ce,
            0x0652_e893_26e5_7dc0,
        ]);
        let c = Fp([
            0xf96e_f3d7_11ab_5355,
            0xe8d4_59ea_00f1_48dd,
            0x53f7_354a_5f00_fa78,
            0x9e34_a4f3_125c_5f83,
            0x3fbe_0c47_ca74_c19e,
            0x01b0_6a8b_bd4a_dfe4,
        ]);

        assert_eq!(a * b, c);
    }
    #[test]
    fn test_fp_addition() {
        let a = Fp([
            0x5360_bb59_7867_8032,
            0x7dd2_75ae_799e_128e,
            0x5c5b_5071_ce4f_4dcf,
            0xcdb2_1f93_078d_bb3e,
            0xc323_65c5_e73f_474a,
            0x115a_2a54_89ba_be5b,
        ]);
        let b = Fp([
            0x9fd2_8773_3d23_dda0,
            0xb16b_f2af_738b_3554,
            0x3e57_a75b_d3cc_6d1d,
            0x900b_c0bd_627f_d6d6,
            0xd319_a080_efb2_45fe,
            0x15fd_caa4_e4bb_2091,
        ]);
        let c = Fp([
            0x3934_42cc_b58b_b327,
            0x1092_685f_3bd5_47e3,
            0x3382_252c_ab6a_c4c9,
            0xf946_94cb_7688_7f55,
            0x4b21_5e90_93a5_e071,
            0x0d56_e30f_34f5_f853,
        ]);

        assert_eq!(a + b, c);
    }

    #[test]
    fn test_fp_subtraction() {
        let a = Fp([
            0x5360_bb59_7867_8032,
            0x7dd2_75ae_799e_128e,
            0x5c5b_5071_ce4f_4dcf,
            0xcdb2_1f93_078d_bb3e,
            0xc323_65c5_e73f_474a,
            0x115a_2a54_89ba_be5b,
        ]);
        let b = Fp([
            0x9fd2_8773_3d23_dda0,
            0xb16b_f2af_738b_3554,
            0x3e57_a75b_d3cc_6d1d,
            0x900b_c0bd_627f_d6d6,
            0xd319_a080_efb2_45fe,
            0x15fd_caa4_e4bb_2091,
        ]);
        let c = Fp([
            0x6d8d_33e6_3b43_4d3d,
            0xeb12_82fd_b766_dd39,
            0x8534_7bb6_f133_d6d5,
            0xa21d_aa5a_9892_f727,
            0x3b25_6cfb_3ad8_ae23,
            0x155d_7199_de7f_8464,
        ]);

        assert_eq!(a - b, c);
    }

    #[test]
    fn test_fp_negation() {
        let a = Fp([
            0x5360_bb59_7867_8032,
            0x7dd2_75ae_799e_128e,
            0x5c5b_5071_ce4f_4dcf,
            0xcdb2_1f93_078d_bb3e,
            0xc323_65c5_e73f_474a,
            0x115a_2a54_89ba_be5b,
        ]);
        let b = Fp([
            0x669e_44a6_8798_2a79,
            0xa0d9_8a50_37b5_ed71,
            0x0ad5_822f_2861_a854,
            0x96c5_2bf1_ebf7_5781,
            0x87f8_41f0_5c0c_658c,
            0x08a6_e795_afc5_283e,
        ]);

        assert_eq!(-a, b);
    }

    #[test]
    fn test_fp2_multiplication() {
        let a = Fp2 {
            c0: Fp([
                0xc9a2_1831_63ee_70d4,
                0xbc37_70a7_196b_5c91,
                0xa247_f8c1_304c_5f44,
                0xb01f_c2a3_726c_80b5,
                0xe1d2_93e5_bbd9_19c9,
                0x04b7_8e80_020e_f2ca,
            ]),
            c1: Fp([
                0x952e_a446_0462_618f,
                0x238d_5edd_f025_c62f,
                0xf6c9_4b01_2ea9_2e72,
                0x03ce_24ea_c1c9_3808,
                0x0559_50f9_45da_483c,
                0x010a_768d_0df4_eabc,
            ]),
        };
        let b = Fp2 {
            c0: Fp([
                0xa1e0_9175_a4d2_c1fe,
                0x8b33_acfc_204e_ff12,
                0xe244_15a1_1b45_6e42,
                0x61d9_96b1_b6ee_1936,
                0x1164_dbe8_667c_853c,
                0x0788_557a_cc7d_9c79,
            ]),
            c1: Fp([
                0xda6a_87cc_6f48_fa36,
                0x0fc7_b488_277c_1903,
                0x9445_ac4a_dc44_8187,
                0x0261_6d5b_c909_9209,
                0xdbed_4677_2db5_8d48,
                0x11b9_4d50_76c7_b7b1,
            ]),
        };
        let c = Fp2 {
            c0: Fp([
                0xf597_483e_27b4_e0f7,
                0x610f_badf_811d_ae5f,
                0x8432_af91_7714_327a,
                0x6a9a_9603_cf88_f09e,
                0xf05a_7bf8_bad0_eb01,
                0x0954_9131_c003_ffae,
            ]),
            c1: Fp([
                0x963b_02d0_f93d_37cd,
                0xc95c_e1cd_b30a_73d4,
                0x3087_25fa_3126_f9b8,
                0x56da_3c16_7fab_0d50,
                0x6b50_86b5_f4b6_d6af,
                0x09c3_9f06_2f18_e9f2,
            ]),
        };

        assert_eq!(a * b, c);
    }

    #[test]
    fn test_fp2_addition() {
        let a = Fp2 {
            c0: Fp([
                0xc9a2_1831_63ee_70d4,
                0xbc37_70a7_196b_5c91,
                0xa247_f8c1_304c_5f44,
                0xb01f_c2a3_726c_80b5,
                0xe1d2_93e5_bbd9_19c9,
                0x04b7_8e80_020e_f2ca,
            ]),
            c1: Fp([
                0x952e_a446_0462_618f,
                0x238d_5edd_f025_c62f,
                0xf6c9_4b01_2ea9_2e72,
                0x03ce_24ea_c1c9_3808,
                0x0559_50f9_45da_483c,
                0x010a_768d_0df4_eabc,
            ]),
        };
        let b = Fp2 {
            c0: Fp([
                0xa1e0_9175_a4d2_c1fe,
                0x8b33_acfc_204e_ff12,
                0xe244_15a1_1b45_6e42,
                0x61d9_96b1_b6ee_1936,
                0x1164_dbe8_667c_853c,
                0x0788_557a_cc7d_9c79,
            ]),
            c1: Fp([
                0xda6a_87cc_6f48_fa36,
                0x0fc7_b488_277c_1903,
                0x9445_ac4a_dc44_8187,
                0x0261_6d5b_c909_9209,
                0xdbed_4677_2db5_8d48,
                0x11b9_4d50_76c7_b7b1,
            ]),
        };
        let c = Fp2 {
            c0: Fp([
                0x6b82_a9a7_08c1_32d2,
                0x476b_1da3_39ba_5ba4,
                0x848c_0e62_4b91_cd87,
                0x11f9_5955_295a_99ec,
                0xf337_6fce_2255_9f06,
                0x0c3f_e3fa_ce8c_8f43,
            ]),
            c1: Fp([
                0x6f99_2c12_73ab_5bc5,
                0x3355_1366_17a1_df33,
                0x8b0e_f74c_0aed_aff9,
                0x062f_9246_8ad2_ca12,
                0xe146_9770_738f_d584,
                0x12c3_c3dd_84bc_a26d,
            ]),
        };

        assert_eq!(a + b, c);
    }

    #[test]
    fn test_fp2_subtraction() {
        let a = Fp2 {
            c0: Fp([
                0xc9a2_1831_63ee_70d4,
                0xbc37_70a7_196b_5c91,
                0xa247_f8c1_304c_5f44,
                0xb01f_c2a3_726c_80b5,
                0xe1d2_93e5_bbd9_19c9,
                0x04b7_8e80_020e_f2ca,
            ]),
            c1: Fp([
                0x952e_a446_0462_618f,
                0x238d_5edd_f025_c62f,
                0xf6c9_4b01_2ea9_2e72,
                0x03ce_24ea_c1c9_3808,
                0x0559_50f9_45da_483c,
                0x010a_768d_0df4_eabc,
            ]),
        };
        let b = Fp2 {
            c0: Fp([
                0xa1e0_9175_a4d2_c1fe,
                0x8b33_acfc_204e_ff12,
                0xe244_15a1_1b45_6e42,
                0x61d9_96b1_b6ee_1936,
                0x1164_dbe8_667c_853c,
                0x0788_557a_cc7d_9c79,
            ]),
            c1: Fp([
                0xda6a_87cc_6f48_fa36,
                0x0fc7_b488_277c_1903,
                0x9445_ac4a_dc44_8187,
                0x0261_6d5b_c909_9209,
                0xdbed_4677_2db5_8d48,
                0x11b9_4d50_76c7_b7b1,
            ]),
        };
        let c = Fp2 {
            c0: Fp([
                0xe1c0_86bb_bf1b_5981,
                0x4faf_c3a9_aa70_5d7e,
                0x2734_b5c1_0bb7_e726,
                0xb2bd_7776_af03_7a3e,
                0x1b89_5fb3_98a8_4164,
                0x1730_4aef_6f11_3cec,
            ]),
            c1: Fp([
                0x74c3_1c79_9519_1204,
                0x3271_aa54_79fd_ad2b,
                0xc9b4_7157_4915_a30f,
                0x65e4_0313_ec44_b8be,
                0x7487_b238_5b70_67cb,
                0x0952_3b26_d0ad_19a4,
            ]),
        };

        assert_eq!(a - b, c);
    }

    #[test]
    fn test_fp2_negation() {
        let a = Fp2 {
            c0: Fp([
                0xc9a2_1831_63ee_70d4,
                0xbc37_70a7_196b_5c91,
                0xa247_f8c1_304c_5f44,
                0xb01f_c2a3_726c_80b5,
                0xe1d2_93e5_bbd9_19c9,
                0x04b7_8e80_020e_f2ca,
            ]),
            c1: Fp([
                0x952e_a446_0462_618f,
                0x238d_5edd_f025_c62f,
                0xf6c9_4b01_2ea9_2e72,
                0x03ce_24ea_c1c9_3808,
                0x0559_50f9_45da_483c,
                0x010a_768d_0df4_eabc,
            ]),
        };
        let b = Fp2 {
            c0: Fp([
                0xf05c_e7ce_9c11_39d7,
                0x6274_8f57_97e8_a36d,
                0xc4e8_d9df_c664_96df,
                0xb457_88e1_8118_9209,
                0x6949_13d0_8772_930d,
                0x1549_836a_3770_f3cf,
            ]),
            c1: Fp([
                0x24d0_5bb9_fb9d_491c,
                0xfb1e_a120_c12e_39d0,
                0x7067_879f_c807_c7b1,
                0x60a9_269a_31bb_dab6,
                0x45c2_56bc_fd71_649b,
                0x18f6_9b5d_2b8a_fbde,
            ]),
        };

        assert_eq!(-a, b);
    }

    #[test]
    fn test_fp12_multiplication() {
        let a = Fp12 {
            c0: Fp6 {
                c0: Fp2 {
                    c0: Fp([
                        0x47f9_cb98_b1b8_2d58,
                        0x5fe9_11eb_a3aa_1d9d,
                        0x96bf_1b5f_4dd8_1db3,
                        0x8100_d27c_c925_9f5b,
                        0xafa2_0b96_7464_0eab,
                        0x09bb_cea7_d8d9_497d,
                    ]),
                    c1: Fp([
                        0x0303_cb98_b166_2daa,
                        0xd931_10aa_0a62_1d5a,
                        0xbfa9_820c_5be4_a468,
                        0x0ba3_643e_cb05_a348,
                        0xdc35_34bb_1f1c_25a6,
                        0x06c3_05bb_19c0_e1c1,
                    ]),
                },
                c1: Fp2 {
                    c0: Fp([
                        0x46f9_cb98_b162_d858,
                        0x0be9_109c_f7aa_1d57,
                        0xc791_bc55_fece_41d2,
                        0xf84c_5770_4e38_5ec2,
                        0xcb49_c1d9_c010_e60f,
                        0x0acd_b8e1_58bf_e3c8,
                    ]),
                    c1: Fp([
                        0x8aef_cb98_b15f_8306,
                        0x3ea1_108f_e4f2_1d54,
                        0xcf79_f69f_a1b7_df3b,
                        0xe4f5_4aa1_d16b_1a3c,
                        0xba5e_4ef8_6105_a679,
                        0x0ed8_6c07_97be_e5cf,
                    ]),
                },
                c2: Fp2 {
                    c0: Fp([
                        0xcee5_cb98_b15c_2db4,
                        0x7159_1082_d23a_1d51,
                        0xd762_30e9_44a1_7ca4,
                        0xd19e_3dd3_549d_d5b6,
                        0xa972_dc17_01fa_66e3,
                        0x12e3_1f2d_d6bd_e7d6,
                    ]),
                    c1: Fp([
                        0xad2a_cb98_b173_2d9d,
                        0x2cfd_10dd_0696_1d64,
                        0x0739_6b86_c6ef_24e8,
                        0xbd76_e2fd_b1bf_c820,
                        0x6afe_a7f6_de94_d0d5,
                        0x1099_4b0c_5744_c040,
                    ]),
                },
            },
            c1: Fp6 {
                c0: Fp2 {
                    c0: Fp([
                        0x47f9_cb98_b1b8_2d58,
                        0x5fe9_11eb_a3aa_1d9d,
                        0x96bf_1b5f_4dd8_1db3,
                        0x8100_d27c_c925_9f5b,
                        0xafa2_0b96_7464_0eab,
                        0x09bb_cea7_d8d9_497d,
                    ]),
                    c1: Fp([
                        0x0303_cb98_b166_2daa,
                        0xd931_10aa_0a62_1d5a,
                        0xbfa9_820c_5be4_a468,
                        0x0ba3_643e_cb05_a348,
                        0xdc35_34bb_1f1c_25a6,
                        0x06c3_05bb_19c0_e1c1,
                    ]),
                },
                c1: Fp2 {
                    c0: Fp([
                        0x46f9_cb98_b162_d858,
                        0x0be9_109c_f7aa_1d57,
                        0xc791_bc55_fece_41d2,
                        0xf84c_5770_4e38_5ec2,
                        0xcb49_c1d9_c010_e60f,
                        0x0acd_b8e1_58bf_e3c8,
                    ]),
                    c1: Fp([
                        0x8aef_cb98_b15f_8306,
                        0x3ea1_108f_e4f2_1d54,
                        0xcf79_f69f_a1b7_df3b,
                        0xe4f5_4aa1_d16b_1a3c,
                        0xba5e_4ef8_6105_a679,
                        0x0ed8_6c07_97be_e5cf,
                    ]),
                },
                c2: Fp2 {
                    c0: Fp([
                        0xcee5_cb98_b15c_2db4,
                        0x7159_1082_d23a_1d51,
                        0xd762_30e9_44a1_7ca4,
                        0xd19e_3dd3_549d_d5b6,
                        0xa972_dc17_01fa_66e3,
                        0x12e3_1f2d_d6bd_e7d6,
                    ]),
                    c1: Fp([
                        0xad2a_cb98_b173_2d9d,
                        0x2cfd_10dd_0696_1d64,
                        0x0739_6b86_c6ef_24e8,
                        0xbd76_e2fd_b1bf_c820,
                        0x6afe_a7f6_de94_d0d5,
                        0x1099_4b0c_5744_c040,
                    ]),
                },
            },
        };

        let b = Fp12 {
            c0: Fp6 {
                c0: Fp2 {
                    c0: Fp([
                        0x47f9_cb98_b1b8_2d58,
                        0x5fe9_11eb_a3aa_1d9d,
                        0x96bf_1b5f_4dd8_1db3,
                        0x8100_d272_c925_9f5b,
                        0xafa2_0b96_7464_0eab,
                        0x09bb_cea7_d8d9_497d,
                    ]),
                    c1: Fp([
                        0x0303_cb98_b166_2daa,
                        0xd931_10aa_0a62_1d5a,
                        0xbfa9_820c_5be4_a468,
                        0x0ba3_643e_cb05_a348,
                        0xdc35_34bb_1f1c_25a6,
                        0x06c3_05bb_19c0_e1c1,
                    ]),
                },
                c1: Fp2 {
                    c0: Fp([
                        0x46f9_cb98_b162_d858,
                        0x0be9_109c_f7aa_1d57,
                        0xc791_bc55_fece_41d2,
                        0xf84c_5770_4e38_5ec2,
                        0xcb49_c1d9_c010_e60f,
                        0x0acd_b8e1_58bf_e348,
                    ]),
                    c1: Fp([
                        0x8aef_cb98_b15f_8306,
                        0x3ea1_108f_e4f2_1d54,
                        0xcf79_f69f_a1b7_df3b,
                        0xe4f5_4aa1_d16b_1a3c,
                        0xba5e_4ef8_6105_a679,
                        0x0ed8_6c07_97be_e5cf,
                    ]),
                },
                c2: Fp2 {
                    c0: Fp([
                        0xcee5_cb98_b15c_2db4,
                        0x7159_1082_d23a_1d51,
                        0xd762_30e9_44a1_7ca4,
                        0xd19e_3dd3_549d_d5b6,
                        0xa972_dc17_01fa_66e3,
                        0x12e3_1f2d_d6bd_e7d6,
                    ]),
                    c1: Fp([
                        0xad2a_cb98_b173_2d9d,
                        0x2cfd_10dd_0696_1d64,
                        0x0739_6b86_c6ef_24e8,
                        0xbd76_e2fd_b1bf_c820,
                        0x6afe_a7f6_de94_d0d5,
                        0x1099_4b0c_5744_c040,
                    ]),
                },
            },
            c1: Fp6 {
                c0: Fp2 {
                    c0: Fp([
                        0x47f9_cb98_b1b8_2d58,
                        0x5fe9_11eb_a3aa_1d9d,
                        0x96bf_1b5f_4dd2_1db3,
                        0x8100_d27c_c925_9f5b,
                        0xafa2_0b96_7464_0eab,
                        0x09bb_cea7_d8d9_497d,
                    ]),
                    c1: Fp([
                        0x0303_cb98_b166_2daa,
                        0xd931_10aa_0a62_1d5a,
                        0xbfa9_820c_5be4_a468,
                        0x0ba3_643e_cb05_a348,
                        0xdc35_34bb_1f1c_25a6,
                        0x06c3_05bb_19c0_e1c1,
                    ]),
                },
                c1: Fp2 {
                    c0: Fp([
                        0x46f9_cb98_b162_d858,
                        0x0be9_109c_f7aa_1d57,
                        0xc791_bc55_fece_41d2,
                        0xf84c_5770_4e38_5ec2,
                        0xcb49_c1d9_c010_e60f,
                        0x0acd_b8e1_58bf_e3c8,
                    ]),
                    c1: Fp([
                        0x8aef_cb98_b15f_8306,
                        0x3ea1_108f_e4f2_1d54,
                        0xcf79_f69f_a117_df3b,
                        0xe4f5_4aa1_d16b_1a3c,
                        0xba5e_4ef8_6105_a679,
                        0x0ed8_6c07_97be_e5cf,
                    ]),
                },
                c2: Fp2 {
                    c0: Fp([
                        0xcee5_cb98_b15c_2db4,
                        0x7159_1082_d23a_1d51,
                        0xd762_30e9_44a1_7ca4,
                        0xd19e_3dd3_549d_d5b6,
                        0xa972_dc17_01fa_66e3,
                        0x12e3_1f2d_d6bd_e7d6,
                    ]),
                    c1: Fp([
                        0xad2a_cb98_b173_2d9d,
                        0x2cfd_10dd_0696_1d64,
                        0x0739_6b86_c6ef_24e8,
                        0xbd76_e2fd_b1bf_c820,
                        0x6afe_a7f6_de94_d0d5,
                        0x1099_4b0c_5744_c040,
                    ]),
                },
            },
        };

        let c = Fp12 {
            c0: Fp6 {
                c0: Fp2 {
                    c0: Fp([
                        0xa45b_f6c5_b3a4_2b19,
                        0x0200_d762_6c52_63f8,
                        0x297e_7a60_d60b_b0f1,
                        0x0a68_cb17_e900_d6b0,
                        0x86ca_21f7_8516_f01f,
                        0x1055_c03a_d3fd_27dc,
                    ]),
                    c1: Fp([
                        0x41d6_bc97_38d9_f82a,
                        0x4958_35f2_505c_f4bb,
                        0xe0c6_adbe_be7e_cf64,
                        0xf803_f193_aab8_66a3,
                        0xbb3f_0661_8110_9cf1,
                        0x0b1d_8eea_c80b_a753,
                    ]),
                },
                c1: Fp2 {
                    c0: Fp([
                        0x472f_966b_5b9d_1634,
                        0x03d1_f0ce_0917_41a9,
                        0x34ca_698c_f1c3_c8bd,
                        0xee55_9567_bef3_1954,
                        0xb46b_75d9_8308_fa8e,
                        0x0ffb_151f_935a_5e8b,
                    ]),
                    c1: Fp([
                        0x1004_6193_2dbf_0951,
                        0x6e1c_ca30_81b2_fc85,
                        0x8598_a480_771c_e6c4,
                        0xf7f3_0d4f_6ed8_6b67,
                        0x926d_d077_abea_a1e6,
                        0x050b_b5a6_ff15_6bd6,
                    ]),
                },
                c2: Fp2 {
                    c0: Fp([
                        0xfa2f_096f_b20e_2a79,
                        0xc897_b1f9_974e_92ae,
                        0x9b13_6dc8_155f_f642,
                        0x7349_c17d_6795_1717,
                        0x0a7c_2b4f_449a_64fa,
                        0x0531_c850_beb1_0014,
                    ]),
                    c1: Fp([
                        0x1d0c_ecbb_80d2_2b00,
                        0x5745_9b1f_5370_5e9d,
                        0x157f_3e54_24d9_3210,
                        0xc5c9_0793_81d4_8ca8,
                        0xfe55_8abd_c972_7d11,
                        0x10da_29b4_044e_1e2b,
                    ]),
                },
            },
            c1: Fp6 {
                c0: Fp2 {
                    c0: Fp([
                        0x5371_8b4b_f98e_147e,
                        0x6b45_60dc_7e72_117b,
                        0x245b_041f_3495_3a3b,
                        0x2447_b5a7_17b3_9b18,
                        0x86e2_5ed4_3dac_6dd5,
                        0x03f9_aea9_556d_0b4a,
                    ]),
                    c1: Fp([
                        0xd815_f8c4_928e_b7f7,
                        0xe5c6_f369_b12f_38df,
                        0xd813_a887_6637_b974,
                        0x56cb_c4d2_6340_7a13,
                        0xb5d5_673b_8321_206e,
                        0x081b_9057_ecc5_dd90,
                    ]),
                },
                c1: Fp2 {
                    c0: Fp([
                        0x80ee_a18a_bdac_6d3f,
                        0x7db2_80c0_e268_71d7,
                        0xddb1_7314_5a5d_611a,
                        0x53ec_289f_72ad_84d0,
                        0x96d8_e528_8519_da71,
                        0x01fb_69f1_9f32_8cb2,
                    ]),
                    c1: Fp([
                        0x47f2_ca61_c8ef_5aab,
                        0xf672_a0f7_5236_c02a,
                        0x32c6_1734_162e_1413,
                        0x991a_55b8_7a70_5cbb,
                        0x6f06_39b3_d4b4_235f,
                        0x01fb_dab0_09fa_481c,
                    ]),
                },
                c2: Fp2 {
                    c0: Fp([
                        0x736f_7154_a66f_e7b3,
                        0x137c_e332_4c34_b386,
                        0x5875_687b_cf2e_8b6b,
                        0x92a7_5a47_5c7c_a95e,
                        0x7e1f_7176_041a_ef83,
                        0x0868_26af_de2f_6675,
                    ]),
                    c1: Fp([
                        0x3828_0f15_38b5_50aa,
                        0x996c_9548_a355_fd10,
                        0x9107_92d3_4cef_59e8,
                        0x8e00_6e25_95b3_a9d5,
                        0x4289_3411_7ae5_29ec,
                        0x05b7_66cd_c522_0ca1,
                    ]),
                },
            },
        };

        assert_eq!(a * b, c);
    }
}
