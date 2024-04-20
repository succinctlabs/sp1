use p3_bn254_fr::Bn254Fr;
use zkhash::ark_ff::PrimeField;
use zkhash::fields::bn256::FpBN256 as ArkFpBN256;
use zkhash::poseidon2::poseidon2_instance_bn256::RC3;

fn bn254_from_ark_ff(input: ArkFpBN256) -> Bn254Fr {
    Bn254Fr {
        value: input.into_bigint().into(),
    }
}

pub fn bn254_poseidon2_rc3() -> Vec<[Bn254Fr; 3]> {
    RC3.iter()
        .map(|vec| {
            vec.iter()
                .cloned()
                .map(bn254_from_ark_ff)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        })
        .collect()
}
