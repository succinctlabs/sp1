use bigint::{
    impl_modulus,
    modular::{
        constant_mod::{Residue, ResidueParams},
        runtime_mod::{DynResidue, DynResidueParams},
    },
    Encoding, MultiExponentiateBoundedExp, Uint, U256,
};
use num_bigint::BigUint;

// Compare retrieved values because native and accelerated residues use different representations.
macro_rules! check_result {
    ($results:expr, $actual:expr, $expected:expr $(,)?) => {{
        let actual = $actual;
        assert_eq!(actual, $expected);
        $results.push(actual.to_be_bytes().as_ref().to_vec());
    }};
}

impl_modulus!(ModOne, U256, "0000000000000000000000000000000000000000000000000000000000000001");
impl_modulus!(Mod17, U256, "0000000000000000000000000000000000000000000000000000000000000011");
const DYNAMIC_ONE: DynResidue<4> =
    DynResidue::one(DynResidueParams::from_residue_params::<ModOne>());
const STATIC_ONE: Residue<ModOne, 4> = Residue::ONE;

fn reference<const L: usize>(base: &Uint<L>, exp: u64, modulus: &Uint<L>) -> Uint<L>
where
    Uint<L>: Encoding,
{
    let result = BigUint::from_bytes_be(base.to_be_bytes().as_ref())
        .modpow(&BigUint::from(exp), &BigUint::from_bytes_be(modulus.to_be_bytes().as_ref()));
    let bytes = result.to_bytes_be();
    let mut padded = vec![0; Uint::<L>::BYTES];
    let start = padded.len() - bytes.len();
    padded[start..].copy_from_slice(&bytes);
    Uint::from_be_slice(&padded)
}

fn dynamic<const L: usize>(mode: u8, results: &mut Vec<Vec<u8>>) -> u32
where
    Uint<L>: Encoding,
{
    let mut count = 0;
    for modulus in [Uint::ONE, Uint::from_u64(3), Uint::from_u64(17), Uint::MAX] {
        let params = DynResidueParams::new(&modulus);
        let one = reference(&Uint::<L>::ONE, 1, &modulus);
        for value in [Uint::ZERO, Uint::ONE, Uint::from_u64(17), Uint::MAX] {
            let base = DynResidue::new(&value, params);
            if mode == 0 {
                let identity = DynResidue::one(params);
                check_result!(results, identity.retrieve(), one);
                check_result!(results, DynResidue::zero(params).retrieve(), Uint::ZERO);
                check_result!(
                    results,
                    (base * identity).retrieve(),
                    reference(&value, 1, &modulus)
                );
                check_result!(
                    results,
                    (base + identity).retrieve(),
                    reference(&value, 1, &modulus).wrapping_add(&one).const_rem(&modulus).0
                );
                #[cfg(all(target_os = "zkvm", target_vendor = "succinct"))]
                if L == 4 && modulus == Uint::ONE {
                    assert_eq!(identity, DynResidue::zero(params));
                    assert_eq!(identity, DynResidue::new(&Uint::ONE, params));
                }
            } else {
                for exp in [0, 1, 2, 17] {
                    check_result!(
                        results,
                        base.pow(&U256::from_u64(exp)).retrieve(),
                        reference(&value, exp, &modulus)
                    );
                    check_result!(
                        results,
                        base.pow_bounded_exp(&U256::from_u64(exp), 5).retrieve(),
                        reference(&value, exp, &modulus)
                    );
                }
                check_result!(results, base.pow_bounded_exp(&U256::MAX, 0).retrieve(), one);
                for (x, y, bits) in [(0, 0, 0), (0, 0, 8), (1, 2, 8)] {
                    let pairs = [(base, U256::from_u64(x)), (base, U256::from_u64(y))];
                    let expected = reference(&value, x + y, &modulus);
                    check_result!(
                        results,
                        DynResidue::multi_exponentiate_bounded_exp(&pairs, bits).retrieve(),
                        expected
                    );
                    check_result!(
                        results,
                        DynResidue::multi_exponentiate_bounded_exp(pairs.as_slice(), bits)
                            .retrieve(),
                        expected
                    );
                }
            }
            count += 1;
        }
    }
    count
}

fn constant<M: ResidueParams<4> + Copy>(mode: u8, results: &mut Vec<Vec<u8>>) -> u32 {
    let one = reference(&U256::ONE, 1, &M::MODULUS);
    for value in [U256::ZERO, U256::ONE, U256::from_u64(17), U256::MAX] {
        let base = Residue::<M, 4>::new(&value);
        if mode == 0 {
            check_result!(results, Residue::<M, 4>::ONE.retrieve(), one);
            check_result!(results, Residue::<M, 4>::ZERO.retrieve(), U256::ZERO);
            check_result!(
                results,
                (base * Residue::<M, 4>::ONE).retrieve(),
                reference(&value, 1, &M::MODULUS)
            );
        } else {
            for exp in [0, 1, 2, 17] {
                check_result!(
                    results,
                    base.pow(&U256::from_u64(exp)).retrieve(),
                    reference(&value, exp, &M::MODULUS)
                );
            }
            check_result!(results, base.pow_bounded_exp(&U256::MAX, 0).retrieve(), one);
            for (x, y, bits) in [(0, 0, 0), (0, 0, 8), (1, 2, 8)] {
                let pairs = [(base, U256::from_u64(x)), (base, U256::from_u64(y))];
                let expected = reference(&value, x + y, &M::MODULUS);
                check_result!(
                    results,
                    Residue::<M, 4>::multi_exponentiate_bounded_exp(&pairs, bits).retrieve(),
                    expected
                );
                check_result!(
                    results,
                    Residue::<M, 4>::multi_exponentiate_bounded_exp(pairs.as_slice(), bits)
                        .retrieve(),
                    expected
                );
            }
            let empty: [(Residue<M, 4>, U256); 0] = [];
            for bits in [0, 8] {
                check_result!(
                    results,
                    Residue::<M, 4>::multi_exponentiate_bounded_exp(&empty, bits).retrieve(),
                    one
                );
                check_result!(
                    results,
                    Residue::<M, 4>::multi_exponentiate_bounded_exp(empty.as_slice(), bits)
                        .retrieve(),
                    one
                );
            }
        }
    }
    4
}

pub fn run(mode: u8) -> Vec<Vec<u8>> {
    let mut results = Vec::new();
    assert!(mode <= 1);
    if mode == 0 {
        check_result!(results, DYNAMIC_ONE.retrieve(), U256::ZERO);
        check_result!(results, STATIC_ONE.retrieve(), U256::ZERO);
        #[cfg(all(target_os = "zkvm", target_vendor = "succinct"))]
        assert_eq!(STATIC_ONE, Residue::<ModOne, 4>::ZERO);
    }
    let count = dynamic::<1>(mode, &mut results)
        + dynamic::<2>(mode, &mut results)
        + dynamic::<4>(mode, &mut results)
        + dynamic::<8>(mode, &mut results)
        + constant::<ModOne>(mode, &mut results)
        + constant::<Mod17>(mode, &mut results);
    assert_eq!(count, 72);
    results
}
