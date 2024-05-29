use p3_field::AbstractField;
use sp1_core::air::Word;
use sp1_recursion_compiler::ir::{Builder, Config, Felt, Var};
use sp1_recursion_core::runtime::DIGEST_SIZE;

pub fn felt2var<C: Config>(builder: &mut Builder<C>, felt: Felt<C::F>) -> Var<C::N> {
    let bits = builder.num2bits_f(felt);
    builder.bits2num_v(&bits)
}

pub fn babybears_to_bn254<C: Config>(
    builder: &mut Builder<C>,
    digest: &[Felt<C::F>; DIGEST_SIZE],
) -> Var<C::N> {
    let var_2_31: Var<_> = builder.constant(C::N::from_canonical_u32(1 << 31));
    let result = builder.constant(C::N::zero());
    for (i, word) in digest.iter().enumerate() {
        let word_bits = builder.num2bits_f_circuit(*word);
        let word_var = builder.bits2num_v_circuit(&word_bits);
        if i == 0 {
            builder.assign(result, word_var);
        } else {
            builder.assign(result, result * var_2_31 + word_var);
        }
    }
    result
}

pub fn babybear_bytes_to_bn254<C: Config>(
    builder: &mut Builder<C>,
    bytes: &[Felt<C::F>; 32],
) -> Var<C::N> {
    let var_256: Var<_> = builder.constant(C::N::from_canonical_u32(256));
    let zero_var: Var<_> = builder.constant(C::N::zero());
    let result = builder.constant(C::N::zero());
    for (i, byte) in bytes.iter().enumerate() {
        let byte_bits = builder.num2bits_f_circuit(*byte);
        if i == 0 {
            // Since 32 bytes doesn't fit into Bn254, we need to truncate the top 3 bits.
            // For first byte, zero out 3 most significant bits.
            for i in 0..3 {
                builder.assign(byte_bits[8 - i - 1], zero_var);
            }
            let byte_var = builder.bits2num_v_circuit(&byte_bits);
            builder.assign(result, byte_var);
        } else {
            let byte_var = builder.bits2num_v_circuit(&byte_bits);
            builder.assign(result, result * var_256 + byte_var);
        }
    }
    result
}

pub fn words_to_bytes<T: Copy>(words: &[Word<T>]) -> Vec<T> {
    words.iter().flat_map(|w| w.0).collect::<Vec<_>>()
}
