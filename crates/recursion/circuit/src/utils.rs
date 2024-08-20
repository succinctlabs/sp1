use p3_field::AbstractField;
use p3_util::log2_strict_usize;
use sp1_recursion_compiler::ir::{Builder, Config, Ext, Felt, Var};
use sp1_recursion_core::runtime::DIGEST_SIZE;
use sp1_stark::Word;

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

pub fn access_index_with_var_e<C: Config>(
    builder: &mut Builder<C>,
    vec: &[Ext<C::F, C::EF>],
    index_bits: Vec<Var<C::N>>,
) -> Ext<C::F, C::EF> {
    let mut result = vec.to_vec();
    for &bit in index_bits[..log2_strict_usize(vec.len())].iter() {
        result = (0..result.len() / 2)
            .map(|i| builder.select_ef(bit, result[2 * i + 1], result[2 * i]))
            .collect();
    }
    result[0]
}

// pub fn insert_e<C: Config>(
//     builder: &mut Builder<C>,
//     vec: &[Ext<C::F, C::EF>],
//     val: Ext<C::F, C::EF>,
//     index_bits: Vec<Var<C::N>>,
// ) -> Vec<Ext<C::F, C::EF>> {
//     let num_bits = index_bits.len();

//     // TODO: refactor so I don't have to reverse the bits.
//     let mut index_bits = index_bits.clone();
//     index_bits.reverse();

//     if vec.len() == 1 {
//         return vec![
//             builder.select_ef(index_bits[0], vec[0], val),
//             builder.select_ef(index_bits[0], val, vec[0]),
//         ];
//     }
//     println!("num_bits: {}", num_bits);
//     println!("vec len: {}", vec.len());
//     let mut result = vec.to_vec();
//     result.insert(0, val);
//     let mut left_half = result[..result.len() / 2].to_vec();
//     let mut right_half = result[result.len() / 2..].to_vec();

//     left_half[0] = builder.select_ef(index_bits[num_bits - 1], right_half[0], left_half[0]);

//     let left_half_val = left_half.remove(0);

//     right_half[0] = builder.select_ef(index_bits[num_bits - 1], left_half[0], right_half[0]);

//     let right_half_val = right_half.remove(0);

//     let left_half_index_bits: Vec<Var<_>> = index_bits[..num_bits - 1]
//         .iter()
//         .map(|x| builder.eval(*x * index_bits[num_bits - 1]))
//         .collect();

//     let right_half_index_bits: Vec<Var<_>> = index_bits[..num_bits - 1]
//         .iter()
//         .map(|x| builder.eval(*x * (index_bits[num_bits - 1]) + C::N::neg_one()))
//         .collect();
//     right_half = insert_e(builder, &right_half, right_half_val, right_half_index_bits);
//     left_half = insert_e(builder, &left_half, left_half_val, left_half_index_bits);
//     left_half.extend(right_half);
//     left_half
// }
