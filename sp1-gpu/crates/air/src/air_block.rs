use crate::{
    symbolic_expr_f::SymbolicExprF, symbolic_var_f::SymbolicVarF, SymbolicProverFolder, F,
};
use itertools::Itertools;
use slop_air::{Air, AirBuilder, PairBuilder};
use slop_algebra::{AbstractExtensionField, AbstractField};
use slop_matrix::Matrix;
use sp1_core_executor::events::FieldOperation;
use sp1_core_executor::{ByteOpcode, SyscallCode};
use sp1_core_machine::air::{MemoryAirBuilder, SP1CoreAirBuilder, WordAirBuilder};
use sp1_core_machine::global::{GlobalChip, GlobalCols};
use sp1_core_machine::operations::{
    AddrAddOperation, AddressSlicePageProtOperation, SyscallAddrOperation,
};
use sp1_core_machine::riscv::{WeierstrassAddAssignChip, WeierstrassDoubleAssignChip};
use sp1_core_machine::syscall::precompiles::weierstrass::{
    WeierstrassAddAssignCols, WeierstrassDoubleAssignCols,
};
use sp1_core_machine::utils::limbs_to_words;
use sp1_core_machine::{
    riscv::{KeccakPermuteChip, RiscvAir},
    syscall::precompiles::keccak256::{columns::KeccakMemCols, constants::rc_value_bit},
};
use sp1_core_machine::{TrustMode, UserMode};
use sp1_curves::k256::elliptic_curve::generic_array::typenum::Unsigned;
use sp1_curves::params::FieldParameters;
use sp1_curves::params::{Limbs, NumLimbs};
use sp1_curves::weierstrass::WeierstrassParameters;
use sp1_curves::{BigUint, CurveType, EllipticCurve};
use sp1_hypercube::air::{InstructionAirBuilder, MachineAirBuilder};
use sp1_hypercube::operations::poseidon2::air::{eval_external_round, eval_internal_rounds};
use sp1_hypercube::operations::poseidon2::permutation::Poseidon2Cols;
use sp1_hypercube::operations::poseidon2::{NUM_EXTERNAL_ROUNDS, WIDTH};
use sp1_hypercube::septic_curve::SepticCurve;
use sp1_hypercube::septic_extension::SepticExtension;
use sp1_hypercube::Word;
use sp1_hypercube::{
    air::{
        AirInteraction, ByteAirBuilder, InteractionScope, MachineAir, MessageBuilder,
        SepticExtensionAirBuilder,
    },
    InteractionKind,
};
use sp1_primitives::consts::{PROT_READ, PROT_WRITE};
use sp1_primitives::polynomial::Polynomial;
use sp1_primitives::SP1Field;
use sp1_recursion_machine::builder::RecursionAirBuilder;
use sp1_recursion_machine::chips::poseidon2_wide::columns::preprocessed::Poseidon2PreprocessedColsWide;
use sp1_recursion_machine::chips::poseidon2_wide::Poseidon2WideChip;
use sp1_recursion_machine::RecursionAir;
use std::borrow::Borrow;
use std::iter::once;
pub trait BlockAir<AB: AirBuilder>: Air<AB> + MachineAir<F> + 'static + Send + Sync {
    fn num_blocks(&self) -> usize {
        1
    }

    fn eval_block(&self, builder: &mut AB, index: usize) {
        assert!(index == 0);
        self.eval(builder);
    }
}

/// Number of [`BlockAir`] blocks consumed by a single Poseidon2 permutation: one block per external
/// round, plus one block holding all internal rounds.
pub const POSEIDON2_PERM_NUM_BLOCKS: usize = NUM_EXTERNAL_ROUNDS + 1;

/// Evaluates the `index`-th block of the Poseidon2 permutation constraints over `perm_cols`.
///
/// `index` must be in `0..POSEIDON2_PERM_NUM_BLOCKS`. The first `NUM_EXTERNAL_ROUNDS` indices each
/// evaluate one external round; the final index evaluates all internal rounds.
fn eval_poseidon2_perm_block<AB>(
    builder: &mut AB,
    perm_cols: &dyn Poseidon2Cols<AB::Var>,
    index: usize,
) where
    AB: MachineAirBuilder + PairBuilder,
{
    if index < NUM_EXTERNAL_ROUNDS {
        eval_external_round(builder, perm_cols, index);
    } else if index == NUM_EXTERNAL_ROUNDS {
        eval_internal_rounds(builder, perm_cols);
    } else {
        panic!("Poseidon2 permutation block index out of range: {index}");
    }
}

impl<'a> BlockAir<SymbolicProverFolder<'a>> for RiscvAir<F> {
    fn num_blocks(&self) -> usize {
        match self {
            RiscvAir::KeccakP(keccak) => keccak.num_blocks(),
            RiscvAir::Secp256k1Add(secp256k1_add) => secp256k1_add.num_blocks(),
            RiscvAir::Secp256k1AddUser(secp256k1_add) => secp256k1_add.num_blocks(),
            RiscvAir::Secp256k1Double(secp256k1_double) => secp256k1_double.num_blocks(),
            RiscvAir::Secp256k1DoubleUser(secp256k1_double) => secp256k1_double.num_blocks(),
            RiscvAir::Global(global) => global.num_blocks(),
            _ => 1,
        }
    }

    fn eval_block(&self, builder: &mut SymbolicProverFolder<'a>, index: usize) {
        match self {
            RiscvAir::KeccakP(keccak) => keccak.eval_block(builder, index),
            RiscvAir::Secp256k1Add(secp256k1_add) => secp256k1_add.eval_block(builder, index),
            RiscvAir::Secp256k1AddUser(secp256k1_add) => secp256k1_add.eval_block(builder, index),
            RiscvAir::Secp256k1Double(secp256k1_double) => {
                secp256k1_double.eval_block(builder, index)
            }
            RiscvAir::Secp256k1DoubleUser(secp256k1_double) => {
                secp256k1_double.eval_block(builder, index)
            }
            RiscvAir::Global(global) => global.eval_block(builder, index),
            _ => {
                assert!(index == 0);
                self.eval(builder);
            }
        }
    }
}

impl<'a, const DEGREE: usize, const VAR_EVENTS_PER_ROW: usize> BlockAir<SymbolicProverFolder<'a>>
    for RecursionAir<SP1Field, DEGREE, VAR_EVENTS_PER_ROW>
{
    fn num_blocks(&self) -> usize {
        match self {
            RecursionAir::Poseidon2Wide(poseidon2_wide) => poseidon2_wide.num_blocks(),
            _ => 1,
        }
    }

    fn eval_block(&self, builder: &mut SymbolicProverFolder<'a>, index: usize) {
        match self {
            RecursionAir::Poseidon2Wide(poseidon2_wide) => {
                poseidon2_wide.eval_block(builder, index)
            }
            _ => {
                assert!(index == 0);
                self.eval(builder);
            }
        }
    }
}

impl<'a> BlockAir<SymbolicProverFolder<'a>> for KeccakPermuteChip {
    fn num_blocks(&self) -> usize {
        11
    }

    fn eval_block(&self, builder: &mut SymbolicProverFolder<'a>, index: usize) {
        const NUM_ROUNDS: usize = 24;
        const BITS_PER_LIMB: usize = 16;
        const U64_LIMBS: usize = 4;

        let main = builder.main();
        let local = main.row_slice(0);
        let local: &KeccakMemCols<SymbolicVarF> = (*local).borrow();

        // Keccak AIRs from Plonky3.
        let andn_gen = |a: SymbolicExprF, b: SymbolicExprF| b - a * b;
        let xor_gen = |a: SymbolicExprF, b: SymbolicExprF| a + b - a * b.double();
        let xor3_gen =
            |a: SymbolicExprF, b: SymbolicExprF, c: SymbolicExprF| xor_gen(a, xor_gen(b, c));

        match index {
            0 => {
                builder.assert_bool(local.is_real);
                // Flag constraints.
                let mut sum_flags = SymbolicExprF::zero();
                let mut computed_index = SymbolicExprF::zero();
                for i in 0..NUM_ROUNDS {
                    builder.assert_bool(local.keccak.step_flags[i]);
                    sum_flags = sum_flags + local.keccak.step_flags[i];
                    computed_index = computed_index
                        + SymbolicExprF::from_canonical_u32(i as u32) * local.keccak.step_flags[i];
                }
                builder.assert_one(sum_flags);
                builder.when(local.is_real).assert_eq(computed_index, local.index);

                // C'[x, z] = xor(C[x, z], C[x - 1, z], C[x + 1, z - 1]).
                for x in 0..5 {
                    for z in 0..64 {
                        builder.assert_bool(local.keccak.c[x][z]);
                        let xor = xor3_gen(
                            local.keccak.c[x][z].into(),
                            local.keccak.c[(x + 4) % 5][z].into(),
                            local.keccak.c[(x + 1) % 5][(z + 63) % 64].into(),
                        );
                        let c_prime = local.keccak.c_prime[x][z];
                        builder.assert_eq(c_prime, xor);
                    }
                }
            }
            1..=5 => {
                // Check that the input limbs are consistent with A' and D.
                // A[x, y, z] = xor(A'[x, y, z], D[x, y, z])
                //            = xor(A'[x, y, z], C[x - 1, z], C[x + 1, z - 1])
                //            = xor(A'[x, y, z], C[x, z], C'[x, z]).
                // The last step is valid based on the identity we checked above.
                // It isn't required, but makes this check a bit cleaner.
                let y = index - 1;
                for x in 0..5 {
                    let get_bit = |z| {
                        let a_prime: SymbolicVarF = local.keccak.a_prime[y][x][z];
                        let c: SymbolicVarF = local.keccak.c[x][z];
                        let c_prime: SymbolicVarF = local.keccak.c_prime[x][z];
                        xor3_gen(a_prime.into(), c.into(), c_prime.into())
                    };

                    for limb in 0..U64_LIMBS {
                        let a_limb = local.keccak.a[y][x][limb];
                        let computed_limb = (limb * BITS_PER_LIMB..(limb + 1) * BITS_PER_LIMB)
                            .rev()
                            .fold(SymbolicExprF::zero(), |acc, z| {
                                builder.assert_bool(local.keccak.a_prime[y][x][z]);
                                acc.double() + get_bit(z)
                            });
                        builder.assert_eq(computed_limb, a_limb);
                    }
                }
            }
            6 => {
                for x in 0..5 {
                    for z in 0..64 {
                        let sum: SymbolicExprF =
                            (0..5).map(|y| local.keccak.a_prime[y][x][z].into()).sum();
                        let diff = sum - local.keccak.c_prime[x][z];
                        let four = SymbolicExprF::from_canonical_u8(4);
                        builder.assert_zero(diff * (diff - SymbolicExprF::two()) * (diff - four));
                    }
                }
            }
            7..=9 => {
                let y_range = match index {
                    7 => 0..2,
                    8 => 2..4,
                    9 => 4..5,
                    _ => unreachable!(),
                };
                // A''[x, y] = xor(B[x, y], andn(B[x + 1, y], B[x + 2, y])).
                for y in y_range {
                    for x in 0..5 {
                        let get_bit = |z| {
                            let andn = andn_gen(
                                local.keccak.b((x + 1) % 5, y, z).into(),
                                local.keccak.b((x + 2) % 5, y, z).into(),
                            );
                            xor_gen(local.keccak.b(x, y, z).into(), andn)
                        };

                        for limb in 0..U64_LIMBS {
                            let computed_limb = (limb * BITS_PER_LIMB..(limb + 1) * BITS_PER_LIMB)
                                .rev()
                                .fold(SymbolicExprF::zero(), |acc, z| acc.double() + get_bit(z));
                            builder
                                .assert_eq(computed_limb, local.keccak.a_prime_prime[y][x][limb]);
                        }
                    }
                }
            }
            10 => {
                // A'''[0, 0] = A''[0, 0] XOR RC
                for limb in 0..U64_LIMBS {
                    let computed_a_prime_prime_0_0_limb = (limb * BITS_PER_LIMB
                        ..(limb + 1) * BITS_PER_LIMB)
                        .rev()
                        .fold(SymbolicExprF::zero(), |acc, z| {
                            builder.assert_bool(local.keccak.a_prime_prime_0_0_bits[z]);
                            acc.double() + local.keccak.a_prime_prime_0_0_bits[z]
                        });
                    let a_prime_prime_0_0_limb = local.keccak.a_prime_prime[0][0][limb];
                    builder.assert_eq(computed_a_prime_prime_0_0_limb, a_prime_prime_0_0_limb);
                }

                let get_xored_bit = |i| {
                    let mut rc_bit_i = SymbolicExprF::zero();
                    for r in 0..NUM_ROUNDS {
                        let this_round = local.keccak.step_flags[r];
                        let this_round_constant =
                            SymbolicExprF::from_canonical_u8(rc_value_bit(r, i));
                        rc_bit_i = rc_bit_i + this_round * this_round_constant;
                    }

                    xor_gen(local.keccak.a_prime_prime_0_0_bits[i].into(), rc_bit_i)
                };

                for limb in 0..U64_LIMBS {
                    let a_prime_prime_prime_0_0_limb =
                        local.keccak.a_prime_prime_prime_0_0_limbs[limb];
                    let computed_a_prime_prime_prime_0_0_limb = (limb * BITS_PER_LIMB
                        ..(limb + 1) * BITS_PER_LIMB)
                        .rev()
                        .fold(SymbolicExprF::zero(), |acc, z| acc.double() + get_xored_bit(z));
                    builder.assert_eq(
                        computed_a_prime_prime_prime_0_0_limb,
                        a_prime_prime_prime_0_0_limb,
                    );
                }
                // Receive state.
                let receive_values =
                    once(local.clk_high)
                        .chain(once(local.clk_low))
                        .chain(local.state_addr)
                        .chain(once(local.index))
                        .chain(local.keccak.a.into_iter().flat_map(|two_d| {
                            two_d.into_iter().flat_map(|one_d| one_d.into_iter())
                        }))
                        .collect::<Vec<_>>();

                builder.receive(
                    AirInteraction::new(receive_values, local.is_real, InteractionKind::Keccak),
                    InteractionScope::Local,
                );

                // Send state.
                let send_values = once(local.clk_high.into())
                    .chain(once(local.clk_low.into()))
                    .chain(local.state_addr.map(Into::into))
                    .chain(once(local.index + SymbolicExprF::one()))
                    .chain((0..5).flat_map(|y| {
                        (0..5).flat_map(move |x| {
                            (0..4).map(move |limb| {
                                local.keccak.a_prime_prime_prime(y, x, limb).into()
                            })
                        })
                    }))
                    .collect::<Vec<_>>();

                builder.send(
                    AirInteraction::new(send_values, local.is_real.into(), InteractionKind::Keccak),
                    InteractionScope::Local,
                );
            }
            _ => unreachable!(),
        };
    }
}

impl<'a, E: EllipticCurve + WeierstrassParameters, M: TrustMode> BlockAir<SymbolicProverFolder<'a>>
    for WeierstrassAddAssignChip<E, M>
where
    Limbs<SymbolicVarF, <E::BaseField as NumLimbs>::Limbs>: Copy,
{
    fn num_blocks(&self) -> usize {
        11
    }

    fn eval_block(&self, builder: &mut SymbolicProverFolder<'a>, index: usize) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &WeierstrassAddAssignCols<SymbolicVarF, E::BaseField, M> = (*local).borrow();

        // Fetch the syscall id for the curve type.
        let syscall_id_felt = match E::CURVE_TYPE {
            CurveType::Secp256k1 => F::from_canonical_u32(SyscallCode::SECP256K1_ADD.syscall_id()),
            CurveType::Secp256r1 => F::from_canonical_u32(SyscallCode::SECP256R1_ADD.syscall_id()),
            CurveType::Bn254 => F::from_canonical_u32(SyscallCode::BN254_ADD.syscall_id()),
            CurveType::Bls12381 => F::from_canonical_u32(SyscallCode::BLS12381_ADD.syscall_id()),
            _ => panic!("Unsupported curve"),
        };
        let num_words_field_element = <E::BaseField as NumLimbs>::Limbs::USIZE / 8;

        // It's very important that the `generate_limbs` function do not call `assert_zero`.
        let p_x_limbs = builder
            .generate_limbs(&local.p_access[0..num_words_field_element], local.is_real.into());
        let p_x: Limbs<SymbolicExprF, <E::BaseField as NumLimbs>::Limbs> =
            Limbs(p_x_limbs.try_into().expect("failed to convert limbs"));
        let p_y_limbs = builder
            .generate_limbs(&local.p_access[num_words_field_element..], local.is_real.into());
        let p_y: Limbs<SymbolicExprF, <E::BaseField as NumLimbs>::Limbs> =
            Limbs(p_y_limbs.try_into().expect("failed to convert limbs"));
        let q_x_limbs = builder
            .generate_limbs(&local.q_access[0..num_words_field_element], local.is_real.into());
        let q_x: Limbs<SymbolicExprF, <E::BaseField as NumLimbs>::Limbs> =
            Limbs(q_x_limbs.try_into().expect("failed to convert limbs"));
        let q_y_limbs = builder
            .generate_limbs(&local.q_access[num_words_field_element..], local.is_real.into());
        let q_y: Limbs<SymbolicExprF, <E::BaseField as NumLimbs>::Limbs> =
            Limbs(q_y_limbs.try_into().expect("failed to convert limbs"));

        let is_not_trap: SymbolicExprF = local.is_real.into();
        let trap_code = SymbolicExprF::zero();

        match index {
            0 => {
                let mut is_not_trap = local.is_real.into();
                let mut trap_code = SymbolicExprF::zero();

                #[cfg(feature = "mprotect")]
                builder.assert_eq(
                    builder.extract_public_values().is_untrusted_programs_enabled,
                    SymbolicExprF::from_bool(!M::IS_TRUSTED),
                );

                if !M::IS_TRUSTED {
                    let local = main.row_slice(0);
                    let local: &WeierstrassAddAssignCols<SymbolicVarF, E::BaseField, UserMode> =
                        (*local).borrow();

                    #[cfg(not(feature = "mprotect"))]
                    builder.assert_zero(local.is_real);

                    AddressSlicePageProtOperation::<F>::eval(
                        builder,
                        local.clk_high.into(),
                        local.clk_low.into(),
                        &local.q_ptr.addr.map(Into::into),
                        &local.q_addrs[local.q_addrs.len() - 1].value.map(Into::into),
                        PROT_READ,
                        &local.read_slice_page_prot_access,
                        &mut is_not_trap,
                        &mut trap_code,
                    );

                    let clk_low: SymbolicExprF = local.clk_low.into();

                    AddressSlicePageProtOperation::<F>::eval(
                        builder,
                        local.clk_high.into(),
                        clk_low + SymbolicExprF::one(),
                        &local.p_ptr.addr.map(Into::into),
                        &local.p_addrs[local.p_addrs.len() - 1].value.map(Into::into),
                        PROT_READ | PROT_WRITE,
                        &local.write_slice_page_prot_access,
                        &mut is_not_trap,
                        &mut trap_code,
                    );

                    let x3_result_words =
                        limbs_to_words::<SymbolicProverFolder>(local.x3_ins.result.0.to_vec());
                    let y3_result_words =
                        limbs_to_words::<SymbolicProverFolder>(local.y3_ins.result.0.to_vec());
                    let result_words =
                        x3_result_words.into_iter().chain(y3_result_words).collect_vec();

                    builder.eval_memory_access_slice_read(
                        local.clk_high,
                        local.clk_low,
                        &local.q_addrs.iter().map(|addr| addr.value.map(Into::into)).collect_vec(),
                        &local.q_access.iter().map(|access| access.memory_access).collect_vec(),
                        is_not_trap,
                    );
                    // We read p at +1 since p, q could be the same.
                    builder.eval_memory_access_slice_write(
                        local.clk_high,
                        local.clk_low + F::from_canonical_u32(1),
                        &local.p_addrs.iter().map(|addr| addr.value.map(Into::into)).collect_vec(),
                        &local.p_access.iter().map(|access| access.memory_access).collect_vec(),
                        result_words,
                        is_not_trap,
                    );
                    builder.receive_syscall(
                        local.clk_high,
                        local.clk_low,
                        syscall_id_felt,
                        trap_code,
                        local.p_ptr.addr.map(Into::into),
                        local.q_ptr.addr.map(Into::into),
                        local.is_real,
                        InteractionScope::Local,
                    );
                }

                local.slope_numerator.eval(builder, &q_y, &p_y, FieldOperation::Sub, local.is_real);
            }
            1 => {
                local.slope_denominator.eval(
                    builder,
                    &q_x,
                    &p_x,
                    FieldOperation::Sub,
                    local.is_real,
                );
            }
            2 => {
                // We check that (q.x - p.x) is non-zero in the base field, by computing 1 / (q.x - p.x).
                let mut coeff_1 = Vec::new();
                coeff_1.resize(<E::BaseField as NumLimbs>::Limbs::USIZE, SymbolicExprF::zero());
                coeff_1[0] = SymbolicExprF::one();
                let one_polynomial = Polynomial::from_coefficients(&coeff_1);

                local.inverse_check.eval(
                    builder,
                    &one_polynomial,
                    &local.slope_denominator.result,
                    FieldOperation::Div,
                    local.is_real,
                );
            }
            3 => {
                local.slope.eval(
                    builder,
                    &local.slope_numerator.result,
                    &local.slope_denominator.result,
                    FieldOperation::Div,
                    local.is_real,
                );
            }
            4 => {
                local.slope_squared.eval(
                    builder,
                    &local.slope.result,
                    &local.slope.result,
                    FieldOperation::Mul,
                    local.is_real,
                );
            }
            5 => {
                local.p_x_plus_q_x.eval(builder, &p_x, &q_x, FieldOperation::Add, local.is_real);
            }
            6 => {
                local.x3_ins.eval(
                    builder,
                    &local.slope_squared.result,
                    &local.p_x_plus_q_x.result,
                    FieldOperation::Sub,
                    local.is_real,
                );
            }
            7 => {
                local.p_x_minus_x.eval(
                    builder,
                    &p_x,
                    &local.x3_ins.result,
                    FieldOperation::Sub,
                    local.is_real,
                );
            }
            8 => {
                local.slope_times_p_x_minus_x.eval(
                    builder,
                    &local.slope.result,
                    &local.p_x_minus_x.result,
                    FieldOperation::Mul,
                    local.is_real,
                );
            }
            9 => {
                local.y3_ins.eval(
                    builder,
                    &local.slope_times_p_x_minus_x.result,
                    &p_y,
                    FieldOperation::Sub,
                    local.is_real,
                );
            }
            10 => {
                let modulus =
                    E::BaseField::to_limbs_field::<SymbolicExprF, F>(&E::BaseField::modulus());
                local.x3_range.eval(builder, &local.x3_ins.result, &modulus, local.is_real);
                local.y3_range.eval(builder, &local.y3_ins.result, &modulus, local.is_real);
                let x3_result_words =
                    limbs_to_words::<SymbolicProverFolder>(local.x3_ins.result.0.to_vec());
                let y3_result_words =
                    limbs_to_words::<SymbolicProverFolder>(local.y3_ins.result.0.to_vec());
                let result_words = x3_result_words.into_iter().chain(y3_result_words).collect_vec();

                let p_ptr = SyscallAddrOperation::<F>::eval(
                    builder,
                    E::NB_LIMBS as u32 * 2,
                    local.p_ptr,
                    local.is_real.into(),
                );
                let q_ptr = SyscallAddrOperation::<F>::eval(
                    builder,
                    E::NB_LIMBS as u32 * 2,
                    local.q_ptr,
                    local.is_real.into(),
                );

                // p_addrs[i] = p_ptr + 8 * i
                for i in 0..local.p_addrs.len() {
                    AddrAddOperation::<F>::eval(
                        builder,
                        Word([
                            p_ptr[0].into(),
                            p_ptr[1].into(),
                            p_ptr[2].into(),
                            SymbolicExprF::zero(),
                        ]),
                        Word::from(8 * i as u64),
                        local.p_addrs[i],
                        local.is_real.into(),
                    );
                }

                // q_addrs[i] = q_ptr + 8 * i
                for i in 0..local.q_addrs.len() {
                    AddrAddOperation::<F>::eval(
                        builder,
                        Word([
                            q_ptr[0].into(),
                            q_ptr[1].into(),
                            q_ptr[2].into(),
                            SymbolicExprF::zero(),
                        ]),
                        Word::from(8 * i as u64),
                        local.q_addrs[i],
                        local.is_real.into(),
                    );
                }

                if M::IS_TRUSTED {
                    builder.eval_memory_access_slice_read(
                        local.clk_high,
                        local.clk_low,
                        &local.q_addrs.iter().map(|addr| addr.value.map(Into::into)).collect_vec(),
                        &local.q_access.iter().map(|access| access.memory_access).collect_vec(),
                        is_not_trap,
                    );
                    // We read p at +1 since p, q could be the same.
                    builder.eval_memory_access_slice_write(
                        local.clk_high,
                        local.clk_low + F::from_canonical_u32(1),
                        &local.p_addrs.iter().map(|addr| addr.value.map(Into::into)).collect_vec(),
                        &local.p_access.iter().map(|access| access.memory_access).collect_vec(),
                        result_words,
                        is_not_trap,
                    );

                    builder.receive_syscall(
                        local.clk_high,
                        local.clk_low,
                        syscall_id_felt,
                        trap_code,
                        p_ptr.map(Into::into),
                        q_ptr.map(Into::into),
                        local.is_real,
                        InteractionScope::Local,
                    );
                }
            }
            _ => unreachable!(),
        };
    }
}

impl<'a, E: EllipticCurve + WeierstrassParameters, M: TrustMode> BlockAir<SymbolicProverFolder<'a>>
    for WeierstrassDoubleAssignChip<E, M>
where
    Limbs<SymbolicVarF, <E::BaseField as NumLimbs>::Limbs>: Copy,
{
    fn num_blocks(&self) -> usize {
        12
    }

    fn eval_block(&self, builder: &mut SymbolicProverFolder<'a>, index: usize) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &WeierstrassDoubleAssignCols<SymbolicVarF, E::BaseField, M> = (*local).borrow();

        let num_words_field_element = <E::BaseField as NumLimbs>::Limbs::USIZE / 8;

        // Fetch the syscall id for the curve type.
        let syscall_id_felt = match E::CURVE_TYPE {
            CurveType::Secp256k1 => {
                F::from_canonical_u32(SyscallCode::SECP256K1_DOUBLE.syscall_id())
            }
            CurveType::Secp256r1 => {
                F::from_canonical_u32(SyscallCode::SECP256R1_DOUBLE.syscall_id())
            }
            CurveType::Bn254 => F::from_canonical_u32(SyscallCode::BN254_DOUBLE.syscall_id()),
            CurveType::Bls12381 => F::from_canonical_u32(SyscallCode::BLS12381_DOUBLE.syscall_id()),
            _ => panic!("Unsupported curve"),
        };

        // It's very important that the `generate_limbs` function do not call `assert_zero`.
        let p_x_limbs = builder
            .generate_limbs(&local.p_access[0..num_words_field_element], local.is_real.into());
        let p_x: Limbs<SymbolicExprF, <E::BaseField as NumLimbs>::Limbs> =
            Limbs(p_x_limbs.try_into().expect("failed to convert limbs"));
        let p_y_limbs = builder
            .generate_limbs(&local.p_access[num_words_field_element..], local.is_real.into());
        let p_y: Limbs<SymbolicExprF, <E::BaseField as NumLimbs>::Limbs> =
            Limbs(p_y_limbs.try_into().expect("failed to convert limbs"));
        // `a` in the Weierstrass form: y^2 = x^3 + a * x + b.
        let a = E::BaseField::to_limbs_field::<SymbolicExprF, F>(&E::a_int());

        let is_not_trap: SymbolicExprF = local.is_real.into();
        let trap_code = SymbolicExprF::zero();

        match index {
            0 => {
                let mut is_not_trap = local.is_real.into();
                let mut trap_code = SymbolicExprF::zero();

                #[cfg(feature = "mprotect")]
                builder.assert_eq(
                    builder.extract_public_values().is_untrusted_programs_enabled,
                    SymbolicExprF::from_bool(!M::IS_TRUSTED),
                );

                if !M::IS_TRUSTED {
                    let local = main.row_slice(0);
                    let local: &WeierstrassDoubleAssignCols<SymbolicVarF, E::BaseField, UserMode> =
                        (*local).borrow();

                    #[cfg(not(feature = "mprotect"))]
                    builder.assert_zero(local.is_real);
                    AddressSlicePageProtOperation::<F>::eval(
                        builder,
                        local.clk_high.into(),
                        local.clk_low.into(),
                        &local.p_ptr.addr.map(Into::into),
                        &local.p_addrs[local.p_addrs.len() - 1].value.map(Into::into),
                        PROT_READ | PROT_WRITE,
                        &local.write_slice_page_prot_access,
                        &mut is_not_trap,
                        &mut trap_code,
                    );

                    let x3_result_words =
                        limbs_to_words::<SymbolicProverFolder>(local.x3_ins.result.0.to_vec());
                    let y3_result_words =
                        limbs_to_words::<SymbolicProverFolder>(local.y3_ins.result.0.to_vec());
                    let result_words =
                        x3_result_words.into_iter().chain(y3_result_words).collect_vec();

                    builder.eval_memory_access_slice_write(
                        local.clk_high,
                        local.clk_low,
                        &local.p_addrs.iter().map(|addr| addr.value.map(Into::into)).collect_vec(),
                        &local.p_access.iter().map(|access| access.memory_access).collect_vec(),
                        result_words,
                        is_not_trap,
                    );

                    builder.receive_syscall(
                        local.clk_high,
                        local.clk_low,
                        syscall_id_felt,
                        trap_code,
                        local.p_ptr.addr.map(Into::into),
                        [SymbolicExprF::zero(), SymbolicExprF::zero(), SymbolicExprF::zero()],
                        local.is_real,
                        InteractionScope::Local,
                    );
                }
                local.p_x_squared.eval(builder, &p_x, &p_x, FieldOperation::Mul, local.is_real);
            }
            1 => {
                local.p_x_squared_times_3.eval(
                    builder,
                    &local.p_x_squared.result,
                    &E::BaseField::to_limbs_field::<SymbolicExprF, F>(&BigUint::from(3u32)),
                    FieldOperation::Mul,
                    local.is_real,
                );
            }
            2 => {
                local.slope_numerator.eval(
                    builder,
                    &a,
                    &local.p_x_squared_times_3.result,
                    FieldOperation::Add,
                    local.is_real,
                );
            }
            3 => {
                local.slope_denominator.eval(
                    builder,
                    &E::BaseField::to_limbs_field::<SymbolicExprF, F>(&BigUint::from(2u32)),
                    &p_y,
                    FieldOperation::Mul,
                    local.is_real,
                );
            }
            4 => {
                local.slope.eval(
                    builder,
                    &local.slope_numerator.result,
                    &local.slope_denominator.result,
                    FieldOperation::Div,
                    local.is_real,
                );
            }
            5 => {
                local.slope_squared.eval(
                    builder,
                    &local.slope.result,
                    &local.slope.result,
                    FieldOperation::Mul,
                    local.is_real,
                );
            }
            6 => {
                local.p_x_plus_p_x.eval(builder, &p_x, &p_x, FieldOperation::Add, local.is_real);
            }
            7 => {
                local.x3_ins.eval(
                    builder,
                    &local.slope_squared.result,
                    &local.p_x_plus_p_x.result,
                    FieldOperation::Sub,
                    local.is_real,
                );
            }
            8 => {
                local.p_x_minus_x.eval(
                    builder,
                    &p_x,
                    &local.x3_ins.result,
                    FieldOperation::Sub,
                    local.is_real,
                );
            }
            9 => {
                local.slope_times_p_x_minus_x.eval(
                    builder,
                    &local.slope.result,
                    &local.p_x_minus_x.result,
                    FieldOperation::Mul,
                    local.is_real,
                );
            }
            10 => {
                local.y3_ins.eval(
                    builder,
                    &local.slope_times_p_x_minus_x.result,
                    &p_y,
                    FieldOperation::Sub,
                    local.is_real,
                );
            }
            11 => {
                let modulus =
                    E::BaseField::to_limbs_field::<SymbolicExprF, F>(&E::BaseField::modulus());
                local.x3_range.eval(builder, &local.x3_ins.result, &modulus, local.is_real);
                local.y3_range.eval(builder, &local.y3_ins.result, &modulus, local.is_real);

                let x3_result_words =
                    limbs_to_words::<SymbolicProverFolder>(local.x3_ins.result.0.to_vec());
                let y3_result_words =
                    limbs_to_words::<SymbolicProverFolder>(local.y3_ins.result.0.to_vec());
                let result_words = x3_result_words.into_iter().chain(y3_result_words).collect_vec();

                let p_ptr = SyscallAddrOperation::<F>::eval(
                    builder,
                    E::NB_LIMBS as u32 * 2,
                    local.p_ptr,
                    local.is_real.into(),
                );

                // p_addrs[i] = p_ptr + 8 * i
                for i in 0..local.p_addrs.len() {
                    AddrAddOperation::<F>::eval(
                        builder,
                        Word([
                            p_ptr[0].into(),
                            p_ptr[1].into(),
                            p_ptr[2].into(),
                            SymbolicExprF::zero(),
                        ]),
                        Word::from(8 * i as u64),
                        local.p_addrs[i],
                        local.is_real.into(),
                    );
                }

                if M::IS_TRUSTED {
                    builder.eval_memory_access_slice_write(
                        local.clk_high,
                        local.clk_low,
                        &local.p_addrs.iter().map(|addr| addr.value.map(Into::into)).collect_vec(),
                        &local.p_access.iter().map(|access| access.memory_access).collect_vec(),
                        result_words,
                        is_not_trap,
                    );

                    builder.receive_syscall(
                        local.clk_high,
                        local.clk_low,
                        syscall_id_felt,
                        trap_code,
                        p_ptr.map(Into::into),
                        [SymbolicExprF::zero(), SymbolicExprF::zero(), SymbolicExprF::zero()],
                        local.is_real,
                        InteractionScope::Local,
                    );
                }
            }

            _ => unreachable!(),
        };
    }
}

impl<'a, const DEGREE: usize> BlockAir<SymbolicProverFolder<'a>> for Poseidon2WideChip<DEGREE> {
    fn num_blocks(&self) -> usize {
        POSEIDON2_PERM_NUM_BLOCKS
    }

    fn eval_block(&self, builder: &mut SymbolicProverFolder<'a>, index: usize) {
        let main = builder.main();
        let prepr = builder.preprocessed();
        let local_row = Self::convert::<SymbolicVarF>(main.row_slice(0));
        let prep_local = prepr.row_slice(0);
        let prep_local: &Poseidon2PreprocessedColsWide<_> = (*prep_local).borrow();

        if index == 0 {
            // Dummy constraints to normalize to DEGREE.
            let lhs = (0..DEGREE)
                .map(|_| local_row.external_rounds_state()[0][0].into())
                .product::<SymbolicExprF>();
            let rhs = (0..DEGREE)
                .map(|_| local_row.external_rounds_state()[0][0].into())
                .product::<SymbolicExprF>();
            builder.assert_eq(lhs, rhs);

            (0..WIDTH).for_each(|i| {
                builder.receive_single(
                    prep_local.input[i],
                    local_row.external_rounds_state()[0][i],
                    prep_local.is_real,
                )
            });

            (0..WIDTH).for_each(|i| {
                builder.send_single(
                    prep_local.output[i].addr,
                    local_row.perm_output()[i],
                    prep_local.output[i].mult,
                )
            });
        }
        eval_poseidon2_perm_block(builder, local_row.as_ref(), index);
    }
}

/// Number of `GlobalChip` [`BlockAir`] blocks consumed *after* the Poseidon2 permutation: one
/// block each for the curve formula, y-coordinate sign + range checks, and digest accumulation.
const GLOBAL_NUM_EC_BLOCKS: usize = 3;

impl<'a> BlockAir<SymbolicProverFolder<'a>> for GlobalChip {
    fn num_blocks(&self) -> usize {
        POSEIDON2_PERM_NUM_BLOCKS + GLOBAL_NUM_EC_BLOCKS
    }

    fn eval_block(&self, builder: &mut SymbolicProverFolder<'a>, index: usize) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &GlobalCols<SymbolicVarF> = (*local).borrow();

        let cols = local.interaction;
        let acc = local.accumulation;
        let is_real = local.is_real;
        let is_receive: SymbolicExprF = local.is_receive.into();
        let is_send: SymbolicExprF = local.is_send.into();

        match index {
            0 => {
                // Top-level constraints from `GlobalChip::eval`.
                builder.assert_bool(is_real);
                builder.receive(
                    AirInteraction::new(
                        vec![
                            SymbolicExprF::from(local.message[0]),
                            local.message[1].into(),
                            local.message[2].into(),
                            local.message[3].into(),
                            local.message[4].into(),
                            local.message[5].into(),
                            local.message[6].into(),
                            local.message[7].into(),
                            local.is_send.into(),
                            local.is_receive.into(),
                            local.kind.into(),
                        ],
                        is_real.into(),
                        InteractionKind::Global,
                    ),
                    InteractionScope::Local,
                );

                // Setup constraints from `GlobalInteractionOperation::eval_single_digest`.
                builder.assert_bool(is_real);
                builder.when(is_real).assert_eq(is_receive + is_send, SymbolicExprF::one());
                builder.assert_bool(is_receive);
                builder.assert_bool(is_send);

                builder.send_byte(
                    SymbolicExprF::from_canonical_u32(ByteOpcode::U8Range as u32),
                    SymbolicExprF::zero(),
                    SymbolicExprF::zero(),
                    SymbolicExprF::from(cols.offset),
                    SymbolicExprF::from(is_real),
                );

                builder.when(is_real).assert_eq(
                    SymbolicExprF::from(local.message[0]),
                    local.message_0_16bit_limb
                        + local.message_0_8bit_limb * F::from_canonical_u32(1 << 16),
                );

                builder.slice_range_check_u16(
                    &[SymbolicExprF::from(local.message_0_16bit_limb), local.message[7].into()],
                    is_real,
                );
                builder.slice_range_check_u8(&[local.message_0_8bit_limb], is_real);

                builder.send_byte(
                    SymbolicExprF::from_canonical_u32(ByteOpcode::Range as u32),
                    SymbolicExprF::from(local.kind),
                    SymbolicExprF::from_canonical_u32(6),
                    SymbolicExprF::zero(),
                    SymbolicExprF::from(is_real),
                );

                // Constrain the permutation input to equal the hash trial.
                let m_trial: [SymbolicExprF; WIDTH] = [
                    SymbolicExprF::from(local.message[0])
                        + SymbolicExprF::from_canonical_u32(1 << 24) * local.kind,
                    local.message[1].into(),
                    local.message[2].into(),
                    local.message[3].into(),
                    local.message[4].into(),
                    local.message[5].into(),
                    local.message[6].into(),
                    SymbolicExprF::from(local.message[7])
                        + SymbolicExprF::from_canonical_u32(1 << 16) * cols.offset,
                    SymbolicExprF::zero(),
                    SymbolicExprF::zero(),
                    SymbolicExprF::zero(),
                    SymbolicExprF::zero(),
                    SymbolicExprF::zero(),
                    SymbolicExprF::zero(),
                    SymbolicExprF::zero(),
                    SymbolicExprF::zero(),
                ];
                for (perm_input, trial) in cols.permutation.permutation.external_rounds_state()[0]
                    .iter()
                    .zip(m_trial.iter())
                {
                    builder.when(is_real).assert_eq(*perm_input, *trial);
                }

                eval_poseidon2_perm_block(builder, &cols.permutation.permutation, 0);
            }
            i if i < POSEIDON2_PERM_NUM_BLOCKS - 1 => {
                eval_poseidon2_perm_block(builder, &cols.permutation.permutation, i);
            }
            i if i == POSEIDON2_PERM_NUM_BLOCKS - 1 => {
                eval_poseidon2_perm_block(builder, &cols.permutation.permutation, i);

                // The Poseidon2 output is the x-coordinate of the curve point.
                let m_hash = cols.permutation.permutation.perm_output();
                for (x_coord, hash) in cols.x_coordinate.0.iter().zip(m_hash.iter()) {
                    builder.when(is_real).assert_eq(*x_coord, *hash);
                }
            }
            9 => {
                // (x, y) lies on the septic curve y^2 = x^3 + 45x + 41z^3.
                let x = SepticExtension::<SymbolicExprF>::from_base_fn(|i| {
                    SymbolicExprF::from(cols.x_coordinate[i])
                });
                let y = SepticExtension::<SymbolicExprF>::from_base_fn(|i| {
                    SymbolicExprF::from(cols.y_coordinate[i])
                });
                let y2 = y.square();
                let curve = SepticCurve::<SymbolicExprF>::curve_formula(x);
                builder.assert_septic_ext_eq(y2, curve);
            }
            10 => {
                // y6 byte decomposition + sign-of-y constraints.
                let y = SepticExtension::<SymbolicExprF>::from_base_fn(|i| {
                    SymbolicExprF::from(cols.y_coordinate[i])
                });

                let mut y6_value = SymbolicExprF::zero();
                for i in 0..3 {
                    y6_value = y6_value
                        + cols.y6_byte_decomp[i] * SymbolicExprF::from_canonical_u32(1 << (8 * i));
                    builder.send_byte(
                        SymbolicExprF::from_canonical_u32(ByteOpcode::U8Range as u32),
                        SymbolicExprF::zero(),
                        SymbolicExprF::zero(),
                        SymbolicExprF::from(cols.y6_byte_decomp[i]),
                        SymbolicExprF::from(is_real),
                    );
                }
                y6_value =
                    y6_value + cols.y6_byte_decomp[3] * SymbolicExprF::from_canonical_u32(1 << 24);
                builder.send_byte(
                    SymbolicExprF::from_canonical_u32(ByteOpcode::LTU as u32),
                    SymbolicExprF::one(),
                    SymbolicExprF::from(cols.y6_byte_decomp[3]),
                    SymbolicExprF::from_canonical_u8(63),
                    SymbolicExprF::from(is_real),
                );

                builder.when(is_receive).assert_eq(y.0[6], SymbolicExprF::one() + y6_value);
                builder.when(is_send).assert_zero(y.0[6] + SymbolicExprF::one() + y6_value);
            }
            11 => {
                // Accumulation: receive previous digest, check sum, send next digest.
                builder.assert_bool(is_real);
                builder.receive(
                    AirInteraction::new(
                        vec![local.index]
                            .into_iter()
                            .chain(acc.initial_digest.into_iter().flat_map(|septic| septic.0))
                            .map(SymbolicExprF::from)
                            .collect(),
                        SymbolicExprF::from(is_real),
                        InteractionKind::GlobalAccumulation,
                    ),
                    InteractionScope::Local,
                );

                let initial_digest = SepticCurve::<SymbolicExprF> {
                    x: SepticExtension::<SymbolicExprF>::from_base_fn(|i| {
                        SymbolicExprF::from(acc.initial_digest[0][i])
                    }),
                    y: SepticExtension::<SymbolicExprF>::from_base_fn(|i| {
                        SymbolicExprF::from(acc.initial_digest[1][i])
                    }),
                };
                let cumulative_sum = SepticCurve::<SymbolicExprF> {
                    x: SepticExtension::<SymbolicExprF>::from_base_fn(|i| {
                        SymbolicExprF::from(acc.cumulative_sum[0].0[i])
                    }),
                    y: SepticExtension::<SymbolicExprF>::from_base_fn(|i| {
                        SymbolicExprF::from(acc.cumulative_sum[1].0[i])
                    }),
                };
                let point_to_add = SepticCurve::<SymbolicExprF> {
                    x: SepticExtension::<SymbolicExprF>::from_base_fn(|i| {
                        SymbolicExprF::from(cols.x_coordinate.0[i])
                    }),
                    y: SepticExtension::<SymbolicExprF>::from_base_fn(|i| {
                        SymbolicExprF::from(cols.y_coordinate.0[i])
                    }),
                };

                let sum_checker_x = SepticCurve::<SymbolicExprF>::sum_checker_x(
                    initial_digest,
                    point_to_add,
                    cumulative_sum,
                );
                let sum_checker_y = SepticCurve::<SymbolicExprF>::sum_checker_y(
                    initial_digest,
                    point_to_add,
                    cumulative_sum,
                );

                builder
                    .assert_septic_ext_eq(sum_checker_x, SepticExtension::<SymbolicExprF>::zero());
                builder
                    .when(is_real)
                    .assert_septic_ext_eq(sum_checker_y, SepticExtension::<SymbolicExprF>::zero());

                builder.send(
                    AirInteraction::new(
                        vec![local.index + SymbolicExprF::one()]
                            .into_iter()
                            .chain(
                                acc.cumulative_sum
                                    .into_iter()
                                    .flat_map(|septic| septic.0)
                                    .map(SymbolicExprF::from),
                            )
                            .collect(),
                        SymbolicExprF::from(is_real),
                        InteractionKind::GlobalAccumulation,
                    ),
                    InteractionScope::Local,
                );
            }
            _ => unreachable!(),
        }
    }
}
