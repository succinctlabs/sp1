use crate::air::{AirInteraction, CurtaAirBuilder, Word};
use crate::utils::{pad_to_power_of_two, Chip};
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use core::borrow::{Borrow, BorrowMut};
use core::mem::{size_of, transmute};
use p3_air::Air;
use p3_air::AirBuilder;
use p3_air::BaseAir;
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::MatrixRowSlices;
use p3_util::indices_arr;
use valida_derive::AlignedBorrow;

use crate::runtime::Segment;

pub struct MemoryInitChip {
    pub init: bool,
}

impl MemoryInitChip {
    pub fn new(init: bool) -> Self {
        Self { init }
    }
}

impl<F> BaseAir<F> for MemoryInitChip {
    fn width(&self) -> usize {
        NUM_MEMORY_INIT_COLS
    }
}

impl<F: PrimeField> Chip<F> for MemoryInitChip {
    fn name(&self) -> String {
        "MemoryInit".to_string()
    }

    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        let rows = segment
            .memory_access
            .iter() // TODO: change this back to par_iter
            .map(|(addr, segment, timestamp, val)| {
                let mut row = [F::zero(); NUM_MEMORY_INIT_COLS];
                let cols: &mut MemoryInitCols<F> = unsafe { transmute(&mut row) };
                cols.addr = F::from_canonical_u32(*addr);
                cols.value = if self.init {
                    0u32.into()
                } else {
                    cols.segment = F::from_canonical_u32(*segment);
                    cols.timestamp = F::from_canonical_u32(*timestamp);
                    (*val).into()
                };
                cols.is_real = F::one();
                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_INIT_COLS,
        );

        pad_to_power_of_two::<NUM_MEMORY_INIT_COLS, F>(&mut trace.values);

        trace
    }
}

#[derive(AlignedBorrow, Default, Debug)]
#[repr(C)]
pub struct MemoryInitCols<T> {
    pub segment: T,
    pub timestamp: T,
    pub addr: T,
    pub value: Word<T>,
    pub is_real: T,
}

pub(crate) const NUM_MEMORY_INIT_COLS: usize = size_of::<MemoryInitCols<u8>>();
pub(crate) const MEMORY_INIT_COL_MAP: MemoryInitCols<usize> = make_col_map();

const fn make_col_map() -> MemoryInitCols<usize> {
    let indices_arr = indices_arr::<NUM_MEMORY_INIT_COLS>();
    unsafe { transmute::<[usize; NUM_MEMORY_INIT_COLS], MemoryInitCols<usize>>(indices_arr) }
}

impl<AB> Air<AB> for MemoryInitChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &MemoryInitCols<AB::Var> = main.row_slice(0).borrow();

        // Dummy constraint of degree 3.
        builder.assert_eq(
            local.is_real * local.is_real * local.is_real,
            local.is_real * local.is_real * local.is_real,
        );

        if self.init {
            let mut values = vec![AB::Expr::zero(), AB::Expr::zero(), local.addr.into()];
            values.extend(local.value.map(Into::into));
            builder.receive(AirInteraction::new(
                values,
                local.is_real.into(),
                crate::lookup::InteractionKind::Memory,
            ));
        } else {
            let mut values: Vec<<AB as AirBuilder>::Expr> = vec![
                local.segment.into(),
                local.timestamp.into(),
                local.addr.into(),
            ];
            values.extend(local.value.map(Into::into));
            builder.send(AirInteraction::new(
                values,
                local.is_real.into(),
                crate::lookup::InteractionKind::Memory,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use p3_air::{Air, AirBuilder};
    use p3_challenger::DuplexChallenger;
    use p3_dft::Radix2DitParallel;
    use p3_field::Field;

    use p3_baby_bear::BabyBear;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{FriBasedPcs, FriConfigImpl, FriLdt};
    use p3_keccak::Keccak256Hash;
    use p3_ldt::QuotientMmcs;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_mds::coset_mds::CosetMds;
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_poseidon2::{DiffusionMatrixBabybear, Poseidon2};
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
    use p3_uni_stark::{prove, verify, StarkConfigImpl, SymbolicExpression, SymbolicVariable};
    use rand::thread_rng;

    use crate::lookup::InteractionBuilder;
    use crate::memory::MemoryInitChip;

    use crate::runtime::tests::simple_program;
    use crate::runtime::Runtime;
    use crate::utils::Chip;

    use p3_commit::ExtensionMmcs;

    #[test]
    fn test_memory_generate_trace() {
        // let events = vec![
        //     MemoryEvent {
        //         clk: 0,
        //         addr: 0,
        //         op: MemOp::Write,
        //         value: 0,
        //     },
        //     MemoryEvent {
        //         clk: 1,
        //         addr: 0,
        //         op: MemOp::Read,
        //         value: 0,
        //     },
        // ];
        // let trace: RowMajorMatrix<BabyBear> = MemoryChip::generate_trace(&events);
        // println!("{:?}", trace.values)
    }

    #[test]
    fn test_memory_prove_babybear() {
        type Val = BabyBear;
        type Domain = Val;
        type Challenge = BinomialExtensionField<Val, 4>;
        type PackedChallenge = BinomialExtensionField<<Domain as Field>::Packing, 4>;

        type MyMds = CosetMds<Val, 16>;
        let mds = MyMds::default();

        type Perm = Poseidon2<Val, MyMds, DiffusionMatrixBabybear, 16, 5>;
        let perm = Perm::new_from_rng(8, 22, mds, DiffusionMatrixBabybear, &mut thread_rng());

        type MyHash = SerializingHasher32<Keccak256Hash>;
        let hash = MyHash::new(Keccak256Hash {});

        type MyCompress = CompressionFunctionFromHasher<Val, MyHash, 2, 8>;
        let compress = MyCompress::new(hash);

        type ValMmcs = FieldMerkleTreeMmcs<Val, MyHash, MyCompress, 8>;
        let val_mmcs = ValMmcs::new(hash, compress);

        type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

        type Dft = Radix2DitParallel;
        let dft = Dft {};

        type Challenger = DuplexChallenger<Val, Perm, 16>;

        type Quotient = QuotientMmcs<Domain, Challenge, ValMmcs>;
        type MyFriConfig = FriConfigImpl<Val, Challenge, Quotient, ChallengeMmcs, Challenger>;
        let fri_config = MyFriConfig::new(40, challenge_mmcs);
        let ldt = FriLdt { config: fri_config };

        type Pcs = FriBasedPcs<MyFriConfig, ValMmcs, Dft, Challenger>;
        type MyConfig = StarkConfigImpl<Val, Challenge, PackedChallenge, Pcs, Challenger>;

        let pcs = Pcs::new(dft, val_mmcs, ldt);
        let config = StarkConfigImpl::new(pcs);
        let mut challenger = Challenger::new(perm.clone());

        let program = simple_program();
        let mut runtime = Runtime::new(program);
        runtime.run();

        let chip = MemoryInitChip::new(true);

        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime.segment);
        let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }

    #[test]
    fn test_memory_lookup_interactions() {
        // let air = MemoryChip::new();

        // let mut builder = InteractionBuilder::<BabyBear>::new(NUM_MEMORY_COLS);

        // air.eval(&mut builder);

        // let mut main = builder.main();
        // let (sends, receives) = builder.interactions();

        // for interaction in receives {
        //     for value in interaction.values {
        //         let expr = value.apply::<SymbolicExpression<BabyBear>, SymbolicVariable<BabyBear>>(
        //             &[],
        //             &main.row_mut(0),
        //         );
        //         println!("{}", expr);
        //     }
        // }

        // assert!(sends.is_empty());
    }
}
