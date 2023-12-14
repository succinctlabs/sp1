use std::collections::BTreeMap;

use crate::runtime::Register;

pub mod air;
mod interaction;
pub mod trace;

pub use interaction::MemoryInteraction;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MemOp {
    Read = 0,
    Write = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemoryEvent {
    pub addr: u32,
    pub clk: u32,
    pub op: MemOp,
    pub value: u32,
}

pub struct Memory {
    max_memory: u32,
    memory: BTreeMap<u32, u32>,
    registers: [u32; 32],
    memory_events: Vec<MemoryEvent>,
}

impl Memory {
    pub fn new(max_memory: u32) -> Self {
        assert_eq!(max_memory % 4, 0, "Memory size must be a multiple of 4");
        assert!(
            max_memory < u32::MAX - 31,
            "Memory size must be smaller than 2^32 - 32"
        );
        Self {
            max_memory,
            memory: BTreeMap::new(),
            registers: [0; 32],
            memory_events: Vec::new(),
        }
    }

    pub fn read(&mut self, clk: u32, addr: u32) -> u32 {
        let value = self.memory.get(&addr).expect("Unititialized memory");
        self.memory_events.push(MemoryEvent {
            clk,
            addr,
            op: MemOp::Read,
            value: *value,
        });
        *value
    }

    pub fn write(&mut self, clk: u32, addr: u32, value: u32) {
        self.memory_events.push(MemoryEvent {
            clk,
            addr,
            op: MemOp::Write,
            value,
        });
        self.memory.insert(addr, value);
    }

    pub fn read_register(&mut self, clk: u32, reg: Register) -> u32 {
        let value = self.registers[reg as usize];
        let addr = self.max_memory + reg as u32;
        self.memory_events.push(MemoryEvent {
            clk,
            addr,
            op: MemOp::Read,
            value,
        });
        value
    }

    pub fn write_register(&mut self, clk: u32, reg: Register, value: u32) {
        self.registers[reg as usize] = value;
        let addr = self.max_memory + reg as u32;
        self.memory_events.push(MemoryEvent {
            clk,
            addr,
            op: MemOp::Write,
            value,
        });
    }
}

#[cfg(test)]
mod tests {
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
    use p3_uni_stark::{prove, verify, StarkConfigImpl};
    use rand::thread_rng;

    use crate::memory::MemOp;
    use p3_commit::ExtensionMmcs;

    use super::air::MemoryAir;
    use super::MemoryEvent;

    #[test]
    fn test_memory_generate_trace() {
        let events = vec![
            MemoryEvent {
                clk: 0,
                addr: 0,
                op: MemOp::Write,
                value: 0,
            },
            MemoryEvent {
                clk: 1,
                addr: 0,
                op: MemOp::Read,
                value: 0,
            },
        ];
        let trace: RowMajorMatrix<BabyBear> = MemoryAir::generate_trace(&events);
        println!("{:?}", trace.values)
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

        // let events = vec![
        //     MemoryEvent {
        //         clk: 1,
        //         addr: 0,
        //         op: MemOp::Write,
        //         value: 1,
        //     },
        //     MemoryEvent {
        //         clk: 2,
        //         addr: 0,
        //         op: MemOp::Read,
        //         value: 1,
        //     },
        //     MemoryEvent {
        //         clk: 3,
        //         addr: 1,
        //         op: MemOp::Write,
        //         value: 0,
        //     },
        //     MemoryEvent {
        //         clk: 4,
        //         addr: 1,
        //         op: MemOp::Read,
        //         value: 0,
        //     },
        // ];
        let events = (0..1024)
            .map(|i| MemoryEvent {
                clk: i + 1,
                addr: i + 1,
                op: MemOp::Write,
                value: i,
            })
            .collect::<Vec<_>>();
        let trace: RowMajorMatrix<BabyBear> = MemoryAir::generate_trace(&events);
        let air = MemoryAir {};
        let proof = prove::<MyConfig, _>(&config, &air, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &air, &mut challenger, &proof).unwrap();
    }
}
