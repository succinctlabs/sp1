use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    iter::once,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use sp1_core_machine::riscv::CoreShapeConfig;
use sp1_recursion_circuit_v2::{
    machine::{
        SP1CompressWithVKeyWitnessValues, SP1CompressWithVkeyShape, SP1DeferredShape,
        SP1DeferredWitnessValues, SP1RecursionShape, SP1RecursionWitnessValues,
    },
    merkle_tree::MerkleTree,
};
use sp1_recursion_core_v2::{shape::RecursionShapeConfig, RecursionProgram};
use sp1_stark::{MachineProver, ProofShape, DIGEST_SIZE};

use crate::{
    components::SP1ProverComponents, utils::MaybeTakeIterator, CompressAir, HashableKey, InnerSC,
    SP1Prover, ShrinkAir,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SP1ProofShape {
    Recursion(ProofShape),
    Compress(Vec<ProofShape>),
    Deferred(ProofShape),
    Shrink(ProofShape),
}

pub enum SP1CompressProgramShape {
    Recursion(SP1RecursionShape),
    Compress(SP1CompressWithVkeyShape),
    Deferred(SP1DeferredShape),
    Shrink(SP1CompressWithVkeyShape),
}

pub fn build_vk_map<C: SP1ProverComponents>(
    build_dir: PathBuf,
    reduce_batch_size: usize,
    dummy: bool,
    num_compiler_workers: usize,
    num_setup_workers: usize,
    range_start: Option<usize>,
    range_end: Option<usize>,
) {
    std::fs::create_dir_all(&build_dir).expect("failed to create build directory");

    let prover = SP1Prover::<C>::new();
    let core_shape_config = prover.core_shape_config.as_ref().expect("core shape config not found");
    let recursion_shape_config =
        prover.recursion_shape_config.as_ref().expect("recursion shape config not found");

    tracing::info!("building compress vk map");
    let vk_map = if dummy {
        tracing::warn!("Making a dummy vk map");
        SP1ProofShape::dummy_vk_map(core_shape_config, recursion_shape_config, reduce_batch_size)
    } else {
        let (vk_tx, vk_rx) = std::sync::mpsc::channel();
        let (shape_tx, shape_rx) = std::sync::mpsc::sync_channel(num_compiler_workers);
        let (program_tx, program_rx) = std::sync::mpsc::sync_channel(num_setup_workers);

        let shape_rx = Mutex::new(shape_rx);
        let program_rx = Mutex::new(program_rx);

        let length = range_end.and_then(|end| end.checked_sub(range_start.unwrap_or(0)));
        let generate_shapes = || {
            SP1ProofShape::generate(core_shape_config, recursion_shape_config, reduce_batch_size)
                .maybe_skip(range_start)
                .maybe_take(length)
        };

        let num_shapes = generate_shapes().count();
        let height = num_shapes.next_power_of_two().ilog2() as usize;

        tracing::info!("There are {} shapes to generate", num_shapes);

        std::thread::scope(|s| {
            // Initialize compiler workers.
            for _ in 0..num_compiler_workers {
                let program_tx = program_tx.clone();
                let shape_rx = &shape_rx;
                let prover = &prover;
                s.spawn(move || {
                    while let Ok(shape) = shape_rx.lock().unwrap().recv() {
                        let program = prover.program_from_shape(shape);
                        program_tx.send(program).unwrap();
                    }
                });
            }

            // Initialize setup workers.
            for _ in 0..num_setup_workers {
                let vk_tx = vk_tx.clone();
                let program_rx = &program_rx;
                let prover = &prover;
                s.spawn(move || {
                    while let Ok(program) = program_rx.lock().unwrap().recv() {
                        let (_, vk) = tracing::debug_span!("setup")
                            .in_scope(|| prover.compress_prover.setup(&program));
                        let vk_digest = vk.hash_babybear();
                        vk_tx.send(vk_digest).unwrap();
                    }
                });
            }

            // Generate shapes and send them to the compiler workers.
            generate_shapes()
                .map(|shape| SP1CompressProgramShape::from_proof_shape(shape, height))
                .for_each(|program_shape| {
                    shape_tx.send(program_shape).unwrap();
                });

            drop(shape_tx);
            drop(program_tx);
            drop(vk_tx);

            let mut vk_set = BTreeSet::new();

            for vk_digest in vk_rx.iter().take(num_shapes) {
                vk_set.insert(vk_digest);
            }

            vk_set.into_iter().enumerate().map(|(i, vk_digest)| (vk_digest, i)).collect()
        })
    };
    tracing::info!("compress vks generated, number of keys: {}", vk_map.len());

    // Save the vk map to a file.
    tracing::info!("saving vk map to file");
    let vk_map_path = build_dir.join("vk_map.bin");
    let mut vk_map_file = File::create(vk_map_path).unwrap();
    bincode::serialize_into(&mut vk_map_file, &vk_map).unwrap();
    tracing::info!("File saved successfully.");

    // Build a merkle tree from the vk map.
    tracing::info!("building merkle tree");
    let (root, merkle_tree) =
        MerkleTree::<BabyBear, InnerSC>::commit(vk_map.keys().cloned().collect());

    // Saving merkle tree data to file.
    tracing::info!("saving merkle tree to file");
    let merkle_tree_path = build_dir.join("merkle_tree.bin");
    let mut merkle_tree_file = File::create(merkle_tree_path).unwrap();
    bincode::serialize_into(&mut merkle_tree_file, &(root, merkle_tree)).unwrap();
    tracing::info!("File saved successfully.");
}

impl SP1ProofShape {
    pub fn generate<'a>(
        core_shape_config: &'a CoreShapeConfig<BabyBear>,
        recursion_shape_config: &'a RecursionShapeConfig<BabyBear, CompressAir<BabyBear>>,
        reduce_batch_size: usize,
    ) -> impl Iterator<Item = Self> + 'a {
        core_shape_config
            .generate_all_allowed_shapes()
            .map(Self::Recursion)
            .chain(
                recursion_shape_config
                    .get_all_shape_combinations(1)
                    .map(|mut x| Self::Deferred(x.pop().unwrap())),
            )
            .chain(
                recursion_shape_config
                    .get_all_shape_combinations(reduce_batch_size)
                    .map(Self::Compress),
            )
            .chain(once(Self::Shrink(ShrinkAir::<BabyBear>::shrink_shape().into())))
    }

    pub fn dummy_vk_map<'a>(
        core_shape_config: &'a CoreShapeConfig<BabyBear>,
        recursion_shape_config: &'a RecursionShapeConfig<BabyBear, CompressAir<BabyBear>>,
        reduce_batch_size: usize,
    ) -> BTreeMap<[BabyBear; DIGEST_SIZE], usize> {
        Self::generate(core_shape_config, recursion_shape_config, reduce_batch_size)
            .enumerate()
            .map(|(i, _)| ([BabyBear::from_canonical_usize(i); DIGEST_SIZE], i))
            .collect()
    }
}

impl SP1CompressProgramShape {
    pub fn from_proof_shape(shape: SP1ProofShape, height: usize) -> Self {
        match shape {
            SP1ProofShape::Recursion(proof_shape) => Self::Recursion(proof_shape.into()),
            SP1ProofShape::Deferred(proof_shape) => {
                Self::Deferred(SP1DeferredShape::new(vec![proof_shape].into(), height))
            }
            SP1ProofShape::Compress(proof_shapes) => Self::Compress(SP1CompressWithVkeyShape {
                compress_shape: proof_shapes.into(),
                merkle_tree_height: height,
            }),
            SP1ProofShape::Shrink(proof_shape) => Self::Shrink(SP1CompressWithVkeyShape {
                compress_shape: vec![proof_shape].into(),
                merkle_tree_height: height,
            }),
        }
    }
}

impl<C: SP1ProverComponents> SP1Prover<C> {
    pub fn program_from_shape(
        &self,
        shape: SP1CompressProgramShape,
    ) -> Arc<RecursionProgram<BabyBear>> {
        match shape {
            SP1CompressProgramShape::Recursion(shape) => {
                let input = SP1RecursionWitnessValues::dummy(self.core_prover.machine(), &shape);
                self.recursion_program(&input)
            }
            SP1CompressProgramShape::Deferred(shape) => {
                let input = SP1DeferredWitnessValues::dummy(self.compress_prover.machine(), &shape);
                self.deferred_program(&input)
            }
            SP1CompressProgramShape::Compress(shape) => {
                let input =
                    SP1CompressWithVKeyWitnessValues::dummy(self.compress_prover.machine(), &shape);
                self.compress_program(&input)
            }
            SP1CompressProgramShape::Shrink(shape) => {
                let input =
                    SP1CompressWithVKeyWitnessValues::dummy(self.compress_prover.machine(), &shape);
                self.shrink_program(&input)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_all_shapes() {
        let core_shape_config = CoreShapeConfig::default();
        let recursion_shape_config = RecursionShapeConfig::default();
        let reduce_batch_size = 2;
        let num_compress_shapes =
            SP1ProofShape::generate(&core_shape_config, &recursion_shape_config, reduce_batch_size)
                .count();
        println!("Number of compress shapes: {}", num_compress_shapes);
    }
}
