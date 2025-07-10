use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs::File,
    hash::{DefaultHasher, Hash, Hasher},
    panic::{catch_unwind, AssertUnwindSafe},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use eyre::Result;
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use serde::{Deserialize, Serialize};
use sp1_core_machine::shape::CoreShapeConfig;
use sp1_recursion_circuit::machine::{
    SP1CompressWithVKeyWitnessValues, SP1DeferredWitnessValues, SP1RecursionWitnessValues,
};
use sp1_recursion_core::{
    shape::{RecursionShape, RecursionShapeConfig},
    RecursionProgram,
};
use sp1_stark::{shape::OrderedShape, MachineProver, DIGEST_SIZE};
use thiserror::Error;

pub use sp1_recursion_circuit::machine::{
    SP1CompressWithVkeyShape, SP1DeferredShape, SP1RecursionShape,
};

use crate::{components::SP1ProverComponents, CompressAir, HashableKey, SP1Prover, ShrinkAir};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SP1ProofShape {
    Recursion(OrderedShape),
    Compress(Vec<OrderedShape>),
    Deferred(OrderedShape),
    Shrink(OrderedShape),
}

#[derive(Debug, Clone, Hash)]
pub enum SP1CompressProgramShape {
    Recursion(SP1RecursionShape),
    Compress(SP1CompressWithVkeyShape),
    Deferred(SP1DeferredShape),
    Shrink(SP1CompressWithVkeyShape),
}

impl SP1CompressProgramShape {
    pub fn hash_u64(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        Hash::hash(&self, &mut hasher);
        hasher.finish()
    }
}

#[derive(Debug, Error)]
pub enum VkBuildError {
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Bincode(#[from] bincode::Error),
}

pub fn check_shapes<C: SP1ProverComponents>(
    reduce_batch_size: usize,
    no_precompiles: bool,
    num_compiler_workers: usize,
    prover: &mut SP1Prover<C>,
) -> bool {
    let (shape_tx, shape_rx) =
        std::sync::mpsc::sync_channel::<SP1CompressProgramShape>(num_compiler_workers);
    let (panic_tx, panic_rx) = std::sync::mpsc::channel();
    let core_shape_config = prover.core_shape_config.as_ref().expect("core shape config not found");
    let recursion_shape_config =
        prover.compress_shape_config.as_ref().expect("recursion shape config not found");

    let shape_rx = Mutex::new(shape_rx);

    let all_maximal_shapes = SP1ProofShape::generate_maximal_shapes(
        core_shape_config,
        recursion_shape_config,
        reduce_batch_size,
        no_precompiles,
    )
    .collect::<BTreeSet<SP1ProofShape>>();
    let num_shapes = all_maximal_shapes.len();
    tracing::debug!("number of shapes: {}", num_shapes);

    // The Merkle tree height.
    let height = num_shapes.next_power_of_two().ilog2() as usize;

    // Empty the join program map so that we recompute the join program.
    prover.join_programs_map.clear();

    let compress_ok = std::thread::scope(|s| {
        // Initialize compiler workers.
        for _ in 0..num_compiler_workers {
            let shape_rx = &shape_rx;
            let prover = &prover;
            let panic_tx = panic_tx.clone();
            s.spawn(move || {
                while let Ok(shape) = shape_rx.lock().unwrap().recv() {
                    tracing::debug!("shape is {:?}", shape);
                    let program = catch_unwind(AssertUnwindSafe(|| {
                        // Try to build the recursion program from the given shape.
                        prover.program_from_shape(shape.clone(), None)
                    }));
                    match program {
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(
                                "Program generation failed for shape {:?}, with error: {:?}",
                                shape,
                                e
                            );
                            panic_tx.send(true).unwrap();
                        }
                    }
                }
            });
        }

        // Generate shapes and send them to the compiler workers.
        all_maximal_shapes.into_iter().for_each(|program_shape| {
            shape_tx
                .send(SP1CompressProgramShape::from_proof_shape(program_shape, height))
                .unwrap();
        });

        drop(shape_tx);
        drop(panic_tx);

        // If the panic receiver has no panics, then the shape is correct.
        panic_rx.iter().next().is_none()
    });

    compress_ok
}

pub fn build_vk_map<C: SP1ProverComponents + 'static>(
    reduce_batch_size: usize,
    dummy: bool,
    num_compiler_workers: usize,
    num_setup_workers: usize,
    indices: Option<Vec<usize>>,
) -> (BTreeSet<[BabyBear; DIGEST_SIZE]>, Vec<usize>, usize) {
    // Setup the prover.
    let mut prover = SP1Prover::<C>::new();
    prover.vk_verification = !dummy;
    if !dummy {
        prover.join_programs_map.clear();
    }
    let prover = Arc::new(prover);

    // Get the shape configs.
    let core_shape_config = prover.core_shape_config.as_ref().expect("core shape config not found");
    let recursion_shape_config =
        prover.compress_shape_config.as_ref().expect("recursion shape config not found");

    let (vk_set, panic_indices, height) = if dummy {
        tracing::warn!("building a dummy vk map");
        let dummy_set = SP1ProofShape::dummy_vk_map(
            core_shape_config,
            recursion_shape_config,
            reduce_batch_size,
        )
        .into_keys()
        .collect::<BTreeSet<_>>();
        let height = dummy_set.len().next_power_of_two().ilog2() as usize;
        (dummy_set, vec![], height)
    } else {
        tracing::debug!("building vk map");

        // Setup the channels.
        let (vk_tx, vk_rx) = std::sync::mpsc::channel();
        let (shape_tx, shape_rx) =
            std::sync::mpsc::sync_channel::<(usize, SP1CompressProgramShape)>(num_compiler_workers);
        let (program_tx, program_rx) = std::sync::mpsc::sync_channel(num_setup_workers);
        let (panic_tx, panic_rx) = std::sync::mpsc::channel();

        // Setup the mutexes.
        let shape_rx = Mutex::new(shape_rx);
        let program_rx = Mutex::new(program_rx);

        // Generate all the possible shape inputs we encounter in recursion. This may span lift,
        // join, deferred, shrink, etc.
        let indices_set = indices.map(|indices| indices.into_iter().collect::<HashSet<_>>());
        let mut all_shapes = BTreeSet::new();
        let start = std::time::Instant::now();
        for shape in
            SP1ProofShape::generate(core_shape_config, recursion_shape_config, reduce_batch_size)
        {
            all_shapes.insert(shape);
        }

        let num_shapes = all_shapes.len();
        tracing::debug!("number of shapes: {} in {:?}", num_shapes, start.elapsed());

        let height = num_shapes.next_power_of_two().ilog2() as usize;
        let chunk_size = indices_set.as_ref().map(|indices| indices.len()).unwrap_or(num_shapes);

        std::thread::scope(|s| {
            // Initialize compiler workers.
            for _ in 0..num_compiler_workers {
                let program_tx = program_tx.clone();
                let shape_rx = &shape_rx;
                let prover = prover.clone();
                let panic_tx = panic_tx.clone();
                s.spawn(move || {
                    while let Ok((i, shape)) = shape_rx.lock().unwrap().recv() {
                        eprintln!("shape: {shape:?}");
                        let is_shrink = matches!(shape, SP1CompressProgramShape::Shrink(_));
                        let prover = prover.clone();
                        let shape_clone = shape.clone();
                        // Spawn on another thread to handle panics.
                        let program_thread = std::thread::spawn(move || {
                            prover.program_from_shape(shape_clone, None)
                        });
                        match program_thread.join() {
                            Ok(program) => program_tx.send((i, program, is_shrink)).unwrap(),
                            Err(e) => {
                                tracing::warn!(
                                    "Program generation failed for shape {} {:?}, with error: {:?}",
                                    i,
                                    shape,
                                    e
                                );
                                panic_tx.send(i).unwrap();
                            }
                        }
                    }
                });
            }

            // Initialize setup workers.
            for _ in 0..num_setup_workers {
                let vk_tx = vk_tx.clone();
                let program_rx = &program_rx;
                let prover = &prover;
                let panic_tx = panic_tx.clone();
                s.spawn(move || {
                    let mut done = 0;
                    while let Ok((i, program, is_shrink)) = program_rx.lock().unwrap().recv() {
                        let prover = prover.clone();
                        let vk_thread = std::thread::spawn(move || {
                            if is_shrink {
                                prover.shrink_prover.setup(&program).1
                            } else {
                                prover.compress_prover.setup(&program).1
                            }
                        });
                        let vk = tracing::debug_span!("setup for program {}", i)
                            .in_scope(|| vk_thread.join());
                        done += 1;

                        if let Err(e) = vk {
                            tracing::error!("failed to setup program {}: {:?}", i, e);
                            panic_tx.send(i).unwrap();
                            continue;
                        }
                        let vk = vk.unwrap();

                        let vk_digest = vk.hash_babybear();
                        tracing::debug!(
                            "program {} = {:?}, {}% done",
                            i,
                            vk_digest,
                            done * 100 / chunk_size
                        );
                        vk_tx.send(vk_digest).unwrap();
                    }
                });
            }

            // Generate shapes and send them to the compiler workers.
            let subset_shapes = all_shapes
                .into_iter()
                .enumerate()
                .filter(|(i, _)| indices_set.as_ref().map(|set| set.contains(i)).unwrap_or(true))
                .collect::<Vec<_>>();

            subset_shapes
                .clone()
                .into_iter()
                .map(|(i, shape)| (i, SP1CompressProgramShape::from_proof_shape(shape, height)))
                .for_each(|(i, program_shape)| {
                    shape_tx.send((i, program_shape)).unwrap();
                });

            drop(shape_tx);
            drop(program_tx);
            drop(vk_tx);
            drop(panic_tx);

            let vk_set = vk_rx.iter().collect::<BTreeSet<_>>();

            let panic_indices = panic_rx.iter().collect::<Vec<_>>();
            for (i, shape) in subset_shapes {
                if panic_indices.contains(&i) {
                    tracing::debug!("panic shape {}: {:?}", i, shape);
                }
            }

            (vk_set, panic_indices, height)
        })
    };
    tracing::debug!("compress vks generated, number of keys: {}", vk_set.len());
    (vk_set, panic_indices, height)
}

pub fn build_vk_map_to_file<C: SP1ProverComponents + 'static>(
    build_dir: PathBuf,
    reduce_batch_size: usize,
    dummy: bool,
    num_compiler_workers: usize,
    num_setup_workers: usize,
    range_start: Option<usize>,
    range_end: Option<usize>,
) -> Result<(), VkBuildError> {
    // Create the build directory if it doesn't exist.
    std::fs::create_dir_all(&build_dir)?;

    // Build the vk map.
    let (vk_set, _, _) = build_vk_map::<C>(
        reduce_batch_size,
        dummy,
        num_compiler_workers,
        num_setup_workers,
        range_start.and_then(|start| range_end.map(|end| (start..end).collect())),
    );

    // Serialize the vk into an ordering.
    let vk_map = vk_set.into_iter().enumerate().map(|(i, vk)| (vk, i)).collect::<BTreeMap<_, _>>();

    // Create the file to store the vk map.
    let mut file = if dummy {
        File::create(build_dir.join("dummy_vk_map.bin"))?
    } else {
        File::create(build_dir.join("vk_map.bin"))?
    };

    Ok(bincode::serialize_into(&mut file, &vk_map)?)
}

impl SP1ProofShape {
    pub fn generate<'a>(
        core_shape_config: &'a CoreShapeConfig<BabyBear>,
        recursion_shape_config: &'a RecursionShapeConfig<BabyBear, CompressAir<BabyBear>>,
        reduce_batch_size: usize,
    ) -> impl Iterator<Item = Self> + 'a {
        core_shape_config
            .all_shapes()
            .map(Self::Recursion)
            .chain((1..=reduce_batch_size).flat_map(|batch_size| {
                recursion_shape_config.get_all_shape_combinations(batch_size).map(Self::Compress)
            }))
            .chain(
                recursion_shape_config
                    .get_all_shape_combinations(1)
                    .map(|mut x| Self::Deferred(x.pop().unwrap())),
            )
            .chain(
                recursion_shape_config
                    .get_all_shape_combinations(1)
                    .map(|mut x| Self::Shrink(x.pop().unwrap())),
            )
    }

    pub fn generate_compress_shapes(
        recursion_shape_config: &'_ RecursionShapeConfig<BabyBear, CompressAir<BabyBear>>,
        reduce_batch_size: usize,
    ) -> impl Iterator<Item = Vec<OrderedShape>> + '_ {
        recursion_shape_config.get_all_shape_combinations(reduce_batch_size)
    }

    pub fn generate_maximal_shapes<'a>(
        core_shape_config: &'a CoreShapeConfig<BabyBear>,
        recursion_shape_config: &'a RecursionShapeConfig<BabyBear, CompressAir<BabyBear>>,
        reduce_batch_size: usize,
        no_precompiles: bool,
    ) -> impl Iterator<Item = Self> + 'a {
        let core_shape_iter = if no_precompiles {
            core_shape_config.maximal_core_shapes(21).into_iter()
        } else {
            core_shape_config.maximal_core_plus_precompile_shapes(21).into_iter()
        };
        core_shape_iter
            .map(|core_shape| {
                Self::Recursion(OrderedShape {
                    inner: core_shape.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
                })
            })
            .chain((1..=reduce_batch_size).flat_map(|batch_size| {
                recursion_shape_config.get_all_shape_combinations(batch_size).map(Self::Compress)
            }))
            .chain(
                recursion_shape_config
                    .get_all_shape_combinations(1)
                    .map(|mut x| Self::Deferred(x.pop().unwrap())),
            )
            .chain(
                recursion_shape_config
                    .get_all_shape_combinations(1)
                    .map(|mut x| Self::Shrink(x.pop().unwrap())),
            )
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
        shrink_shape: Option<RecursionShape>,
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
                self.shrink_program(
                    shrink_shape.unwrap_or_else(ShrinkAir::<BabyBear>::shrink_shape),
                    &input,
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::print_stdout)]

    use super::*;

    #[test]
    #[ignore]
    fn test_generate_all_shapes() {
        let core_shape_config = CoreShapeConfig::default();
        let recursion_shape_config = RecursionShapeConfig::default();
        let reduce_batch_size = 2;
        let all_shapes =
            SP1ProofShape::generate(&core_shape_config, &recursion_shape_config, reduce_batch_size)
                .collect::<BTreeSet<_>>();

        println!("Number of compress shapes: {}", all_shapes.len());
    }
}
