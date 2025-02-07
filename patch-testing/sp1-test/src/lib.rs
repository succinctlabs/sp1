use serde::{Deserialize, Serialize};

pub mod utils;

/// How many items to generate for the corpus.
pub const DEFAULT_CORPUS_COUNT: u8 = 100;

/// The maximum length of an item in the corpus, if applicable.
pub const DEFAULT_CORPUS_MAX_LEN: usize = 100;

/// A lock to enforce serial execution of tests.
pub static SERIAL_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// A lock for the benchmark file.
pub static BENCH_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

pub fn lock_serial() -> parking_lot::MutexGuard<'static, ()> {
    SERIAL_LOCK.lock()
}

#[derive(Serialize, Deserialize)]
pub struct BenchEntry {
    pub name: String,
    pub cycles: u64,
}

pub fn write_cycles(name: &str, cycles: u64) {
    let Some(file) = std::env::var("SP1_PATCH_BENCH").ok().map(std::path::PathBuf::from) else {
        return;
    };

    // Take the lock to ensure thread safety.
    let _lock = BENCH_LOCK.lock();

    // Deserialize the file so we can append to it correctly.
    let mut entries: Vec<BenchEntry> = if file.is_file() {
        let str = std::fs::read_to_string(&file).unwrap();

        if str.is_empty() {
            vec![]
        } else {
            serde_json::from_str(&str).unwrap()
        }
    } else {
        vec![]
    };

    entries.push(BenchEntry { name: name.to_string(), cycles });

    // Re-serialize the file.
    std::fs::write(file, serde_json::to_string(&entries).unwrap()).unwrap();
}

lazy_static::lazy_static! {
    /// Use a single CPU prover for all tests.
    pub static ref SP1_CPU_PROVER: sp1_sdk::cpu::CpuProver = sp1_sdk::cpu::CpuProver::new();
}

/// Append common edge cases to the corpus.
///
/// Like all 0s or all 1s or the empty string.
pub fn add_hash_fn_edge_cases(corpus: &mut Vec<Vec<u8>>) {
    let max_len = DEFAULT_CORPUS_COUNT;
    corpus.push(vec![]);

    // push inputs of all 0s
    for len in 1..=max_len {
        corpus.push(vec![0; len as usize]);
    }

    // push inputs of all 255s
    for len in 1..=max_len {
        corpus.push(vec![255; len as usize]);
    }
}

/// Generate `count` random preimages with bounded length `len`.
pub fn random_preimages_with_bounded_len(count: u8, len: usize) -> Vec<Vec<u8>> {
    use rand::distributions::Distribution;

    (0..count)
        .map(|_| {
            let len =
                rand::distributions::Uniform::new(0_usize, len).sample(&mut rand::thread_rng());

            (0..len).map(|_| rand::random::<u8>()).collect::<Vec<u8>>()
        })
        .collect()
}

pub fn random_prehash() -> [u8; 32] {
    use sha2_v0_9_8::Digest;

    let prehash = rand::random::<[u8; 32]>();

    let mut sha = sha2_v0_9_8::Sha256::new();
    sha.update(prehash);

    sha.finalize().into()
}

#[doc(inline)]
pub use sp1_test_macro::sp1_test;
