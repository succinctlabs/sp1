#[derive(Clone)]
pub struct Blake3SingleBlockCompression;

impl Blake3SingleBlockCompression {
    pub const fn new() -> Self {
        Self {}
    }
}

impl PseudoCompressionFunction<[u32; 8], 2> for Blake3SingleBlockCompression {
    fn compress(&self, input: [[u32; 8]; 2]) -> [u32; 8] {
        let mut block_words = [0u32; blake3_zkvm::BLOCK_LEN];
        block_words[0..8].copy_from_slice(&input[0]);
        block_words[8..].copy_from_slice(&input[1]);
        blake3_zkvm::hash_single_block(&block_words, blake3_zkvm::BLOCK_LEN)
    }
}

#[derive(Copy, Clone)]
pub struct Blake3U32;

impl CryptographicHasher<u32, [u32; 8]> for Blake3U32 {
    fn hash_iter<I>(&self, input: I) -> [u32; 8]
    where
        I: IntoIterator<Item = u32>,
    {
        let input = input.into_iter().collect::<Vec<_>>();
        self.hash_iter_slices([input.as_slice()])
    }

    fn hash_iter_slices<'a, I>(&self, input: I) -> [u32; 8]
    where
        I: IntoIterator<Item = &'a [u32]>,
    {
        let mut hasher = blake3::Hasher::new();
        for chunk in input.into_iter() {
            let u8_chunk = chunk
                .iter()
                .flat_map(|x| x.to_le_bytes())
                .collect::<Vec<_>>();
            #[cfg(not(feature = "parallel"))]
            hasher.update(&u8_chunk);
            #[cfg(feature = "parallel")]
            hasher.update_rayon(&u8_chunk);
        }
        let u8_hash = hasher.finalize();
        blake3::platform::words_from_le_bytes_32(u8_hash.as_bytes())
    }
}

#[derive(Copy, Clone)]
pub struct Blake3U32Zkvm;

impl CryptographicHasher<u32, [u32; 8]> for Blake3U32Zkvm {
    fn hash_iter<I>(&self, input: I) -> [u32; 8]
    where
        I: IntoIterator<Item = u32>,
    {
        let mut input = input.into_iter().collect::<Vec<_>>();
        if input.len() <= blake3_zkvm::BLOCK_LEN {
            let size = input.len();
            input.resize(blake3_zkvm::BLOCK_LEN, 0u32);
            blake3_zkvm::hash_single_block(input.as_slice().try_into().unwrap(), size)
        } else {
            let ret = self.hash_iter_slices([input.as_slice()]);
            ret
        }
    }

    fn hash_iter_slices<'a, I>(&self, input: I) -> [u32; 8]
    where
        I: IntoIterator<Item = &'a [u32]>,
    {
        let mut zkvm_hasher = blake3_zkvm::Hasher::new();

        for chunk in input.into_iter() {
            zkvm_hasher.update(chunk);
        }
        let mut out: [u32; 8] = [0u32; 8];
        zkvm_hasher.finalize(&mut out);

        out
    }
}
