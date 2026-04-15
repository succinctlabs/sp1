pub const WIDTH: usize = 16;
pub const RATE: usize = 8;
pub const BYTE_BLOCK_SIZE: usize = RATE * 3;

use crate::syscall_poseidon2;

#[repr(C)]
#[repr(align(8))]
pub struct Poseidon2State([u32; WIDTH]);

impl Default for Poseidon2State {
    fn default() -> Self {
        Self([0; WIDTH])
    }
}

impl Poseidon2State {
    #[inline]
    pub fn permute(&mut self) {
        unsafe {
            syscall_poseidon2(self);
        }
    }

    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u32 {
        self.0.as_mut_ptr()
    }

    /// Absorb a [`RATE`] size block of field elements
    ///
    /// # Safety
    /// This function assumes that the elements are within the `SP1Field` range. Breaking this
    /// constraint will lead to prover failure (the proof will not verify).
    pub fn absorb_field_block_unchecked(&mut self, block: &[u32; RATE]) {
        self.0[0..RATE].copy_from_slice(block);
        self.permute();
    }

    /// Absorb a single byte block into the sponge state (raw, no padding).
    ///
    /// Encodes `BYTE_BLOCK_SIZE` (24) bytes into `RATE` (8) field elements using a little-endian
    /// 3-bytes-per-element packing (max 24 bits per element), then overwrites the rate portion of
    /// the state and permutes.
    ///
    /// **No padding is applied.** If you are hashing a variable-length message, use
    /// [`Poseidon2ByteHash::hash`] which handles padding, or apply your own padding scheme
    /// before calling this method.
    pub fn absorb_byte_block(&mut self, block: &[u8; BYTE_BLOCK_SIZE]) {
        let mut field_block = [0u32; RATE];
        for (i, element) in field_block.iter_mut().enumerate() {
            let start_idx = 3 * i;
            *element += block[start_idx] as u32;
            *element += (block[start_idx + 1] as u32) << 8;
            *element += (block[start_idx + 2] as u32) << 16;
        }
        self.absorb_field_block_unchecked(&field_block);
    }

    /// Returns the rate portion of the current sponge state as the hash output.
    ///
    /// # Warning
    /// This method does **not** apply any finalization padding. It returns the raw state after
    /// the last permutation. If you are hashing variable-length input, you must ensure that a
    /// padding-safe protocol was followed (e.g., by prefixing the message length). Consider using
    /// [`Poseidon2ByteHash::hash`] which handles this automatically.
    pub fn output(self) -> [u32; RATE] {
        let mut output = [0; RATE];
        output.copy_from_slice(&self.0[0..RATE]);
        output
    }
}

/// Poseidon2 byte hasher with safe padding (length-prefixed sponge).
///
/// Accepts an arbitrary-length byte slice and returns a `RATE`-sized field element digest.
/// The input length is absorbed as the first message block before the data blocks,
/// which prevents collisions between inputs that differ only in trailing zeros.
pub struct Poseidon2ByteHash;

impl Poseidon2ByteHash {
    pub fn hash(input: &[u8]) -> [u32; RATE] {
        let mut state = Poseidon2State::default();

        // Absorb the input length (in bytes) as the first block for safe padding.
        // This ensures inputs of different lengths that zero-pad identically still
        // produce different hashes.
        // The length is encoded as little-endian bytes and packed into field elements
        // using the same 3-bytes-per-element scheme, supporting lengths up to 2^192.
        let len_bytes = input.len().to_le_bytes();
        let mut len_block = [0u8; BYTE_BLOCK_SIZE];
        len_block[..len_bytes.len()].copy_from_slice(&len_bytes);
        state.absorb_byte_block(&len_block);

        // Absorb full blocks.
        let chunks = input.chunks_exact(BYTE_BLOCK_SIZE);
        let remainder = chunks.remainder();
        for chunk in chunks {
            state.absorb_byte_block(chunk.try_into().unwrap());
        }

        // Absorb the final partial block (zero-padded).
        if !remainder.is_empty() {
            let mut last_block = [0u8; BYTE_BLOCK_SIZE];
            last_block[..remainder.len()].copy_from_slice(remainder);
            state.absorb_byte_block(&last_block);
        }

        state.output()
    }
}
