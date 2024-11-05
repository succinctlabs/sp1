pub struct EnhancedMemoryCache {
    segments: HashMap<u64, Vec<u8>>,
    access_count: HashMap<u64, usize>,
    max_size: usize,
}

impl EnhancedMemoryCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            segments: HashMap::new(),
            access_count: HashMap::new(),
            max_size,
        }
    }

    pub fn access(&mut self, address: u64) -> Option<&[u8]> {
        if let Some(count) = self.access_count.get_mut(&address) {
            *count += 1;
        }
        self.segments.get(&address).map(|v| v.as_slice())
    }
}
