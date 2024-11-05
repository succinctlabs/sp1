#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enhanced_memory_cache() {
        let mut cache = EnhancedMemoryCache::new(1024);
        let data = vec![1, 2, 3, 4];
        cache.segments.insert(0, data);
        
        assert!(cache.access(0).is_some());
        assert_eq!(cache.access_count.get(&0), Some(&1));
    }
}
