pub fn segment_size() -> usize {
    let value = match std::env::var("SEGMENT_SIZE") {
        Ok(val) => val.parse().unwrap(),
        Err(_) => 1 << 18,
    };
    assert!(value != 0 && (value & (value - 1)) == 0);
    value
}
