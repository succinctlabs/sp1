#[sp1_test::sp1_test("curve25519_ng_decompress")]
fn test_decompressed_expected_value(stdin: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use curve25519_dalek_ng::edwards::CompressedEdwardsY;
    use curve25519_dalek_ng::edwards::EdwardsPoint;
    use curve25519_dalek_ng::constants::ED25519_BASEPOINT_POINT;
    use rand::distributions::Distribution;
    use rand::distributions::WeightedIndex;
    use sp1_test::DEFAULT_CORPUS_COUNT; 

    let dist = rand::distributions::WeightedIndex::new([9_usize, 1]).unwrap();

    /// Flips a bit in the compressed point with probability 0.1.
    ///
    /// Returns true if a bit was flipped. With probablity .5 this is not a valid compressed point.
    fn bork_point(compressed: &mut CompressedEdwardsY, dist: &WeightedIndex<usize>) -> bool { 
        if dist.sample(&mut rand::thread_rng()) == 1 {
            let bit = 1 << 2;
            compressed.0[0] ^= bit;

            return true;
        }

        false
    }
    
    let how_many_points = DEFAULT_CORPUS_COUNT as usize;
    stdin.write(&how_many_points);

    let mut decompress_outputs = Vec::new();
    while decompress_outputs.len() < how_many_points {
        let rand_scalar = curve25519_dalek_ng::scalar::Scalar::random(&mut rand::thread_rng());
        let rand_point = ED25519_BASEPOINT_POINT * rand_scalar; 
        let mut compressed = rand_point.compress();

        if bork_point(&mut compressed, &dist) {
            // if point has been borked lets just make it cant be decompressed. 
            let decompress = compressed.decompress(); 
            if decompress.is_some() {
                continue;
            }

            decompress_outputs.push(decompress);
        } else {
            decompress_outputs.push(compressed.decompress());
        }

        stdin.write(&compressed);
    }
    
    assert!(decompress_outputs.iter().any(|x| x.is_none()), "Expected at least one decompressed point to be None");

    move |mut public| {
        for decompressed in decompress_outputs {
            assert_eq!(decompressed, public.read::<Option<EdwardsPoint>>()); 
        }
    }
}
