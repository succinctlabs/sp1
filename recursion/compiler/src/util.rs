use p3_field::PrimeField32;

pub fn canonical_i32_to_field<F: PrimeField32>(x: i32) -> u32 {
    if x < 0 {
        (-F::from_canonical_u32((-x) as u32)).as_canonical_u32()
    } else {
        x as u32
    }
}
